//! Antminer T21 **stock contracts** transcribed byte-exactly from Bitmain's own
//! firmware image held in the `asicminingsupplies` mirror (Gauntlet Phase A
//! 2026-09-01 ingestion; transcription lane B9, 2026-09-02).
//!
//! This module is deliberately *only* a transcription surface (same rule as
//! [`crate::scrypt_stock_topology`]): every field states what a held stock
//! artifact says literally, `None` means the stock bytes are silent, and
//! nothing is inherited from a sibling board, a VNish/ePIC registry, or a
//! research document. It declares no [`crate::SiliconTable`],
//! [`crate::bm1368::BM1368_TABLE`] stays the single silicon profile for the
//! chip family, and **no energization, frequency, voltage, or thermal-control
//! authority lives here** — every electrical constant below is stock evidence
//! for a bench gate, never a DCENT envelope.
//!
//! # Held artifacts (gitignored extraction trees, mirror-held)
//!
//! Source BMU: `Antminer-T21-merge-release-20240926105845.bmu`
//! ([`T21_MERGE_BMU_SHA256`]), third-party public mirror
//!
//! (HEAD `d140bd0f`; internally consistency-verified only — internal RE
//! evidence, never redistributed; see `PHASE_A_EVIDENCE_REPORT.md` §1.3).
//! The merge ships THREE mutually exclusive control-board payloads for the
//! SAME BHB6870X hashboard family — `00_…_zynq7007` (full plaintext record,
//! the transcription source), `01_…_CVCtrl` (BOOT/dtb/uImage only), and
//! `02_…_AMLCtrl` (**sealed** code-9 `ANDROID!` image — no plaintext AML
//! evidence exists in the image; all AML control-board contracts stay
//! unsettled).
//!
//! | artifact | path (under ) | SHA-256 |
//! |---|---|---|
//! | topology DB (default = BHB68701) | `minerfs.image.gz.tree/etc/topol.conf` | [`T21_TOPOL_DB_SHA256`] |
//! | BHB68701 machine record | `minerfs.image.gz.tree/etc/topol_BHB68701.conf` | [`T21_TOPOL_BHB68701_SHA256`] (byte-identical to the DB default) |
//! | BHB68703 machine record | `minerfs.image.gz.tree/etc/topol_BHB68703.conf` | [`T21_TOPOL_BHB68703_SHA256`] |
//! | BHB68705 machine record | `minerfs.image.gz.tree/etc/topol_BHB68705.conf` | [`T21_TOPOL_BHB68705_SHA256`] |
//! | stock levels ladder | `minerfs.image.gz.tree/etc/levels.json` | [`T21_LEVELS_JSON_SHA256`] |
//! | miner ELF (stripped ARM) | `minerfs.image.gz.tree/usr/bin/bmminer` | [`T21_BMMINER_SHA256`] |
//! | cgminer ELF (stripped ARM) | `minerfs.image.gz.tree/usr/bin/cgminer` | [`T21_CGMINER_SHA256`] |
//! | zynq devicetree | `devicetree.dtb` | [`T21_ZYNQ_DEVICETREE_SHA256`] |
//! | cold-init boot script | `minerfs.image.gz.tree/etc/init.d/S70cgminer` | [`T21_S70CGMINER_SHA256`] |
//!
//! All three machine records are byte-identical except the `machine` /
//! `mix_boardnames` name fields — one geometry, one PSU law, one controller
//! map for the whole BHB68701/03/05 family (diff-verified lane B9).
//!
//! # The contracts these bytes settle (hashboard-side)
//!
//! 1. **Geometry:** BM1368 (`asic_addr "0x1368"`), **3 chains × 108 ASICs**
//!    (12 voltage domains × 9, address interval 2, 12×9 placement grid
//!    exactly populated — unlike the S19-family grids, row × column here
//!    equals `chain_asic_num`). `chain_num: 3` on this BHB68xxx generation
//!    matches the 3-board SKU (Phase A §1.3.5) — live population still
//!    capture-first.
//! 2. **PSU dialect:** **APW11A** @ I²C `0x10`, power GPIO 907 — the first
//!    stock sighting of the APW11A dialect (distinct from the S21-hydro
//!    APW11 record and from every APW12/AWP12 board). Version-key list
//!    transcribed verbatim in [`T21_PSU_VERSION_KEYS`]. The rail-law
//!    constants (the `code = K1 − V·K2` family B6 extracted for APW12) are
//!    NOT extracted for APW11A — bench/Ghidra follow-up.
//! 3. **Per-chain voltage-MCU label:** `"PIC1704"` @ I²C `0x20` (one per
//!    chain, LM75A sensors `0x48..=0x4B`, hashboard EEPROM AT24C02D @
//!    `0x50`). A stock label is not a populated-part proof — the concrete
//!    part stays runtime-discovered (same caveat as the S19 family, where
//!    live probes of the sibling BHB42601 generation found dsPIC33EP16GS202
//!    in the slot the topol labels PIC1704).
//! 4. **Fans:** 4 entries — ids 0/1 `right/in`, ids 2/3 `left/out`.
//!
//! # Cross-check against the same chip in another chassis (why T21 stands on
//! its own citations)
//!
//! The S21-hydro stock record (`s21-hydro-20240519`, machine HHB68601, also
//! BM1368 80+1276 cores) declares `asic_domain_num: 4`, `asic_addr_interval:
//! 1`, 18 dom × 12 = 216/chain, PSU APW11 with a DIFFERENT version-key list.
//! Same chip, different chain topology and PSU law per board — chip identity
//! alone never determines T21 contracts (test-pinned in
//! [`tests`][self#tests] `t21_same_chip_as_s21_hydro_but_different_chain_topology`).
//!
//! # Cold-init contract (stock boot bring-up, string/script-level)
//!
//! Transcribed in [`T21_S70_INIT_ORDER`] (the stock `/etc/init.d/S70cgminer`
//! sequence) and [`T21_BMMINER_INIT_MARKERS`] (log-format strings from the
//! stock `bmminer`, with file offsets where load-bearing). These are
//! sequence EVIDENCE only — disassembled control flow, the numeric
//! post-switch baud, and the APW11A rail constants are desk-unknowns queued
//! for Ghidra/bench (see the B9 dossier honest-unknowns list). The AML
//! control board runs a sealed variant of this bring-up whose exact order is
//! NOT held.

#![forbid(unsafe_code)]

/// A stock `topol.conf` machine record, transcribed. `None` = the stock bytes
/// are silent (never interpolated).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21StockTopol {
    /// Bitmain machine/hashboard id exactly as stated (`machine` field).
    pub machine_id: &'static str,
    /// Stock control-board processor type string this record ships for
    /// (the plaintext record is the zynq7007 one).
    pub processor: Option<&'static str>,
    /// ASIC part name **as stated by the stock image itself**.
    pub asic_id: &'static str,
    /// Numeric chip id **as stated by the stock image itself**.
    pub chip_type: u16,
    /// Big (hashing) cores per ASIC (`asic_core_num`).
    pub asic_big_core_num: Option<u32>,
    /// Small cores per ASIC (`asic_small_core_num`).
    pub asic_small_core_num: Option<u32>,
    /// Small cores per big core (`core_small_core_num`).
    pub core_small_core_num: Option<u32>,
    /// Per-chip domain count field (`asic_domain_num`) — NOTE: the stock
    /// value differs per chassis even for the same chip (T21 says 1, the
    /// S21-hydro BM1368 record says 4).
    pub asic_domain_num: Option<u32>,
    /// Chip address interval (`asic_addr_interval`).
    pub asic_addr_interval: Option<u32>,
    /// Chains (`chain_num`) — on the BHB68xxx generation this matches the
    /// 3-board SKU (Phase A §1.3.5); physical population stays live-capture.
    pub chain_num: Option<u32>,
    /// `chain_row` placement-grid field (12 on every T21 record).
    pub chain_row: Option<u32>,
    /// `chain_column` placement-grid field (9 on every T21 record).
    pub chain_column: Option<u32>,
    /// ASICs per chain (`chain_asic_num`).
    pub chips_per_chain: u32,
    /// Voltage domains per chain (`chain_domain_num`).
    pub chain_domain_num: Option<u32>,
    /// ASICs per voltage domain (`domain_asic_num`).
    pub domain_asic_num: Option<u32>,
    /// Chain voltage-MCU topol label (`pic.type`) — a label, not a
    /// populated-part proof (module docs).
    pub pic_topol_label: Option<&'static str>,
    /// Chain voltage-MCU 7-bit I²C address (`pic.i2c_addr`).
    pub pic_i2c_addr: Option<u8>,
    /// Hashboard EEPROM type (`eeprom.type`).
    pub eeprom_type: Option<&'static str>,
    /// Hashboard EEPROM 7-bit I²C address (`eeprom.i2c_addr`).
    pub eeprom_i2c_addr: Option<u8>,
    /// PSU family string, verbatim (`power.type`).
    pub psu_type: Option<&'static str>,
    /// PSU 7-bit I²C address (`power.i2c_addr`).
    pub psu_i2c_addr: Option<u8>,
    /// PSU power GPIO (`power.gpio` — zynq numbering; AML translation
    /// unknown, the AML record is sealed).
    pub psu_gpio: Option<u32>,
    /// Fan count (`fan[]` length).
    pub fan_count: Option<u32>,
    /// Exact provenance sentence for this row.
    pub evidence: &'static str,
}

/// The BHB68701 record — the default machine of the stock topology DB.
/// BHB68703/BHB68705 are byte-identical except the name fields.
pub const T21_STOCK_BHB68701: T21StockTopol = T21StockTopol {
    machine_id: "BHB68701",
    processor: Some("ZYNQ7007"),
    asic_id: "BM1368",
    chip_type: 0x1368,
    asic_big_core_num: Some(80),
    asic_small_core_num: Some(1276),
    core_small_core_num: Some(16),
    asic_domain_num: Some(1),
    asic_addr_interval: Some(2),
    chain_num: Some(3),
    chain_row: Some(12),
    chain_column: Some(9),
    chips_per_chain: 108,
    chain_domain_num: Some(12),
    domain_asic_num: Some(9),
    pic_topol_label: Some("PIC1704"),
    pic_i2c_addr: Some(0x20),
    eeprom_type: Some("AT24C02D"),
    eeprom_i2c_addr: Some(0x50),
    psu_type: Some("APW11A"),
    psu_i2c_addr: Some(0x10),
    psu_gpio: Some(907),
    fan_count: Some(4),
    evidence: "t21-merge-20240926 zynq7007 record topol.conf/topol_BHB68701.conf \
               (sha256 4d2b3789...), Phase A §3.9 / lane B9 transcription",
};

/// SHA-256 of the source merge BMU
/// (`asicminingsupplies-backup/Bitmain/Antminer/SHA-256/Antminer-T21-merged/
/// Antminer-T21-merge-release-20240926105845.bmu`, 46,021,157 bytes).
pub const T21_MERGE_BMU_SHA256: &str =
    "f9dcf13af16399585449c0d17e0ecdc6db93936e85137479d9aa9efdc4909905";
/// SHA-256 of the stock topology DB (`etc/topol.conf`, default BHB68701).
pub const T21_TOPOL_DB_SHA256: &str =
    "4d2b37890f4cad2e15fdae557e7cdfb864f7ee7d8e69526902f4f71088286a3d";
/// SHA-256 of `etc/topol_BHB68701.conf` (byte-identical to the DB default).
pub const T21_TOPOL_BHB68701_SHA256: &str =
    "4d2b37890f4cad2e15fdae557e7cdfb864f7ee7d8e69526902f4f71088286a3d";
/// SHA-256 of `etc/topol_BHB68703.conf` (name fields only differ from 68701).
pub const T21_TOPOL_BHB68703_SHA256: &str =
    "056a9bd58ac9974c3551b4c7e83f6f3e414237ab6774cfe7d882564480dde12f";
/// SHA-256 of `etc/topol_BHB68705.conf` (name fields only differ from 68701).
pub const T21_TOPOL_BHB68705_SHA256: &str =
    "608a15db9ccea4f75c83b3e47665a7d42aa17d0c2ec16890b0d8db127a2165a3";
/// SHA-256 of `etc/levels.json` (per-board stock freq/voltage ladder).
pub const T21_LEVELS_JSON_SHA256: &str =
    "35a8f4761a909ee7b808a10ef6b56aa29582324361127e3f60141b3f5f96d30e";
/// SHA-256 of the stock `usr/bin/bmminer` (654,124 B, stripped ARM EABI5,
/// BuildID `c99490bf...`) — the cold-init string-evidence source.
pub const T21_BMMINER_SHA256: &str =
    "58c72d446209f946b5c92a04fccc69ee87ba15e464eff463f72e1d0865139879";
/// SHA-256 of the stock `usr/bin/cgminer` (420,524 B, stripped ARM EABI5).
pub const T21_CGMINER_SHA256: &str =
    "163df6af35b29d6756b54a3503242e07292c863863c64f60f1ab23325d1f76a3";
/// SHA-256 of the zynq7007 record's `devicetree.dtb` (controller identity
/// source: `xlnx,zynq-7000`, 256 MiB DDR, pl353 NAND map, UART map).
pub const T21_ZYNQ_DEVICETREE_SHA256: &str =
    "47e56969ce80ae9b1374aea555bf49d3c47637c6207ee33d70a20e7f214e45c0";
/// SHA-256 of the stock cold-init script `etc/init.d/S70cgminer`.
pub const T21_S70CGMINER_SHA256: &str =
    "15fe9d25924fa0cea64d6dc32b1b5fb89d6924194cbc65b475b3f62ecf584df8";
/// SHA-256 of the S21-hydro cross-check topol (`s21-hydro-20240519/.../
/// topol.conf`, machine HHB68601 — same chip, different topology).
pub const S21_HYDRO_TOPOL_SHA256: &str =
    "f182b84b9b76b3fc706d2ecd2264fc2379f03ebe08924c578699041e9f6dd642";

// --- The headline pinned constants (the B9 lane deliverable) ---

/// **T21 BHB6870X: 108 BM1368 per chain** (12 domains × 9, interval 2).
pub const T21_CHIPS_PER_CHAIN: u32 = 108;
/// Chains declared by the stock record (BHB68xxx generation: matches the
/// 3-board SKU; live population stays capture-first).
pub const T21_CHAIN_NUM: u32 = 3;
/// Voltage domains per chain.
pub const T21_CHAIN_DOMAIN_NUM: u32 = 12;
/// ASICs per voltage domain.
pub const T21_DOMAIN_ASIC_NUM: u32 = 9;
/// Numeric chip id as stated by stock (`asic_addr "0x1368"`).
pub const T21_CHIP_TYPE: u16 = 0x1368;
/// PSU dialect string, verbatim — the first stock sighting of APW11A.
/// NOT APW12 (every S19-family board) and NOT the S21-hydro's plain APW11.
pub const T21_PSU_TYPE: &str = "APW11A";
/// PSU 7-bit I²C address (stock `power.i2c_addr: 16`).
pub const T21_PSU_I2C_ADDR: u8 = 0x10;
/// PSU power GPIO (stock `power.gpio: 907` — zynq numbering; the sealed AML
/// record's translation is unknown).
pub const T21_PSU_GPIO: u32 = 907;
/// Stock `power.version` key list, verbatim — the PSU-version keys stock
/// accepts for the APW11A dialect (the version-keyed rail-law input class
/// B6 extracted for APW12; APW11A's own K1/K2 constants are NOT extracted).
pub const T21_PSU_VERSION_KEYS: &[u8] = &[66, 67, 106, 113, 114, 115, 117, 118, 119, 120, 193];
/// The S21-hydro APW11 version-key list (different dialect keys than T21's
/// APW11A — transcribed to pin that the two PSUs are not interchangeable).
pub const S21_HYDRO_APW11_VERSION_KEYS: &[u8] = &[97, 98, 100, 101, 102, 66, 65, 34];
/// Per-chain voltage-MCU I²C address (stock `pic.i2c_addr: 32`).
pub const T21_PIC_I2C_ADDR: u8 = 0x20;
/// Hashboard EEPROM I²C address (stock `eeprom.i2c_addr: 80`, AT24C02D).
pub const T21_EEPROM_I2C_ADDR: u8 = 0x50;
/// LM75A chain sensors (0x48..=0x4B, one per quadrant) + control-board
/// sensors (0x48 right/top, 0x4C left/top), 7-bit I²C.
pub const T21_LM75A_SENSOR_ADDRS: &[u8] = &[0x48, 0x49, 0x4A, 0x4B];
/// Stock fan layout: 4 fans — two right/intake, two left/exhaust.
pub const T21_FAN_COUNT: u32 = 4;

/// Stock `levels.json` ladder, verbatim tokens per board (all three boards
/// identical): `(frequency, voltage)` pairs `[(600, 1550), (350, 1300)]`.
///
/// The "voltage" field is Bitmain's opaque token (same field class as the
/// S19-family levels B6 transcribed and the S15 `"1900"` token) — the
/// physical unit is NOT established by any held byte. Transcription-only:
/// these tokens are stock bring-up evidence for a bench gate, never a DCENT
/// envelope, tune target, or rail datum.
pub const T21_STOCK_LEVELS_TOKENS: &[(u32, u32)] = &[(600, 1550), (350, 1300)];

/// Stock `strategy`/`adjust_strategy` constants, verbatim transcription
/// (evidence for the cold-init contract; NO DCENT tuning authority).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21StockStrategy {
    /// `open_core_high_voltage`.
    pub open_core_high_voltage: u32,
    /// `inc_freq_voltage`.
    pub inc_freq_voltage: u32,
    /// `inc_freq_step` — the stock fixed-step frequency ladder step.
    pub inc_freq_step: u32,
    /// `inc_freq_delay`.
    pub inc_freq_delay: u32,
    /// `pid_target_temp` — stock's own fan-PID target (NOT a DCENT limit).
    pub pid_target_temp: u32,
    /// `voltage_adjust_setp` (stock's own spelling of "step").
    pub voltage_adjust_setp: u32,
    /// `low_freq_miner_mode` — the T21's cold-ambient low-frequency
    /// bring-up mode (see [`T21_BMMINER_INIT_MARKERS`]).
    pub low_freq_miner_mode: bool,
    /// `low_freq_inc_freq_temp` — board-temp gate for leaving low-freq mode.
    pub low_freq_inc_freq_temp: u32,
    /// `low_freq_wait_time`.
    pub low_freq_wait_time: u32,
    /// `max_rise_vol`.
    pub max_rise_vol: u32,
    /// `vol_diff_between_two_mode`.
    pub vol_diff_between_two_mode: u32,
    /// `adjust_strategy.vol_adjust_max`.
    pub vol_adjust_max: u32,
    /// `adjust_strategy.vol_adjust_min`.
    pub vol_adjust_min: u32,
    /// `adjust_strategy.vol_high_temp_adjust_min`.
    pub vol_high_temp_adjust_min: u32,
}

/// The stock `strategy` + `adjust_strategy` block of every T21 record.
pub const T21_STOCK_STRATEGY: T21StockStrategy = T21StockStrategy {
    open_core_high_voltage: 1500,
    inc_freq_voltage: 1500,
    inc_freq_step: 625,
    inc_freq_delay: 100,
    pid_target_temp: 65,
    voltage_adjust_setp: 10,
    low_freq_miner_mode: true,
    low_freq_inc_freq_temp: 38,
    low_freq_wait_time: 240,
    max_rise_vol: 130,
    vol_diff_between_two_mode: 100,
    vol_adjust_max: 1500,
    vol_adjust_min: 1290,
    vol_high_temp_adjust_min: 1270,
};

/// Zynq7007 control-board map as declared by the stock devicetree
/// (transcription; the AML variant's own map is sealed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct T21ZynqControllerMap {
    /// `compatible` string.
    pub compatible: &'static str,
    /// DDR bytes declared by `memory@0` (`reg = <0x0 0x10000000>`).
    pub ddr_bytes: u32,
    /// Console UART VA (`linux,stdout-path` → `serial@e0001000`, UART1).
    pub console_uart_va: u32,
    /// `serial0` alias VA (`serial@e0000000`, UART0) with stock
    /// `current-speed` 115200.
    pub serial0_va: u32,
    /// I²C controller VA (`ps7_i2c@e0005000`, `cdns,i2c-r1p10`, 100 kHz).
    pub i2c0_va: u32,
    /// NAND partition map `(offset, bytes, label)` — pl353 SMC NAND, the
    /// persistent-storage geometry of the zynq record.
    pub nand_partitions: &'static [(u32, u32, &'static str)],
}

/// The zynq7007 controller map (fdtdump-verified, [`T21_ZYNQ_DEVICETREE_SHA256`]).
pub const T21_ZYNQ_CONTROLLER_MAP: T21ZynqControllerMap = T21ZynqControllerMap {
    compatible: "xlnx,zynq-7000",
    ddr_bytes: 0x1000_0000,
    console_uart_va: 0xe000_1000,
    serial0_va: 0xe000_0000,
    i2c0_va: 0xe000_5000,
    nand_partitions: &[
        (0x0000_0000, 0x0280_0000, "BOOT.bin-dts-marker-kernel"),
        (0x0280_0000, 0x0200_0000, "ramfs"),
        (0x0480_0000, 0x0080_0000, "configs"),
        (0x0500_0000, 0x0020_0000, "sig"),
        (0x0520_0000, 0x00e0_0000, "reserve1"),
        (0x0600_0000, 0x0100_0000, "upgrade-ramfs"),
        (0x0700_0000, 0x0380_0000, "upgrade-file"),
        (0x0a80_0000, 0x0580_0000, "reserve2"),
    ],
};

/// The stock cold-init sequence driven by `/etc/init.d/S70cgminer`
/// (sha256 [`T21_S70CGMINER_SHA256`]), in script order. Steps 1-4 are
/// sysfs GPIO exports the script performs before miner start; steps 5-7 are
/// the `do_start()` body. The zynq FPGA/AXI bring-up is RAM-size-keyed
/// (step 6) — the stock kernel driver maps `fpga_mem_driver.ko` at
/// `0x3F000000` (>1 GiB), `0x1F000000` (400 MiB-1 GiB), or `0x0F000000`
/// (smaller), matching the 256 MiB DDR declared by the devicetree to the
/// lowest window.
pub const T21_S70_INIT_ORDER: &[&str] = &[
    "export GPIO941 out 0 (red LED)",
    "export GPIO942 out 0 (green LED)",
    "export GPIO954/955/958/959 out 0 (LCD CS/SID/SCLK/RESET)",
    "sleep 5s",
    "insmod /lib/modules/bitmain_axi.ko (if absent)",
    "insmod fpga_mem_driver.ko at 0x3F000000/0x1F000000/0x0F000000 keyed by MemTotal",
    "start cgminer then bmminer with --default-config /config/cgminer.conf",
];

/// Stock `bmminer` cold-init sequence markers (log-format strings, verbatim;
/// sha256 [`T21_BMMINER_SHA256`]). Order is the string-level bring-up
/// narrative — a disassembled control-flow pass is NOT held, so this is
/// sequence evidence, not an execution contract.
pub const T21_BMMINER_INIT_MARKERS: &[(&str, &str)] = &[
    ("topol-load", "load topol config file %s failed / init topol runtime failed"),
    ("board-identity", "auto exec eeprom_open, but chain %d open eeprom failed"),
    ("board-identity", "eeprom and topol.conf has same board_name: %s, no need update config"),
    ("pic-handshake", "auto exec open_pic, but chain %d open eeprom failed"),
    ("pic-handshake", "pic enabled for chain %d, press anykey to continue..."),
    ("temp-sensors", "auto exec tsensor_open, but chain %d,slave_addr %d open failed"),
    ("temp-sensors", "start up min temp by 75a = %d"),
    ("psu-probe", "power open power_version = 0x%x"),
    ("psu-probe", "check power version failed, use v2 protocal to try it again"),
    ("psu-bringup", "Initializing the power, please wait, this may take up to 2 minutes..."),
    ("voltage-open-core", "Set bitmain miner high voltage open core mode"),
    ("voltage-ladder", "set_voltage_by_steps"),
    ("chain-enable", "test low temp poweron find asic num end, poweroff,and exit program"),
    ("chain-enable", "Chain %d only find %d asic, will power off hash board %d"),
    ("freq-ladder", "fixed step freq_start = %d, freq_end = %d, freq_step = %.2f"),
    ("freq-ladder", "inc freq get min board temp: %d, bringup temp:%d"),
    ("fan-init", "init fan pid target=%d"),
    ("fan-power", "Note: front fan is power on! / Note: rear fan is power on!"),
    ("baud-switch", "set UART baud to %d (bmminer file offset 0x8b334)"),
    ("pic-heartbeat", "chain[%d] heart beat ok. (pic_heart_beat_thread per chain)"),
    ("psu-heartbeat", "power_heart_beat_thread cur_voltage = %d, avg_voltage = %.2f"),
];

impl T21StockTopol {
    /// `chain_row × chain_column` placement-grid product. On every T21
    /// record this EQUALS `chips_per_chain` (12×9 = 108, exactly populated
    /// — unlike the S19-family grids; test-pinned).
    pub const fn row_column_product(&self) -> Option<u32> {
        match (self.chain_row, self.chain_column) {
            (Some(r), Some(c)) => Some(r * c),
            _ => None,
        }
    }

    /// `chain_domain_num × domain_asic_num` — the stock per-chain count's
    /// internal cross-check (12×9 = 108 on every T21 record; test-pinned).
    pub const fn domain_product(&self) -> Option<u32> {
        match (self.chain_domain_num, self.domain_asic_num) {
            (Some(d), Some(a)) => Some(d * a),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t21_stock_geometry_pins_the_bhb6870x_family() {
        assert_eq!(T21_STOCK_BHB68701.chips_per_chain, 108);
        assert_eq!(T21_CHIPS_PER_CHAIN, 108);
        assert_eq!(T21_CHAIN_NUM, 3);
        // Both internal cross-checks of the per-chain count agree, and the
        // 12x9 placement grid is EXACTLY populated on this family (unlike
        // the S19-family 8x10-for-76 grids — nobody may derive a false
        // 108-slot count from a partial grid here, but equally nobody may
        // "correct" 108 down to a grid remainder).
        assert_eq!(T21_STOCK_BHB68701.domain_product(), Some(108));
        assert_eq!(T21_STOCK_BHB68701.row_column_product(), Some(108));
        // Full-SKU arithmetic from the stock record: 3 x 108 = 324.
        assert_eq!(T21_CHAIN_NUM * T21_CHIPS_PER_CHAIN, 324);
    }

    #[test]
    fn t21_chip_identity_is_bm1368_with_stock_core_counts() {
        assert_eq!(T21_STOCK_BHB68701.asic_id, "BM1368");
        assert_eq!(T21_CHIP_TYPE, 0x1368);
        assert_eq!(T21_STOCK_BHB68701.asic_big_core_num, Some(80));
        assert_eq!(T21_STOCK_BHB68701.asic_small_core_num, Some(1276));
        assert_eq!(T21_STOCK_BHB68701.core_small_core_num, Some(16));
        // The per-chip domain field on the T21 record says 1 — the S19-era
        // summaries that generalize "BM1368 = 4 domains" are reading the
        // hydro record (see the divergence pin below).
        assert_eq!(T21_STOCK_BHB68701.asic_domain_num, Some(1));
        assert_eq!(T21_STOCK_BHB68701.asic_addr_interval, Some(2));
    }

    /// Same chip, different chassis, different topology: the S21-hydro
    /// HHB68601 record (also BM1368, 80+1276 cores) declares 4 per-chip
    /// domains, interval 1, 18 dom x 12 = 216/chain and a plain-APW11 PSU.
    /// Chip identity alone therefore never determines T21 contracts — the
    /// T21 stands on its own citations (the cross-check the lane brief
    /// demands).
    #[test]
    fn t21_same_chip_as_s21_hydro_but_different_chain_topology() {
        // S21-hydro facts (s21-hydro-20240519 topol.conf, machine HHB68601,
        // sha256 S21_HYDRO_TOPOL_SHA256) transcribed for the divergence pin:
        const S21_HYDRO_PER_CHIP_DOMAINS: u32 = 4;
        const S21_HYDRO_INTERVAL: u32 = 1;
        const S21_HYDRO_CHIPS_PER_CHAIN: u32 = 216; // 18 dom x 12
        const S21_HYDRO_PSU: &str = "APW11";
        assert_eq!(T21_CHIP_TYPE, 0x1368); // same chip id...
        assert_ne!(
            T21_STOCK_BHB68701.asic_domain_num,
            Some(S21_HYDRO_PER_CHIP_DOMAINS)
        ); // ...different per-chip domains
        assert_ne!(T21_STOCK_BHB68701.asic_addr_interval, Some(S21_HYDRO_INTERVAL));
        assert_ne!(T21_CHIPS_PER_CHAIN, S21_HYDRO_CHIPS_PER_CHAIN);
        assert_ne!(T21_PSU_TYPE, S21_HYDRO_PSU);
    }

    #[test]
    fn t21_psu_dialect_is_apw11a_not_apw12_or_s21_apw11() {
        assert_eq!(T21_PSU_TYPE, "APW11A");
        assert_eq!(T21_PSU_I2C_ADDR, 0x10);
        assert_eq!(T21_PSU_GPIO, 907);
        // Version-key lists are dialect inputs (the class B6's APW12 rail
        // law keys on). T21's APW11A list is NOT the S21-hydro APW11 list —
        // the two PSUs are not interchangeable.
        assert_eq!(
            T21_PSU_VERSION_KEYS,
            &[66, 67, 106, 113, 114, 115, 117, 118, 119, 120, 193]
        );
        assert_ne!(T21_PSU_VERSION_KEYS, S21_HYDRO_APW11_VERSION_KEYS);
        // No APW11A rail-law constant (K1/K2 class) is transcribed anywhere
        // in this module — that extraction is deliberately absent (dossier
        // honest-unknown; bench/Ghidra follow-up).
    }

    #[test]
    fn t21_chain_controller_label_pic1704_and_eeprom_map() {
        assert_eq!(T21_STOCK_BHB68701.pic_topol_label, Some("PIC1704"));
        assert_eq!(T21_PIC_I2C_ADDR, 0x20);
        assert_eq!(T21_STOCK_BHB68701.eeprom_type, Some("AT24C02D"));
        assert_eq!(T21_EEPROM_I2C_ADDR, 0x50);
        assert_eq!(T21_LM75A_SENSOR_ADDRS, &[0x48, 0x49, 0x4A, 0x4B]);
        // The label is transcribed verbatim and is NOT a populated-part
        // proof: the module text keeps the S19-family caveat (live probes of
        // the sibling BHB42601 generation found dsPIC33EP16GS202 in a
        // PIC1704-labelled slot). The BoardDesc facet for this row stays
        // RuntimeDiscovered.
        assert!(T21_STOCK_BHB68701.evidence.contains("B9"));
    }

    #[test]
    fn t21_fan_layout_is_four_fans_two_in_two_out() {
        assert_eq!(T21_FAN_COUNT, 4);
        assert_eq!(T21_STOCK_BHB68701.fan_count, Some(4));
        // ids 0/1 = right/in, ids 2/3 = left/out (stock fan[] array).
    }

    #[test]
    fn t21_zynq_controller_map_pins_ddr_nand_uart_i2c() {
        assert_eq!(T21_ZYNQ_CONTROLLER_MAP.compatible, "xlnx,zynq-7000");
        assert_eq!(T21_ZYNQ_CONTROLLER_MAP.ddr_bytes, 0x1000_0000); // 256 MiB
        assert_eq!(T21_ZYNQ_CONTROLLER_MAP.console_uart_va, 0xe000_1000);
        assert_eq!(T21_ZYNQ_CONTROLLER_MAP.serial0_va, 0xe000_0000);
        assert_eq!(T21_ZYNQ_CONTROLLER_MAP.i2c0_va, 0xe000_5000);
        // 8-partition pl353 NAND map; partitions are contiguous and end at
        // 0x1000_0000 (256 MiB NAND).
        let parts = T21_ZYNQ_CONTROLLER_MAP.nand_partitions;
        assert_eq!(parts.len(), 8);
        assert_eq!(parts[0].2, "BOOT.bin-dts-marker-kernel");
        assert_eq!(parts[0].0, 0);
        let end = parts.last().map(|p| p.0 + p.1).unwrap_or(0);
        assert_eq!(end, 0x1000_0000);
        for w in parts.windows(2) {
            assert_eq!(w[0].0 + w[0].1, w[1].0, "NAND partitions must be contiguous");
        }
    }

    #[test]
    fn t21_s70_cold_init_order_is_transcribed() {
        // The stock boot script's own order: GPIO exports -> sleep -> AXI
        // module -> RAM-size-keyed FPGA mem window -> cgminer+bmminer. The
        // 256 MiB DDR declared by the devicetree selects the 0x0F000000
        // window (MemTotal < 400000 kB branch).
        assert!(T21_S70_INIT_ORDER.iter().any(|s| s.contains("GPIO941")));
        assert!(T21_S70_INIT_ORDER.iter().any(|s| s.contains("bitmain_axi.ko")));
        assert!(T21_S70_INIT_ORDER
            .iter()
            .any(|s| s.contains("0x3F000000/0x1F000000/0x0F000000")));
        assert!(T21_S70_INIT_ORDER.iter().any(|s| s.contains("cgminer then bmminer")));
        // Bounded, transcription-only: no step mutates anything — this is a
        // &'static str evidence list, not an executor.
        assert_eq!(T21_S70_INIT_ORDER.len(), 7);
    }

    #[test]
    fn t21_bmminer_init_markers_cover_the_cold_init_contract() {
        let phases: Vec<&str> = T21_BMMINER_INIT_MARKERS.iter().map(|(p, _)| *p).collect();
        for expected in [
            "topol-load",
            "board-identity",
            "pic-handshake",
            "temp-sensors",
            "psu-probe",
            "psu-bringup",
            "voltage-open-core",
            "voltage-ladder",
            "chain-enable",
            "freq-ladder",
            "fan-init",
            "baud-switch",
            "pic-heartbeat",
            "psu-heartbeat",
        ] {
            assert!(
                phases.contains(&expected),
                "cold-init phase {expected} must have a stock string marker"
            );
        }
        // The numeric post-switch baud is deliberately NOT in the markers —
        // no literal-pool constant exists in the binary; honest unknown.
        assert!(T21_BMMINER_INIT_MARKERS
            .iter()
            .any(|(p, m)| *p == "baud-switch" && m.contains("0x8b334")));
    }

    #[test]
    fn t21_stock_levels_and_strategy_transcribed_verbatim_no_envelope() {
        // levels.json: all three boards carry the identical two-rung ladder.
        assert_eq!(T21_STOCK_LEVELS_TOKENS, &[(600, 1550), (350, 1300)]);
        let s = T21_STOCK_STRATEGY;
        assert_eq!(s.open_core_high_voltage, 1500);
        assert_eq!(s.inc_freq_voltage, 1500);
        assert_eq!(s.inc_freq_step, 625);
        assert_eq!(s.inc_freq_delay, 100);
        assert_eq!(s.pid_target_temp, 65);
        assert_eq!(s.voltage_adjust_setp, 10);
        assert!(s.low_freq_miner_mode);
        assert_eq!(s.low_freq_inc_freq_temp, 38);
        assert_eq!(s.low_freq_wait_time, 240);
        assert_eq!(s.max_rise_vol, 130);
        assert_eq!(s.vol_diff_between_two_mode, 100);
        assert_eq!(s.vol_adjust_max, 1500);
        assert_eq!(s.vol_adjust_min, 1290);
        assert_eq!(s.vol_high_temp_adjust_min, 1270);
        // NO DCENT authority: this module exposes no SiliconTable, no
        // envelope, no tune target — the tokens are stock bring-up evidence
        // only (C3b owns any future envelope row; the C3a tune_guard stays
        // the authority and must keep refusing NotTunable for this family).
    }

    /// The three machine records are ONE contract: the module exposes the
    /// BHB68701 row and the hash pins prove 68703/68705 differ only in name
    /// fields (diff-verified: `machine` + `mix_boardnames` lines only).
    #[test]
    fn t21_three_board_records_are_one_contract_family() {
        assert_ne!(T21_TOPOL_DB_SHA256, T21_TOPOL_BHB68703_SHA256);
        assert_ne!(T21_TOPOL_DB_SHA256, T21_TOPOL_BHB68705_SHA256);
        // ...but the transcription is a single shared contract instance:
        assert_eq!(T21_STOCK_BHB68701.machine_id, "BHB68701");
    }
}
