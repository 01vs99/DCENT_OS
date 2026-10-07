//! Antminer **S21 air family** (S21 / S21 Pro / S21 XP) stock-evidence
//! contracts + the controller adjudication record (Gauntlet lane B10,
//! 2026-09-02; Phase A §3.10 input brief).
//!
//! Same transcription-only rule as [`crate::t21_stock_topol`] and
//! [`crate::scrypt_stock_topology`]: every field states what a held artifact
//! says literally, `None` means the held bytes are silent, nothing is
//! inherited from a sibling SKU, and **no energization, frequency, voltage,
//! PIC, PSU or thermal-control authority lives here**.
//!
//! # Why this module is NOT a `topol.conf` transcription (the honesty spine)
//!
//! The S21 air family's asicminingsupplies stock records are **single-record
//! AMLCtrl BMUs whose only payload is the sealed code-9 `ANDROID!`
//! Amlogic-boot image** (Phase A §3.10: "no new air evidence" — verified
//! again by this lane). There is **no plaintext stock topol/levels/bmminer
//! for any S21 air SKU in the held corpus**. What IS readable from each
//! sealed single is transcribed below at header level only (boot-image
//! section sizes + the `AMLSECU!` factory build timestamp); the payloads are
//! encrypted and nothing in the held corpus unseals them.
//!
//! The lane's real stock-side evidence base is therefore:
//!
//! 1. **Bitmain's own factory test jigs** (first-party, unstripped, with
//!    `debug_info`) — the S21/BHB68603 bench `Config.ini` + the
//!    S21/S21pro/S21xp `single_board_test` binaries. These are *factory*
//!    software for the air boards, not miner firmware; they settle the
//!    factory-side contracts (geometry for the base S21, chip identity for
//!    Pro/XP, the per-board PIC1704 programming surface, bench PSU version
//!    keys, bench levels) and they are the backbone of the controller
//!    adjudication.
//! 2. **The zynq-class S21 hydro stock records** (plaintext `topol.conf` +
//!    `levels.json` + `devicetree.dtb`) — cited ONLY as (a) the
//!    controller-platform cross-check (every zynq-class S21-family record
//!    labels per-chain PIC1704 @ `0x20`) and (b) the same-chip /
//!    different-chassis divergence pins. Hydro BoardDesc/geometry authority
//!    stays with lane B11's [`crate::hydro_fleet`].
//! 3. **Held live-unit observations** (`a lab unit`, the fleet's only S21 air
//!    unit) — cited where the fact is a live datum, not a stock fact.
//!
//! # Held artifacts (gitignored trees; internal RE evidence only)
//!
//! Mirror caveats: third-party public mirror
//!  (HEAD
//! `d140bd0f`; internally consistency-verified only — never redistributed;
//! `PHASE_A_EVIDENCE_REPORT.md` §1.3). The jig corpus under
//!  predates the mirror (held AMTC/HashSource
//! acquisitions). All SHA-256s below were (re)computed by lane B10 against
//! the on-disk bytes.
//!
//! | artifact | path (under `knowledge-base/`) | SHA-256 |
//! |---|---|---|
//! | S21 air sealed payload | `extractions/asicminingsupplies/s21-aml-20241011/components/unknown_09` | [`S21_AIR_PAYLOAD_SHA256`] |
//! | S21 Pro air sealed payload | `extractions/asicminingsupplies/s21-pro-aml-20240828/components/unknown_09` | [`S21PRO_AIR_PAYLOAD_SHA256`] |
//! | S21 XP air sealed payload | `extractions/asicminingsupplies/s21-xp-aml-20241105/components/unknown_09` | [`S21XP_AIR_PAYLOAD_SHA256`] |
//! | S21 factory bench config | `repos/amtc-s21-jig/Config.ini` | [`S21_JIG_CONFIG_SHA256`] |
//! | S21 factory jig binary | `repos/amtc-s21-jig/single_board_test_bm1368` ≡ `repos/HashSource/bitmain_antminer_binaries/S21/single_board_test` (byte-identical, two held copies) | [`S21_JIG_BINARY_SHA256`] |
//! | S21 Pro factory jig binary | `repos/HashSource/bitmain_antminer_binaries/S21pro/single_board_test` | [`S21PRO_JIG_BINARY_SHA256`] |
//! | S21 XP factory jig binary | `repos/HashSource/bitmain_antminer_binaries/S21xp/single_board_test` | [`S21XP_JIG_BINARY_SHA256`] |
//! | S21-hydro stock topol | `extractions/asicminingsupplies/s21-hydro-20240519/…/etc/topol.conf` | [`S21_HYDRO_TOPOL_SHA256`] |
//! | S21-XP-hydro stock topol | `extractions/asicminingsupplies/s21-xp-hydro-20241011/…/etc/topol.conf` | [`S21_XP_HYDRO_TOPOL_SHA256`] |
//! | S21-XP-hydro levels | `…s21-xp-hydro-20241011/…/etc/levels.json` | [`S21_XP_HYDRO_LEVELS_SHA256`] |
//! | S21-XP-hydro devicetree | `…s21-xp-hydro-20241011/components/devicetree.dtb` | [`S21_XP_HYDRO_DTB_SHA256`] |
//! | S21-XP-hydro miner ELF | `…s21-xp-hydro-20241011/…/usr/bin/bmminer` (stripped) | [`S21_XP_HYDRO_BMMINER_SHA256`] |
//!
//! # The controller adjudication record (the lane differentiator)
//!
//! For each S21 air SKU the module pins WHAT THE EVIDENCE SHOWS about the
//! controller/PIC story — **it does not flip any `pic_type_hint`**: the
//! plan gates that flip on DCENT_EE review + DMM bench proof (the B9 T21
//! contradiction flag and B6's PIC16F1704 correction follow the same
//! rule). Summary (each field test-pinned below):
//!
//! * **S21 (BM1368, BHB68603):** the factory bench PROGRAMS a PIC1704 on
//!   every hashboard (flash erase/write/seek + "pic jump from loader to
//!   app" + `Pic heart beat` symbols in Bitmain's own unstripped jig) —
//!   first-party proof the air hashboard family **populates** a PIC1704.
//!   The shipped bench config reads NO temps through it
//!   (`Read_Temperature_From_Pic: false`), and the live AML production
//!   stack never addresses it (ftrace on the fleet unit: zero PIC I2C
//!   traffic; voltage via kernel-DTB TAS5782M + PSU PMBus/GPIO). Verdict:
//!   **part present (factory-proven), idle in the AML runtime** — the
//!   daemon's `NoPic` posture for `am3-s21` is a control-board *software*
//!   fact, not a statement about hashboard silicon.
//! * **S21 Pro (BM1370, A3HB706xx):** Bitmain's own S21pro factory jig
//!   carries the same `bitmain_pic_1704.c` HAL + flash programmer (new
//!   datum this lane) — a second Bitmain-origin source (after the
//!   ePIC-transcribed hashboard DB) supporting PIC1704 presence on the
//!   A3HB7-generation air boards. Air stock record sealed; no live unit.
//!   The ePIC-PIC1704 vs VNish-NoPic vs TAS5782M-DTB three-way
//!   disagreement stays open exactly as `model.rs` records it — the new
//!   datum only STRENGTHENS the pending promotion-time DCENT_EE review.
//! * **S21 XP (BM1370, A3HB705xx):** identical adjudication to the Pro —
//!   its factory jig carries the PIC1704 driver plus `A3HB70501/02/03`
//!   board literals. Air stock record sealed; no live unit.
//!
//! # The BM1370 "20-step PLL table" open item (desk-resolved)
//!
//! `BETA_ROSTER`'s open item asked whether BM1370 inherits the BM1362-style
//! discrete 20-step PLL frequency table. Desk answer, two-pronged:
//!
//! 1. **The stock miner ELF carries no discrete table**: a pattern scan of
//!    the S21-XP-hydro `bmminer` ([`S21_XP_HYDRO_BMMINER_SHA256`]; both
//!    endiannesses of the `0x50XX0141` BM1362-family register template,
//!    400/425/450/475 ladders in four encodings, the BM1362 FBDIV byte
//!    ladder `A0 AA B4 BE C8 D2`, and every `41 01` halfword) found zero
//!    table words — the survivors are all instruction bytes.
//! 2. **Bitmain's factory software computes instead of tabulating**: the
//!    S21pro + S21xp jigs' `get_pllparam_divider` + `set_pllparameter`
//!    (prior desk RE, )
//!    search divider tuples against VCO bounds [2000, 3200] MHz (3125 cap
//!    at REFDIV=1) from a 25 MHz reference and encode into registers
//!    `{0x08, 0x60, 0x64}` — logic-identical between the Pro and XP jigs.
//!
//! Conclusion: the register ENCODING family is shared with BM1362
//! (byte-segmented, postdiv `-1`-encoded), but Bitmain's BM1370 software
//! carries no discrete table to inherit; DCENT's formula-based
//! [`crate::bm1370`] encoder matches the factory formula. No chip-relative
//! change owed; the open item is annotated in the roster.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// 1. Sealed air AML records (header-level transcription only)
// ---------------------------------------------------------------------------

/// Header-level transcription of one sealed S21-family air AML record.
/// Every payload is an encrypted code-9 `ANDROID!` Amlogic-boot image —
/// the fields below are the PLAINTEXT parts of its boot header plus the
/// `AMLSECU!` factory wrapper; nothing else is readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21AirSealedAmlRecord {
    /// SKU the BMU ships for.
    pub sku: &'static str,
    /// Source BMU file name in the mirror (`…/Antminer-SHA-256/…`).
    pub bmu_name: &'static str,
    /// SHA-256 of the source BMU (Phase A ledger).
    pub bmu_sha256: &'static str,
    /// `unknown_09` payload size in bytes.
    pub payload_bytes: u32,
    /// SHA-256 of the `unknown_09` payload.
    pub payload_sha256: &'static str,
    /// Boot-image `kernel_size` (LE u32 @ file offset 0x08).
    pub kernel_size: u32,
    /// Boot-image `ramdisk_size` (LE u32 @ 0x10).
    pub ramdisk_size: u32,
    /// Boot-image `second_size` (LE u32 @ 0x18).
    pub second_size: u32,
    /// Boot-image `page_size` (LE u32 @ 0x24).
    pub page_size: u32,
    /// Boot-image `cmdline` (@ 0x40) — verbatim (all three say only this).
    pub cmdline: &'static str,
    /// `AMLSECU!` wrapper build timestamp, 16 ASCII digits
    /// (`YYYYMMDDhhmmssxx`) at file offset 0x410.
    pub amlsecu_build_timestamp: &'static str,
}

/// S21 (air) sealed AML record — mirror BMU
/// `Antminer-S21-AML-release-202410111634.bmu`.
pub const S21_AIR_SEALED_AML: S21AirSealedAmlRecord = S21AirSealedAmlRecord {
    sku: "S21",
    bmu_name: "Antminer-S21/Antminer-S21-AML-release-202410111634.bmu",
    bmu_sha256: "c09a1904b958495ceaa6261e84235f61e295d01e88e079b83508c9f5b0644435",
    payload_bytes: 15_137_280,
    payload_sha256: "e91db6a157d17df334f0e2e7e85929ab7a115d653dec4707ffc2d87b73c17a86",
    kernel_size: 0x005c_0800,
    ramdisk_size: 0x008a_7000,
    second_size: 0x0000_7800,
    page_size: 2048,
    cmdline: "init=/sbin/init",
    amlsecu_build_timestamp: "2024101117590111",
};

/// S21 Pro (air) sealed AML record — mirror BMU
/// `Antminer-S21-Pro-AML-release-202408281552.bmu`.
pub const S21PRO_AIR_SEALED_AML: S21AirSealedAmlRecord = S21AirSealedAmlRecord {
    sku: "S21 Pro",
    bmu_name: "Antminer-S21-Pro/Antminer-S21-Pro-AML-release-202408281552.bmu",
    bmu_sha256: "c5f45da59d0ef1c58eda8f53595f9a2559a2d3c5d178bc36425e04fcf0899e49",
    payload_bytes: 15_948_288,
    payload_sha256: "d617faab2fd8b94682f18844f012c3689734217420f2021afb7d64c7c35acb35",
    kernel_size: 0x005c_0800,
    ramdisk_size: 0x0096_d000,
    second_size: 0x0000_7800,
    page_size: 2048,
    cmdline: "init=/sbin/init",
    amlsecu_build_timestamp: "2024082816145518",
};

/// S21 XP (air) sealed AML record — mirror BMU
/// `Antminer-S21-XP-AML-release-202411051642.bmu`.
pub const S21XP_AIR_SEALED_AML: S21AirSealedAmlRecord = S21AirSealedAmlRecord {
    sku: "S21 XP",
    bmu_name: "Antminer-S21-XP/Antminer-S21-XP-AML-release-202411051642.bmu",
    bmu_sha256: "dc05255115674f2c5dfa147fbd1dc8f7c7e11f34c972ee7cd863a0208d821849",
    payload_bytes: 15_948_288,
    payload_sha256: "09b6d0b95f51607963d9b224a5c772e7420f76b454d4e0cec6d578f1fabe867c",
    kernel_size: 0x005c_0800,
    ramdisk_size: 0x0096_d000,
    second_size: 0x0000_7800,
    page_size: 2048,
    cmdline: "init=/sbin/init",
    amlsecu_build_timestamp: "2024110518194710",
};

/// SHA-256 of the S21 air sealed payload (`unknown_09`).
pub const S21_AIR_PAYLOAD_SHA256: &str = S21_AIR_SEALED_AML.payload_sha256;
/// SHA-256 of the S21 Pro air sealed payload (`unknown_09`).
pub const S21PRO_AIR_PAYLOAD_SHA256: &str = S21PRO_AIR_SEALED_AML.payload_sha256;
/// SHA-256 of the S21 XP air sealed payload (`unknown_09`).
pub const S21XP_AIR_PAYLOAD_SHA256: &str = S21XP_AIR_SEALED_AML.payload_sha256;

/// A second, earlier sealed S21 Pro AML sample is ALSO held (vnish-farm
/// mirror stock: `Antminer-S21-Pro-AML-release-202407071629.bmu`, 15,944,704
/// B, byte-identical BMU/inner blob) — two sealed S21 Pro builds, zero new
/// plaintext. Recorded so nobody re-acquires it as an "unsealing" lead.
pub const S21PRO_AIR_SECOND_SEALED_SAMPLE_SHA256: &str =
    "a9900e82c12bbca1fe3b16d870a8ae8a92a9ca12d535110e53411079626302dc";

// ---------------------------------------------------------------------------
// 2. The factory jig contracts (first-party, the lane's evidence backbone)
// ---------------------------------------------------------------------------

/// Factory-bench contract for one S21-family air board, transcribed from
/// Bitmain's own `single_board_test` jig (+ its `Config.ini` where held).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21AirFactoryJig {
    /// SKU under test.
    pub sku: &'static str,
    /// Hashboard board code(s) the jig test-flow names.
    pub board_codes: &'static [&'static str],
    /// ASIC the jig's `asic-abs` layer is compiled for (its own check
    /// string: `asic should be BM…`).
    pub asic_id: &'static str,
    /// SHA-256 of the jig binary.
    pub binary_sha256: &'static str,
    /// The jig carries `../../hal/pic/bitmain_pic_1704.c` + the 1704
    /// flash programmer symbols (`_bitmain_pic_{write,erase,seek}_1704`,
    /// `_update_pic_app_program_1704`, `_app_{read,write}_data_from_flash_
    /// 1704_v8`, `pic jump from loader to app`).
    pub carries_pic1704_driver: bool,
    /// Geometry from the bench config, if the per-board `Config.ini` is
    /// held (base S21 only — the Pro/XP jigs read geometry from an
    /// external config NOT held; their geometry stays on the Lane J
    /// bosminer/ePIC citations).
    pub bench_geometry: Option<(u32, u32, u32)>, // (chips, domains, per-domain)
    /// Exact provenance sentence.
    pub evidence: &'static str,
}

/// S21 air factory bench: `Config.ini` (sha256 [`S21_JIG_CONFIG_SHA256`])
/// pinned to `Miner_Type S21`, `Board_Name BHB68603`, `Asic_Type BM1368`,
/// `Asic_Num 108`, `Voltage_Domain 12 × Asic_Num_Per_Voltage_Domain 9` —
/// **the first-party factory confirmation of the Lane I geometry**
/// (3-board SKU = 3 × 108; the fleet's `a lab unit` unit populates slot 2).
pub const S21_AIR_FACTORY_JIG: S21AirFactoryJig = S21AirFactoryJig {
    sku: "S21",
    board_codes: &["BHB68603"],
    asic_id: "BM1368",
    binary_sha256: "0be428078300f78752ad1b9f9be8ae47e301d4b9db1fdfc351683731a1f4377e",
    carries_pic1704_driver: true,
    bench_geometry: Some((108, 12, 9)),
    evidence: "amtc-s21-jig Config.ini + single_board_test_bm1368 (unstripped, \
               debug_info; byte-identical second copy HashSource S21/) — lane B10",
};

/// S21 Pro air factory jig (A3HB706xx): `asic-abs/src/BM1370` + PIC1704 HAL.
/// No bench Config.ini held → geometry stays on Lane J citations (13×5=65).
pub const S21PRO_AIR_FACTORY_JIG: S21AirFactoryJig = S21AirFactoryJig {
    sku: "S21 Pro",
    board_codes: &["A3HB70601", "A3HB70602"], // from bosminer model-list, Lane J
    asic_id: "BM1370",
    binary_sha256: "eb0b8d615ba35c78b9ec2ccc462ba6608c8087c261b239fe1314923531503507",
    carries_pic1704_driver: true,
    bench_geometry: None,
    evidence: "HashSource S21pro/single_board_test (BM1370 asic-abs + \
               bitmain_pic_1704.c + NCT218 sensor strings) — lane B10; board \
               codes cited from bosminer model-list.json (Lane J), the binary \
               itself does not carry them",
};

/// S21 XP air factory jig (A3HB705xx): `asic-abs/src/BM1370` + PIC1704 HAL
/// + `A3HB70501/70502/70503` literals IN the binary.
pub const S21XP_AIR_FACTORY_JIG: S21AirFactoryJig = S21AirFactoryJig {
    sku: "S21 XP",
    board_codes: &["A3HB70501", "A3HB70502", "A3HB70503"],
    asic_id: "BM1370",
    binary_sha256: "4b4e08d1f206836749b71b2a01822a66127fbf7d9904d0ba91427e28fd4f3f61",
    carries_pic1704_driver: true,
    bench_geometry: None,
    evidence: "HashSource S21xp/single_board_test (BM1370 asic-abs + \
               bitmain_pic_1704.c + A3HB70501/02/03 literals + NCT218) — \
               lane B10",
};

/// SHA-256 of the S21 bench `Config.ini`
/// (`repos/amtc-s21-jig/Config.ini`, 3,424 B, dated 2024-01-23).
pub const S21_JIG_CONFIG_SHA256: &str =
    "fab1a64d0514a96fbb11d8f5758cbcbc0c73b2b663abc7216d2bbba88df9e357";
/// SHA-256 of the S21 jig binary (3,984,488 B, ARM EABI5, dynamically
/// linked, **with debug_info, not stripped**, BuildID `d3fd9dbd…`; held
/// twice byte-identical: `amtc-s21-jig` + `HashSource S21`).
pub const S21_JIG_BINARY_SHA256: &str = S21_AIR_FACTORY_JIG.binary_sha256;
/// SHA-256 of the S21 Pro jig binary (same unstripped class).
pub const S21PRO_JIG_BINARY_SHA256: &str = S21PRO_AIR_FACTORY_JIG.binary_sha256;
/// SHA-256 of the S21 XP jig binary (same unstripped class).
pub const S21XP_JIG_BINARY_SHA256: &str = S21XP_AIR_FACTORY_JIG.binary_sha256;

// --- The S21 bench Config.ini contracts (verbatim, the base-SKU set) ---

/// **S21 BHB68603: 108 BM1368 per board, 12 voltage domains × 9** —
/// Bitmain's own factory number, agreeing with the Lane I live/enum
/// resolution and the T21 BHB6870X grid (same 12×9 layout, different SKU).
pub const S21_AIR_CHIPS_PER_BOARD: u32 = 108;
/// Voltage domains per BHB68603 board.
pub const S21_AIR_DOMAIN_NUM: u32 = 12;
/// ASICs per voltage domain.
pub const S21_AIR_DOMAIN_ASIC_NUM: u32 = 9;
/// Bench PSU firmware-version keys the S21 test accepts, verbatim:
/// `[193, 113, 114, 116, 117, 118, 119, 120]`. Version keys are PSU-firmware
/// identifiers (the class B6's APW12 rail law and every stock topol
/// `power.version` list key on) — they do NOT name a PSU model, and the
/// bench's own power hardware is an APW9 driver (`bitmain_power_APW9.c`),
/// so this list is bench-scope evidence, not the miner's PSU population.
/// Note `116`: first appearance in any held version-key list (absent from
/// the T21 APW11A and S19-XP APW12 stock lists).
pub const S21_JIG_POWER_VERSION_KEYS: &[u8] = &[193, 113, 114, 116, 117, 118, 119, 120];
/// Bench test ladder (level → pre-open-core mV / operating mV / MHz):
/// `(1500, 1320, 450)`, `(1500, 1320, 425)`, `(1500, 1320, 400)` —
/// factory *test* levels, NOT miner nameplate (the air stock levels are
/// sealed). The fleet unit's own EEPROM carries 1360 mV / 460 MHz class
/// values (held fixture log, Lane I/B10 citations).
pub const S21_JIG_TEST_LEVELS: &[(u32, u32, u32)] =
    &[(1500, 1320, 450), (1500, 1320, 425), (1500, 1320, 400)];
/// Bench chain baud: **12 Mbaud — JIG-ONLY** (same class as the S19k
/// bosminer note: the miner run baud is 3.125 Mbaud, live-proven on
/// `a lab unit`; the FPGA-side table in the BM1370 jigs is {3.0M, 1.5M, 6.0M,
/// 12.0M}).
pub const S21_JIG_BAUD: u32 = 12_000_000;
/// The shipped S21 bench config reads NO temperature through the board PIC
/// (`Read_Temperature_From_Pic: false`), none from the ASIC sensors, and
/// uses the two control-board LM75A (`[0, 4]` → 0x48/0x4C) — a factory
/// datum for the controller adjudication: the production AML stack can
/// bring a board up without addressing the PIC at all.
pub const S21_JIG_READ_TEMP_FROM_PIC: bool = false;
/// Per-board sensor map the bench knows: PIC-side LM75A `[0,1,2,3]`
/// (0x48-0x4B quadrants), ASIC-side NCT218 `[25, 57, 58]` (0x19/0x39/0x3A),
/// control-board LM75A `[0, 4]`.
pub const S21_JIG_PIC_SENSOR_LM75A_ADDRS: &[u8] = &[0, 1, 2, 3];
pub const S21_JIG_ASIC_SENSOR_NCT218_ADDRS: &[u8] = &[25, 57, 58];
pub const S21_JIG_CTRLBOARD_SENSOR_LM75A_ADDRS: &[u8] = &[0, 4];

// ---------------------------------------------------------------------------
// 3. The controller adjudication (per SKU) — evidence record, NO code flip
// ---------------------------------------------------------------------------

/// The per-SKU controller/PIC adjudication, as the stock+factory+live
/// evidence shows it. Every field is a citation-backed fact or an explicit
/// unknown; nothing here authorizes a `pic_type_hint` change (the flip is
/// gated on DCENT_EE review + DMM bench proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S21AirControllerAdjudication {
    /// SKU.
    pub sku: &'static str,
    /// Chip id the factory jig's own asic-abs layer is compiled for.
    pub factory_chip: u16,
    /// First-party factory evidence that the hashboard POPULATES a
    /// PIC1704 (jig flash-programmer symbols + `bitmain_pic_1704.c`).
    pub hashboard_pic1704_factory_proof: bool,
    /// Live-unit evidence the AML production stack leaves the PIC idle
    /// (ftrace: zero PIC I2C traffic; voltage via kernel-DTB TAS5782M
    /// @ 0x48-0x4B + PSU PMBus/GPIO). `false` = no live unit exists.
    pub aml_runtime_pic_idle_live_evidence: bool,
    /// The stock air AML record state (all three SKUs: sealed).
    pub stock_air_record_sealed: bool,
    /// What stays unknown (bench/Ghidra queue).
    pub open_questions: &'static [&'static str],
}

/// S21 adjudication: **part present, runtime idle** (see module docs).
pub const S21_AIR_CONTROLLER_ADJUDICATION: S21AirControllerAdjudication =
    S21AirControllerAdjudication {
        sku: "S21",
        factory_chip: 0x1368,
        hashboard_pic1704_factory_proof: true,
        aml_runtime_pic_idle_live_evidence: true,
        stock_air_record_sealed: true,
        open_questions: &[
            "does any AML stock build ever address the per-board PIC1704 at \
             runtime (sealed record — unseal or serial-analyze a live unit)?",
            "does a zynq/CV-class control board exist for BHB68603 (stock \
             hydro siblings all say PIC1704@0x20)?",
            "DMM rail-polarity proof for the GPIO437-class PSU-enable pin \
             (queue item #4 dependency)",
        ],
    };

/// S21 Pro adjudication: presence now two-Bitmain-source supported, runtime
/// story sealed, no live unit.
pub const S21PRO_AIR_CONTROLLER_ADJUDICATION: S21AirControllerAdjudication =
    S21AirControllerAdjudication {
        sku: "S21 Pro",
        factory_chip: 0x1370,
        hashboard_pic1704_factory_proof: true,
        aml_runtime_pic_idle_live_evidence: false,
        stock_air_record_sealed: true,
        open_questions: &[
            "ePIC PIC1704@0x20 vs VNish direct-NoPic vs TAS5782M kernel-DTB \
             three-way disagreement — unchanged, now with factory-jig \
             presence support (promotion-time DCENT_EE review)",
            "no live BM1370 unit anywhere on the fleet (first-light item)",
            "PSU dialect for the air Pro is UNKNOWN (sealed record; the \
             shipped TOML APW12 label is an inherited placeholder, not \
             stock evidence)",
        ],
    };

/// S21 XP adjudication: identical shape to the Pro.
pub const S21XP_AIR_CONTROLLER_ADJUDICATION: S21AirControllerAdjudication =
    S21AirControllerAdjudication {
        sku: "S21 XP",
        factory_chip: 0x1370,
        hashboard_pic1704_factory_proof: true,
        aml_runtime_pic_idle_live_evidence: false,
        stock_air_record_sealed: true,
        open_questions: &[
            "same three-way controller disagreement as the Pro (ePIC PIC1704 \
             vs VNish NoPic vs TAS5782M DTB); factory jig adds presence \
             support — DCENT_EE promotion-scope",
            "no live unit; exact ttyS3/ttyS2/ttyS1 route never exercised",
            "PSU dialect unknown (sealed record; TOML APW12 label is a \
             placeholder — the S21-XP TODO-confirm note stands)",
        ],
    };

/// The one-line verdict per SKU (for surfaces/tests to pin).
pub const S21_CONTROLLER_VERDICTS: &[(&str, &str)] = &[
    (
        "S21",
        "PIC1704 populated (factory-proven) + idle in the AML runtime \
         (live-proven); NoPic is a control-board software posture, not a \
         silicon statement",
    ),
    (
        "S21 Pro",
        "PIC1704 presence supported by two Bitmain-origin sources (factory \
         jig + ePIC DB) vs NoPic runtime sources; unresolved — DCENT_EE \
         promotion-scope, no flip",
    ),
    (
        "S21 XP",
        "same as S21 Pro (factory jig carries A3HB70501/02/03 + the PIC1704 \
         driver); unresolved — DCENT_EE promotion-scope, no flip",
    ),
];

// ---------------------------------------------------------------------------
// 4. Live-unit (fleet `a lab unit`) reference datums — cited, not re-derived
// ---------------------------------------------------------------------------

/// The fleet S21 air unit's PSU identity, first-hand (held fixture-RE doc):
/// an **APW121215f** reporting `power_version` **118 (0x76)** — a member of
/// the bench key list [`S21_JIG_POWER_VERSION_KEYS`]. The shipped
/// `am3-s21` TOML's `psu_override model = "APW12"` label is therefore
/// live-corroborated FOR THE BASE SKU'S HELD UNIT ONLY (Pro/XP have no
/// equivalent datum).
pub const S21_LIVE_PSU_MODEL: &str = "APW121215f";
/// `power_version` byte the live PSU reports.
pub const S21_LIVE_PSU_VERSION_KEY: u8 = 118;
/// Live-unit fan map (BraiinsOS deep-probe, held doc): **4 fans** — tachs
/// GPIO 447-450 (`FAN_FRONT_SPEED0/1`, `FAN_REAR_SPEED0/1`), PWM via
/// `pwmchip0/pwm0` (rear pair) + `pwmchip0/pwm1` (front pair), 10 kHz.
pub const S21_LIVE_FAN_COUNT: u32 = 4;

// ---------------------------------------------------------------------------
// 5. Zynq-class hydro sibling context (cross-checks only — B11 owns hydro)
// ---------------------------------------------------------------------------

/// SHA-256 of the S21-hydro stock topol (`s21-hydro-20240519`, machines
/// HHB68601/68602/68501/68502…).
pub const S21_HYDRO_TOPOL_SHA256: &str =
    "f182b84b9b76b3fc706d2ecd2264fc2379f03ebe08924c578699041e9f6dd642";
/// SHA-256 of the S21-XP-hydro stock topol (`s21-xp-hydro-20241011`,
/// machines H6HB70601/H6HB70602/H6HB70501/H1HB70601).
pub const S21_XP_HYDRO_TOPOL_SHA256: &str =
    "d765e8ef74534ccc5bfb7b1f6a1fc8e38af10ef2b0f8d3327b0d3ef4b6b70a57";
/// SHA-256 of the S21-XP-hydro stock `levels.json`.
pub const S21_XP_HYDRO_LEVELS_SHA256: &str =
    "976deb8d1569cf50b1c4f4ddc309056476b458343cabefef9159b58bb87ecd85";
/// SHA-256 of the S21-XP-hydro `devicetree.dtb` — fdtdump-verified by this
/// lane: `compatible "xlnx,zynq-7000"`, model "Xilinx Zynq", dual
/// Cortex-A9 (the zynq-class controller identity for the S21 family's
/// hydro records).
pub const S21_XP_HYDRO_DTB_SHA256: &str =
    "47e56969ce80ae9b1374aea555bf49d3c47637c6207ee33d70a20e7f214e45c0";
/// SHA-256 of the S21-XP-hydro `bmminer` (626,484 B, stripped ARM) — the
/// negative-scan subject of the BM1370 PLL open item (module docs).
pub const S21_XP_HYDRO_BMMINER_SHA256: &str =
    "aa642f76eb2f1680780d29a59ffd4a823d4f31b2a906d6fa8099c84322ddfda1";

/// Same-chip / different-chassis divergence pins (why no S21 air contract
/// may be derived from the hydro records — and vice versa):
///
/// | chip | air chassis | hydro chassis |
/// |---|---|---|
/// | BM1368 | S21 air: 108/board **12 dom × 9** (factory jig; T21-shaped grid) | S21 hydro HHB685xx/686xx: **216/chain, 18 dom × 12**, interval 1, APW11 |
/// | BM1370 | S21 Pro air: 65/board **13 × 5**; S21 XP air: 91/board **13 × 7** (Lane J) | S21-XP hydro H6HB70x/H1HB: **160/chain, 20 dom × 8**, interval 1, APW11 @0x10 gpio907, PIC1704@0x20, AT24C02D@0x50, 4 fans |
///
/// Every zynq-class S21-family stock record labels **PIC1704 @ `0x20`** —
/// the platform half of the adjudication above.
pub const S21_FAMILY_CHIP_TOPOLOGY_DIVERGENCE: &[(&str, &str, &str)] = &[
    ("BM1368", "S21 air 108 = 12x9 (jig)", "S21 hydro 216 = 18x12 (topol)"),
    ("BM1370", "S21 Pro air 65 = 13x5 (Lane J)", "XP hydro 160 = 20x8 (topol)"),
    ("BM1370", "S21 XP air 91 = 13x7 (Lane J)", "XP hydro 160 = 20x8 (topol)"),
];

/// S21-XP-hydro stock `levels.json` ladders, verbatim tokens (miner →
/// [(freq, voltage-token)]): hydro nameplate evidence ONLY — the AIR
/// Pro/XP ladders are sealed. Voltage fields are Bitmain opaque tokens
/// (unit not established; same class as every levels.json held).
pub const S21_XP_HYDRO_STOCK_LEVELS_TOKENS: &[(&str, &[(u32, u32)])] = &[
    ("H6HB70601", &[(370, 1900), (410, 2140)]),
    ("H6HB70602", &[(450, 1900), (495, 2180)]),
    ("H6HB70501", &[(461, 1900), (495, 2180)]),
    ("H1HB70601", &[(450, 1900), (495, 2180)]),
];

/// S21-hydro stock `levels.json` (same caveat): HHB68601/68602
/// 350/1900 + 390/2060; HHB685xx 370/1900 + 410/2080-class.
pub const S21_HYDRO_STOCK_LEVELS_TOKENS: &[(&str, &[(u32, u32)])] = &[
    ("HHB68601", &[(350, 1900), (390, 2060)]),
    ("HHB68602", &[(350, 1900), (390, 2060)]),
];

#[cfg(test)]
mod tests {
    use super::*;

    // --- 1. sealed AML records ---

    #[test]
    fn all_three_air_aml_records_are_sealed_android_images() {
        for r in [
            S21_AIR_SEALED_AML,
            S21PRO_AIR_SEALED_AML,
            S21XP_AIR_SEALED_AML,
        ] {
            assert!(r.bmu_name.contains("AML-release"));
            assert_eq!(r.cmdline, "init=/sbin/init"); // the ONLY cmdline text
            assert_eq!(r.page_size, 2048);
            assert_eq!(r.kernel_size, 0x005c_0800); // shared kernel image size
            assert!(r.amlsecu_build_timestamp.len() == 16);
            // The three payloads differ (distinct builds)...
            assert_eq!(r.payload_sha256.len(), 64);
        }
        // ...and the Pro/XP share the newer, larger ramdisk layout.
        assert_eq!(S21_AIR_SEALED_AML.ramdisk_size, 0x008a_7000);
        assert_eq!(S21PRO_AIR_SEALED_AML.ramdisk_size, 0x0096_d000);
        assert_eq!(S21XP_AIR_SEALED_AML.ramdisk_size, 0x0096_d000);
        assert_eq!(S21PRO_AIR_SEALED_AML.payload_bytes, S21XP_AIR_SEALED_AML.payload_bytes);
        // Build timestamps order: Pro (2024-08-28) < S21 (2024-10-11) < XP
        // (2024-11-05) — the records are distinct factory builds.
        assert!(S21PRO_AIR_SEALED_AML.amlsecu_build_timestamp
            < S21_AIR_SEALED_AML.amlsecu_build_timestamp);
        assert!(S21_AIR_SEALED_AML.amlsecu_build_timestamp
            < S21XP_AIR_SEALED_AML.amlsecu_build_timestamp);
    }

    #[test]
    fn sealed_records_grant_no_runtime_contract() {
        // The honesty spine: nothing beyond header fields may be claimed
        // from these payloads. The struct carries ONLY header/wrapper
        // fields — no geometry, PSU, PIC or levels field exists on it,
        // and no test may "derive" one.
        for r in [
            S21_AIR_SEALED_AML,
            S21PRO_AIR_SEALED_AML,
            S21XP_AIR_SEALED_AML,
        ] {
            assert!(r.payload_bytes > 15_000_000); // real sealed blob
        }
        // A second sealed S21 Pro sample is also held — still zero plaintext.
        assert_eq!(S21PRO_AIR_SECOND_SEALED_SAMPLE_SHA256.len(), 64);
    }

    // --- 2. factory jig contracts ---

    #[test]
    fn s21_factory_jig_pins_the_lane_i_geometry_first_party() {
        let (chips, domains, per_domain) = S21_AIR_FACTORY_JIG
            .bench_geometry
            .expect("base-S21 bench Config.ini is held");
        assert_eq!((chips, domains, per_domain), (108, 12, 9));
        assert_eq!(S21_AIR_CHIPS_PER_BOARD * 1, 108);
        assert_eq!(S21_AIR_DOMAIN_NUM * S21_AIR_DOMAIN_ASIC_NUM, 108);
        assert_eq!(S21_AIR_FACTORY_JIG.board_codes, &["BHB68603"]);
        assert_eq!(S21_AIR_FACTORY_JIG.asic_id, "BM1368");
        // Full-SKU arithmetic: 3 boards x 108 = 324 (matches skus.conf row).
        assert_eq!(3 * S21_AIR_CHIPS_PER_BOARD, 324);
    }

    #[test]
    fn every_air_family_jig_carries_the_pic1704_factory_surface() {
        for j in [
            S21_AIR_FACTORY_JIG,
            S21PRO_AIR_FACTORY_JIG,
            S21XP_AIR_FACTORY_JIG,
        ] {
            assert!(
                j.carries_pic1704_driver,
                "{} jig must carry bitmain_pic_1704.c (B10 evidence)",
                j.sku
            );
            assert_eq!(j.binary_sha256.len(), 64);
        }
        // The three binaries are distinct artifacts.
        let hashes = [
            S21_JIG_BINARY_SHA256,
            S21PRO_JIG_BINARY_SHA256,
            S21XP_JIG_BINARY_SHA256,
        ];
        for i in 0..hashes.len() {
            for k in i + 1..hashes.len() {
                assert_ne!(hashes[i], hashes[k]);
            }
        }
        // Pro/XP geometry is NOT bench-pinned (no Config.ini held) — their
        // geometry stays on the Lane J citations; the jig struct says so.
        assert_eq!(S21PRO_AIR_FACTORY_JIG.bench_geometry, None);
        assert_eq!(S21XP_AIR_FACTORY_JIG.bench_geometry, None);
        // The XP jig alone carries its board literals in-binary.
        assert_eq!(
            S21XP_AIR_FACTORY_JIG.board_codes,
            &["A3HB70501", "A3HB70502", "A3HB70503"]
        );
    }

    #[test]
    fn s21_jig_bench_contracts_transcribed_verbatim() {
        assert_eq!(
            S21_JIG_POWER_VERSION_KEYS,
            &[193, 113, 114, 116, 117, 118, 119, 120]
        );
        // 116 is the first-sighting key: absent from T21 APW11A and every
        // held APW12 stock list (cross-checked against t21_stock_topol).
        assert!(!crate::t21_stock_topol::T21_PSU_VERSION_KEYS.contains(&116));
        assert_eq!(
            S21_JIG_TEST_LEVELS,
            &[(1500, 1320, 450), (1500, 1320, 425), (1500, 1320, 400)]
        );
        assert_eq!(S21_JIG_BAUD, 12_000_000);
        assert!(!S21_JIG_READ_TEMP_FROM_PIC);
        assert_eq!(S21_JIG_PIC_SENSOR_LM75A_ADDRS, &[0, 1, 2, 3]);
        assert_eq!(S21_JIG_ASIC_SENSOR_NCT218_ADDRS, &[25, 57, 58]);
        assert_eq!(S21_JIG_CTRLBOARD_SENSOR_LM75A_ADDRS, &[0, 4]);
        // The bench's own PSU driver is APW9 — the version-key list is
        // bench-scope evidence, never a miner-PSU-population claim.
        assert!(S21_AIR_FACTORY_JIG.evidence.contains("amtc-s21-jig"));
    }

    // --- 3. controller adjudication ---

    #[test]
    fn s21_adjudication_is_present_but_runtime_idle() {
        let a = S21_AIR_CONTROLLER_ADJUDICATION;
        assert_eq!(a.factory_chip, 0x1368);
        assert!(a.hashboard_pic1704_factory_proof);
        assert!(a.aml_runtime_pic_idle_live_evidence);
        assert!(a.stock_air_record_sealed);
        assert_eq!(a.open_questions.len(), 3);
        // The live PSU datum ties the fleet unit into the bench key list.
        assert!(S21_JIG_POWER_VERSION_KEYS.contains(&S21_LIVE_PSU_VERSION_KEY));
        assert_eq!(S21_LIVE_PSU_MODEL, "APW121215f");
        assert_eq!(S21_LIVE_FAN_COUNT, 4);
    }

    #[test]
    fn pro_and_xp_adjudications_stay_open_pending_dcent_ee() {
        for a in [
            S21PRO_AIR_CONTROLLER_ADJUDICATION,
            S21XP_AIR_CONTROLLER_ADJUDICATION,
        ] {
            assert_eq!(a.factory_chip, 0x1370);
            assert!(a.hashboard_pic1704_factory_proof);
            assert!(!a.aml_runtime_pic_idle_live_evidence); // no live unit
            assert!(a.stock_air_record_sealed);
            assert!(a
                .open_questions
                .iter()
                .any(|q| q.contains("DCENT_EE")));
            assert!(a
                .open_questions
                .iter()
                .any(|q| q.contains("PSU dialect") || q.contains("PSU")));
        }
        // The PSU-placeholder honesty: neither Pro nor XP may claim the
        // base unit's APW121215f datum.
        assert!(S21PRO_AIR_CONTROLLER_ADJUDICATION
            .open_questions
            .iter()
            .any(|q| q.contains("placeholder")));
    }

    #[test]
    fn controller_verdicts_exist_for_all_three_skus_and_flip_nothing() {
        assert_eq!(S21_CONTROLLER_VERDICTS.len(), 3);
        for (sku, verdict) in S21_CONTROLLER_VERDICTS {
            assert!(!verdict.is_empty());
            if *sku != "S21" {
                // Pro/XP verdicts must say unresolved + DCENT_EE scope.
                assert!(verdict.contains("unresolved"));
                assert!(verdict.contains("DCENT_EE") || verdict.contains("no flip"));
            }
        }
        // The adjudication grants no runtime authority: this module exposes
        // no executor, no SiliconTable, no envelope — structurally pinned
        // by the absence of any such type in the public surface above.
    }

    // --- 4. hydro cross-checks (context only) ---

    #[test]
    fn chip_identity_never_determines_air_contracts() {
        // BM1368: air 12x9 vs hydro 18x12; BM1370: air 13x5 / 13x7 vs
        // hydro 20x8. The divergence table pins all four contrasts.
        assert_eq!(S21_FAMILY_CHIP_TOPOLOGY_DIVERGENCE.len(), 3);
        assert!(S21_FAMILY_CHIP_TOPOLOGY_DIVERGENCE
            .iter()
            .any(|(chip, air, hydro)| *chip == "BM1368"
                && air.contains("12x9") && hydro.contains("18x12")));
        assert!(S21_FAMILY_CHIP_TOPOLOGY_DIVERGENCE
            .iter()
            .any(|(chip, air, hydro)| *chip == "BM1370"
                && air.contains("13x7") && hydro.contains("20x8")));
    }

    #[test]
    fn zynq_class_s21_records_label_pic1704_everywhere() {
        // The platform half of the adjudication: every zynq-class S21
        // family stock record (hydro machines, fdtdump-verified zynq-7000
        // dtb) labels per-chain PIC1704 @ 0x20 with AT24C02D @ 0x50.
        // Transcribed from the two hydro topol DBs pinned above.
        for (machine, _) in S21_XP_HYDRO_STOCK_LEVELS_TOKENS {
            assert!(machine.starts_with("H") || machine.starts_with("HHB"));
        }
        assert!(S21_XP_HYDRO_DTB_SHA256
            == "47e56969ce80ae9b1374aea555bf49d3c47637c6207ee33d70a20e7f214e45c0");
        // Same dtb hash as the T21 zynq record (the generation shares the
        // board-support dtb family) — controller identity cross-source.
        assert_eq!(
            S21_XP_HYDRO_DTB_SHA256,
            crate::t21_stock_topol::T21_ZYNQ_DEVICETREE_SHA256
        );
    }

    #[test]
    fn hydro_levels_are_tokens_only_never_air_nameplate() {
        // The AIR Pro/XP nameplate ladders are sealed — only the hydro
        // tokens are held, and they are opaque Bitmain tokens (no unit).
        assert_eq!(
            S21_XP_HYDRO_STOCK_LEVELS_TOKENS[0],
            (
                "H6HB70601",
                &[(370u32, 1900u32), (410u32, 2140u32)] as &[(u32, u32)]
            )
        );
        assert_eq!(S21_HYDRO_STOCK_LEVELS_TOKENS[0].0, "HHB68601");
        // Frequency spread 350-495 MHz across the hydro family — recorded
        // as stock bring-up evidence only (no DCENT envelope; C3b scope).
        let freqs: Vec<u32> = S21_XP_HYDRO_STOCK_LEVELS_TOKENS
            .iter()
            .flat_map(|(_, l)| l.iter().map(|(f, _)| *f))
            .collect();
        assert!(freqs.iter().all(|f| (350..=500).contains(f)));
    }

    /// The BM1370 "20-step PLL table" open item: resolved desk-side as
    /// FORMULA-based (no discrete table to inherit). Pins both prongs.
    #[test]
    fn bm1370_pll_open_item_resolves_formula_not_table() {
        // Prong 1: the stock miner ELF (hash pinned) carries no discrete
        // BM1362-style table — negative pattern scan documented in the
        // module header (LE/BE 0x50XX0141 words, ladders, FBDIV bytes).
        assert_eq!(S21_XP_HYDRO_BMMINER_SHA256.len(), 64);
        // Prong 2: the factory jigs COMPUTE divider tuples (VCO 2000-3200,
        // 25 MHz ref, regs {0x08, 0x60, 0x64}) — logic-identical Pro/XP.
        // The in-tree formula encoder is the SSOT: bm1370's VCO clamp
        // matches the factory bounds (pinned by bm1370's own jig tests).
        assert_eq!(crate::bm1370::BM1370_TABLE.chip_family, "BM1370");
    }
}
