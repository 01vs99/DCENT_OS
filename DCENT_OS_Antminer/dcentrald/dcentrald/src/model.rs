#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportTier {
    Validated,
    Experimental,
    /// Hardware identity/evidence is modeled, but no callable mining runtime
    /// or complete board target exists.
    EvidenceOnly,
    Planned,
    Blind,
}

impl SupportTier {
    /// Whether this model-tier label claims a callable mining runtime.
    ///
    /// Evidence, driver fragments, and build artifacts are intentionally not
    /// enough. `Experimental` means implemented and callable with live
    /// validation still pending; non-runnable rows must use a non-callable
    /// tier.
    pub const fn claims_callable_runtime(self) -> bool {
        matches!(self, Self::Validated | Self::Experimental)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelPicTypeHint {
    Pic16,
    DsPic,
    NoPic,
}

/// Strongly-typed model enum for variants with full hardware detail.
///
/// The string-keyed [`lookup_model`] remains the primary API for legacy
/// callers; this enum is the forward-looking form that enables exhaustive
/// pattern matches in drivers that need platform-specific codepaths
/// (e.g. MiscCtrl triple-write, PIC framing, PSU protocol dispatch).
///
/// Phase 2 Agent D (2026-04-20): only `S19jProAm2` is populated so far.
/// Additional variants will be introduced as each platform is validated
/// end-to-end; until then, drivers should keep consuming [`ModelSpec`]
/// via the string key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Model {
    /// Antminer S19j Pro on am2 X19 control board (Zynq + BM1362 + dsPIC33).
    /// Live probe: 203.0.113.139.
    S19jProAm2,
}

impl Model {
    /// Canonical string key used with [`lookup_model`].
    pub const fn model_key(self) -> &'static str {
        match self {
            Self::S19jProAm2 => "s19jproam2",
        }
    }

    /// bos_platform value as reported by `/etc/bos_platform` on BraiinsOS.
    pub const fn platform_key(self) -> &'static str {
        match self {
            Self::S19jProAm2 => "zynq-bm3-am2",
        }
    }

    /// Board family (matches Buildroot board dir / sysupgrade prefix family).
    pub const fn board_family(self) -> &'static str {
        match self {
            Self::S19jProAm2 => "am2",
        }
    }

    /// Sysupgrade board target — MUST match the tarball prefix exactly
    /// (; wrong prefix = brick).
    pub const fn board_target(self) -> &'static str {
        match self {
            Self::S19jProAm2 => "am2-s19j",
        }
    }

    /// Lookup the matching [`ModelSpec`] (infallible for enum variants).
    pub fn spec(self) -> ModelSpec {
        // SAFETY: every enum variant has a registered ModelSpec entry.
        lookup_model(self.model_key()).expect("Model variant has registered ModelSpec")
    }
}

/// Detect the [`Model`] from a BraiinsOS `bos_platform` string plus an
/// observed ASIC chip ID (as returned by the GetAddress broadcast).
///
/// `zynq-bm3-am2` alone is ambiguous — the S19 Pro (BM1398) and S19j Pro
/// (BM1362) share the am2 control board. We disambiguate via `chip_id`:
///   - 0x1362 → `S19jProAm2`
///   - 0x1398 → S19 Pro (no enum variant yet; returns `None` for Phase 2 D)
///
/// Returns `None` when the (platform, chip) pair isn't a known enum variant.
/// Callers should fall back to [`lookup_model`] with the configured model
/// string in that case.
pub fn detect_model_from_platform(bos_platform: &str, chip_id: Option<u16>) -> Option<Model> {
    match (bos_platform.trim(), chip_id) {
        ("zynq-bm3-am2", Some(0x1362)) => Some(Model::S19jProAm2),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeProfile {
    X17S17,
    X17T17,
    X17S17Plus,
    X17T17Plus,
    X17S17e,
    X17T17e,
}

impl RuntimeProfile {
    pub fn key(self) -> &'static str {
        match self {
            Self::X17S17 => "x17-s17-dspic-48",
            Self::X17T17 => "x17-t17-pic16-30",
            Self::X17S17Plus => "x17-s17plus-pic16-65",
            Self::X17T17Plus => "x17-t17plus-pic16-44",
            Self::X17S17e => "x17-s17e-dspic-planned",
            Self::X17T17e => "x17-t17e-pic16-planned",
        }
    }

    pub fn chips_per_chain(self) -> Option<u8> {
        match self {
            Self::X17S17 => Some(48),
            Self::X17T17 => Some(30),
            Self::X17S17Plus => Some(65),
            Self::X17T17Plus => Some(44),
            Self::X17S17e | Self::X17T17e => None,
        }
    }

    pub fn pic_type_hint(self) -> ModelPicTypeHint {
        match self {
            Self::X17S17 | Self::X17S17e => ModelPicTypeHint::DsPic,
            Self::X17T17 | Self::X17S17Plus | Self::X17T17Plus | Self::X17T17e => {
                ModelPicTypeHint::Pic16
            }
        }
    }

    pub fn pic_addrs_hint(self) -> Option<&'static [u8]> {
        match self.pic_type_hint() {
            ModelPicTypeHint::Pic16 => Some(X17_PIC_ADDRS),
            ModelPicTypeHint::DsPic | ModelPicTypeHint::NoPic => None,
        }
    }
}

const X17_PIC_ADDRS: &[u8] = &[0x50, 0x51, 0x52];

/// Thermal threshold bundle (degrees Celsius).
///
/// Semantics mirror the S9/S19 thermal controller:
///   - `target_c`  — PID setpoint
///   - `hot_c`     — push fans to max (honors PWM cap)
///   - `dangerous_c` — PCB/board danger line; throttle frequency
///   - `dangerous_internal_c` — die/chip danger line; disable hash boards
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThermalThresholds {
    pub target_c: u8,
    pub hot_c: u8,
    pub dangerous_c: u8,
    pub dangerous_internal_c: u8,
}

/// Extended, fully-populated hardware constants for a validated model variant.
///
/// This is the Phase-2 forward-looking form: one struct per `Model` enum
/// variant with every hardware constant a driver could need, verified
/// against a live probe. Keeps the legacy string-keyed [`ModelSpec`] system
/// untouched so existing call sites are unaffected.
///
/// Lookup via [`Model::extended_spec`] or [`lookup_extended_spec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelExtendedSpec {
    /// Canonical string key (matches [`Model::model_key`]).
    pub model_key: &'static str,
    /// Hardware chain count (populated boards are a runtime fact).
    pub chain_count: u8,
    /// ASIC chips per populated chain.
    pub chips_per_chain: u8,
    /// SHA-256 cores per ASIC chip (e.g. 114 for BM1387, 4 for BM1362).
    pub cores_per_chip: u16,
    /// Rated full-unit hashrate in TH/s (per Bitmain datasheet).
    pub rated_hashrate_th: u16,
    /// Rated full-unit wall power in watts.
    pub rated_power_w: u16,
    /// Default mining frequency in MHz (conservative pre-autotune).
    pub default_freq_mhz: u16,
    /// Default shared-rail voltage in millivolts.
    pub default_voltage_mv: u16,
    /// Hard voltage floor in millivolts.
    pub voltage_min_mv: u16,
    /// Hard voltage ceiling in millivolts.
    pub voltage_max_mv: u16,
    /// Minimum legal mining frequency in MHz.
    pub freq_min_mhz: u16,
    /// Maximum legal mining frequency in MHz.
    pub freq_max_mhz: u16,
    /// UART baud used during ASIC enumeration / init phase.
    pub init_baud: u32,
    /// UART baud used during sustained mining (post-MiscCtrl upgrade).
    pub mining_baud: u32,
    /// Thermal control thresholds.
    pub thermal: ThermalThresholds,
    /// Fan channel count on the control board.
    pub fan_count: u8,
    /// Default industrial-profile PWM cap (home/heater profiles override
    /// via config down to ~30 —).
    pub fan_pwm_cap_industrial: u8,
    /// PIC I2C bus addresses (empty slice for NoPic platforms).
    pub pic_addrs: &'static [u8],
    /// Primary expected PIC firmware byte (e.g. 0x89 for S19j Pro am2).
    pub pic_fw_byte_expected: u8,
    /// Additional PIC firmware bytes considered compatible.
    pub pic_fw_bytes_secondary: &'static [u8],
    /// bos_platform key (e.g. `zynq-bm3-am2`).
    pub platform_key: &'static str,
    /// Board family string (e.g. `am2`) — MUST match Buildroot / sysupgrade.
    pub board_family: &'static str,
    /// Sysupgrade target prefix (e.g. `am2-s19j`). Wrong prefix = brick
    ///.
    pub board_target: &'static str,
}

/// PIC firmware bytes considered compatible with the S19j Pro am2 driver.
/// Primary is 0x89 (observed on .139 — BraiinsOS+ 26.04-plus). 0x88/0xB9/0xFE
/// are additional S19/S17+ am2 PIC firmware variants seen across the fleet.
const S19JPRO_AM2_PIC_FW_SECONDARY: &[u8] = &[0x88, 0xB9, 0xFE];

/// PIC I2C addresses for S19j Pro am2 (dsPIC33 on am2 X19 control board).
/// Source: live probe of 203.0.113.139 (see
/// ).
const S19JPRO_AM2_PIC_ADDRS: &[u8] = &[0x20, 0x21, 0x22];

/// S19j Pro am2 ModelExtendedSpec — verified on 203.0.113.139 (2026-04-20).
pub const S19JPRO_AM2_SPEC: ModelExtendedSpec = ModelExtendedSpec {
    model_key: "s19jproam2",
    chain_count: 3,
    chips_per_chain: 126,
    cores_per_chip: 4,
    rated_hashrate_th: 104,
    rated_power_w: 3068,
    default_freq_mhz: 545,
    default_voltage_mv: 13_700,
    voltage_min_mv: 11_960,
    voltage_max_mv: 15_200,
    freq_min_mhz: 50,
    freq_max_mhz: 1300,
    init_baud: 115_200,
    mining_baud: 3_125_000,
    thermal: ThermalThresholds {
        target_c: 60,
        hot_c: 80,
        dangerous_c: 90,
        dangerous_internal_c: 110,
    },
    fan_count: 4,
    // Industrial-profile default. Home/heater users MUST override to 30 via
    // config. The driver itself never hardcodes
    // above config — this value is only the upper bound for the industrial
    // profile.
    fan_pwm_cap_industrial: 80,
    pic_addrs: S19JPRO_AM2_PIC_ADDRS,
    pic_fw_byte_expected: 0x89,
    pic_fw_bytes_secondary: S19JPRO_AM2_PIC_FW_SECONDARY,
    platform_key: "zynq-bm3-am2",
    board_family: "am2",
    board_target: "am2-s19j",
};

impl Model {
    /// Lookup the fully-populated hardware spec for this variant.
    pub const fn extended_spec(self) -> ModelExtendedSpec {
        match self {
            Self::S19jProAm2 => S19JPRO_AM2_SPEC,
        }
    }
}

/// String-keyed lookup for [`ModelExtendedSpec`]. Returns `None` for keys
/// that don't (yet) have a full Phase-2 spec.
pub fn lookup_extended_spec(model: &str) -> Option<ModelExtendedSpec> {
    let normalized = normalize_model_token(model);
    match normalized.as_str() {
        "s19jproam2" => Some(S19JPRO_AM2_SPEC),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelSpec {
    pub model_key: &'static str,
    pub family_key: &'static str,
    pub chip_label: &'static str,
    pub chip_id: Option<u16>,
    /// Chips on ONE hash board.
    ///
    /// **Provenance (2026-08-06 audit).** The BM1385/BM1387-era values are not
    /// guesses — every one matches Bitmain's own factory jig configs in
    /// *`, which declare
    /// `AsicType` + `AsicNum` per model:
    ///
    /// | config | `AsicType` | `AsicNum` | row here |
    /// |---|---|---|---|
    /// | `Config.ini-S9`    | 1387 | 63 | `s9`  = 63 |
    /// | `Config.ini-S9+`   | 1387 | 84 | `s9+` = 84 |
    /// | `Config.ini-T9`    | 1387 | 57 | `t9`  = 57 |
    /// | `Config.ini-T9+`   | 1387 | **18** | `t9+` = 18 |
    /// | `Config.ini-S7-45` / `-S7-54` | 1385 | 45 / 54 | (no row yet) |
    /// | `Config.ini-V11-S` | 1390 | 60 | (no row yet) |
    ///
    /// Two consequences worth keeping written down:
    /// - `t9+` = 18 is **correct**. `research/models/:26`
    ///   claims "3 | 63" for T9+, but 63 is exactly S9's `AsicNum` — an
    ///   S9 copy-across, not a measurement.
    /// - These counts are **per hash board**. They are NOT a board count, so
    ///   they never on their own establish a chain topology.
    pub chips_per_chain_hint: Option<u8>,
    pub pic_type_hint: Option<ModelPicTypeHint>,
    pub pic_addrs_hint: Option<&'static [u8]>,
    pub support_tier: SupportTier,
}

fn normalize_model_token(model: &str) -> String {
    model
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+')
        .collect()
}

pub fn lookup_model(model: &str) -> Option<ModelSpec> {
    let normalized = normalize_model_token(model);

    let spec = match normalized.as_str() {
        // Antminer S7 (BM1385). Registered for IDENTITY ONLY.
        //
        // Evidence: Bitmain's own AMTC jig configs
        //  and
        // `-S7-54` (`Name=S7 HASH board`, `AsicType=1385`, `CoreNum=50`), which
        // corroborate `dcentrald-silicon-profiles::bm1385`'s independently
        // jig-decompiled `BM1385_CORES_PER_CHIP = 50`.
        //
        // `chips_per_chain_hint: None` is deliberate and NOT laziness: the jig
        // ships **two** S7 board variants — `AsicNum=45` and `AsicNum=54` — and
        // nothing in the held corpus says which one a given S7 carries.
        // Declaring either would be a coin flip on enumeration geometry, the
        // same error that put a false "63" on T9+ in MASTER_MODEL_CATALOG.
        //
        // There is deliberately NO `SUPPORT_MATRIX.md` row and no
        // `board_target`: we hold no S7 firmware and no S7 control-board
        // evidence, and `AsicProtocolIdentity` has no `Bm1385` variant, so a
        // board row could not be spelled honestly. See the matching
        // `model-rs-key-without-matrix-row:s7` entry in
        // `scripts/check_support_matrix_drift.py`.
        "s7" => ModelSpec {
            model_key: "s7",
            family_key: "bm1385",
            chip_label: "BM1385",
            chip_id: Some(0x1385),
            chips_per_chain_hint: None,
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::EvidenceOnly,
        },
        "s9" => ModelSpec {
            model_key: "s9",
            family_key: "bm1387",
            chip_label: "BM1387",
            chip_id: Some(0x1387),
            chips_per_chain_hint: Some(63),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Validated,
        },
        // The identical 2019-07-31 S9i/S9j production images actively call
        // the bare PIC enable/heartbeat and exact S9 DAC law. These are
        // exact 3x63 BM1387 beta compositions, distinct from T9+'s framed PIC.
        "s9i" | "antminers9i" | "s9j" | "antminers9j" => ModelSpec {
            model_key: if normalized.ends_with("s9i") {
                "s9i"
            } else {
                "s9j"
            },
            family_key: "bm1387",
            chip_label: "BM1387",
            chip_id: Some(0x1387),
            chips_per_chain_hint: Some(63),
            pic_type_hint: Some(ModelPicTypeHint::Pic16),
            pic_addrs_hint: Some(&[0x55, 0x56, 0x57]),
            support_tier: SupportTier::Experimental,
        },
        // Antminer S9++ (BM1387, 54 chips/board). Identity-only.
        //
        // Evidence: the unstripped AMTC `single-board-test` binary exports
        // `set_Voltage_S9_plus_plus_BM1387_54` — chip family and chip count are
        // both encoded in the symbol, so unlike S7 (which the jig ships at BOTH
        // 45 and 54) this count is unambiguous and IS declared.
        //:217,470-471`.
        //
        // No `SUPPORT_MATRIX.md` row / `board_target` for the same reason as S7:
        // no S9++ firmware or control-board evidence is held. Paired with
        // `model-rs-key-without-matrix-row:s9++` in the drift gate.
        "s9++" | "s9plusplus" => ModelSpec {
            model_key: "s9++",
            family_key: "bm1387",
            chip_label: "BM1387",
            chip_id: Some(0x1387),
            chips_per_chain_hint: Some(54),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::EvidenceOnly,
        },
        // Exact C43/BM1393 native compositions use the retained FPGA/PIC owner.
        // Generic PIC hints stay absent because its framed ABI is specialised.
        "s9se" => ModelSpec {
            model_key: "s9se",
            family_key: "bm1393",
            chip_label: "BM1393",
            chip_id: Some(0x1393),
            chips_per_chain_hint: Some(60),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        "s9k" => ModelSpec {
            model_key: "s9k",
            family_key: "bm1393",
            chip_label: "BM1393",
            chip_id: Some(0x1393),
            chips_per_chain_hint: Some(60),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        "s9+" | "s9plus" => ModelSpec {
            model_key: "s9+",
            family_key: "bm1387",
            chip_label: "BM1387P",
            chip_id: Some(0x1387),
            chips_per_chain_hint: Some(84),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::EvidenceOnly,
        },
        "t9" => ModelSpec {
            model_key: "t9",
            family_key: "bm1387",
            chip_label: "BM1387",
            chip_id: Some(0x1387),
            chips_per_chain_hint: Some(57),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::EvidenceOnly,
        },
        "t9+" | "t9plus" => ModelSpec {
            model_key: "t9+",
            family_key: "bm1387",
            chip_label: "BM1387",
            chip_id: Some(0x1387),
            chips_per_chain_hint: Some(18),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::EvidenceOnly,
        },
        "s15" | "antminers15" | "t15" | "antminert15" => ModelSpec {
            model_key: if normalized.ends_with("t15") {
                "t15"
            } else {
                "s15"
            },
            family_key: "bm1391",
            chip_label: "BM1391",
            chip_id: Some(0x1391),
            chips_per_chain_hint: Some(if normalized.ends_with("t15") { 60 } else { 72 }),
            // The native runtime owns the exact application protocol; this
            // model hint does not select or identify the PIC microcontroller.
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        "s17" | "s17pro" => ModelSpec {
            model_key: "s17",
            family_key: "bm1397",
            chip_label: "BM1397",
            chip_id: Some(0x1397),
            chips_per_chain_hint: Some(48),
            pic_type_hint: Some(ModelPicTypeHint::DsPic),
            pic_addrs_hint: None,
            // 2026-08-27 unlock-armada (B1 runtime + B2 skus flip): the S17
            // hybrid lane is a desk-validated callable runtime; the tier
            // follows the EXPERIMENTAL acceptance claim. Live energize stays
            // bench-gated (DCENT_AM2_S17_ALLOW_ENERGIZE, never in images).
            support_tier: SupportTier::Experimental,
        },
        "t17" => ModelSpec {
            model_key: "t17",
            family_key: "bm1397",
            chip_label: "BM1397",
            chip_id: Some(0x1397),
            chips_per_chain_hint: Some(30),
            pic_type_hint: Some(ModelPicTypeHint::Pic16),
            pic_addrs_hint: Some(X17_PIC_ADDRS),
            // 2026-08-27 unlock-armada: desk-validated callable s17-hybrid
            // lane (dsPIC33 G2a controller class per A1 §V1).
            support_tier: SupportTier::Experimental,
        },
        // S17+/T17+ are BM1397 -- operator-confirmed twice and corroborated by four
        // independent sources. Promoted from the unregistered 0x1396 to the
        // RECOGNIZED BM1397 identity (the same one S17 / S17 Pro / T17 already
        // use) by operator decision 2026-08-03. Chip COUNTS differ from S17
        // (65 and 44 per chain, not 48) and are unchanged.
        // 2026-08-27 unlock-armada: the four BM1397 17-series BoardDesc rows
        // were promoted to the desk-validated s17-hybrid lane and their
        // acceptance rows claim EXPERIMENTAL, so the complete-model tier
        // follows (PIC16 G2b controller class per A1 §V1). Live energize
        // remains bench-gated and no unit is on the fleet.
        "s17+" | "s17plus" => ModelSpec {
            model_key: "s17+",
            family_key: "bm1397",
            chip_label: "BM1397",
            chip_id: Some(0x1397),
            chips_per_chain_hint: Some(65),
            pic_type_hint: Some(ModelPicTypeHint::Pic16),
            pic_addrs_hint: Some(X17_PIC_ADDRS),
            support_tier: SupportTier::Experimental,
        },
        "t17+" | "t17plus" => ModelSpec {
            model_key: "t17+",
            family_key: "bm1397",
            chip_label: "BM1397",
            chip_id: Some(0x1397),
            chips_per_chain_hint: Some(44),
            pic_type_hint: Some(ModelPicTypeHint::Pic16),
            pic_addrs_hint: Some(X17_PIC_ADDRS),
            support_tier: SupportTier::Experimental,
        },
        "s17e" => ModelSpec {
            model_key: "s17e",
            family_key: "bm1396",
            chip_label: "BM1396",
            chip_id: Some(0x1396),
            chips_per_chain_hint: Some(135),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        // Exact native framed application custody; no generic PIC adapter hint.
        "t17e" => ModelSpec {
            model_key: "t17e",
            family_key: "bm1396",
            chip_label: "BM1396",
            chip_id: Some(0x1396),
            chips_per_chain_hint: Some(78),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        "s19" => ModelSpec {
            model_key: "s19",
            family_key: "bm1398",
            chip_label: "BM1398",
            chip_id: Some(0x1398),
            // SETTLED first-party (Gauntlet B6, 2026-09-02): the stock S19
            // topol.conf names hashboard NBS1902 = BM1398P with 76 ASICs/chain
            // (8x10 grid, 38 domains x 2, addr interval 3) — Phase A §3.7 row 7,
            // .
            // The old "76-hint vs 114" divergence is board-dependent, not a bug:
            // stock itself ships TWO S19-class boards (NBS1902-76 and the S19
            // Pro's NBP1901-114). This hint still only seeds the expected-count
            // display — runtime enumeration stays authoritative, and the BoardDesc
            // runtime remains management-only (tier Planned). Geometry pinned as
            // `bm1398_protocol::S19_NBS1902_BOARD_GEOMETRY`.
            chips_per_chain_hint: Some(76),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        "s19pro" => ModelSpec {
            model_key: "s19pro",
            family_key: "bm1398",
            chip_label: "BM1398",
            chip_id: Some(0x1398),
            chips_per_chain_hint: Some(114),
            pic_type_hint: None,
            pic_addrs_hint: None,
            // Exact am2-s19pro/NBP1901 native composition now consumes its
            // ExperimentalOptIn BoardDesc before generic serial hardware.
            // The controller is bound by that owner, not a model-level hint.
            support_tier: SupportTier::Experimental,
        },
        "s19a" => ModelSpec {
            model_key: "s19a",
            family_key: "bm1398",
            chip_label: "BM1398",
            chip_id: Some(0x1398),
            chips_per_chain_hint: Some(72),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        // Antminer S19+ (BM1398, 80 chips/board), exact BHB28701 runtime profile.
        //
        // Exact held evidence:
        // - Bosminer model-list, 16,854 B, SHA-256
        //   c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0,
        //   lines 432-440: S19+, zynq-bm3-am2, BM1398, 80/HB.
        // - VNish 1.2.7 thermal matrix, SHA-256
        //   4e065ebd7605fbeb88a3aa04f6124ed9230eed40d48409de33685854f8b7a1f4:
        //   BHB28701, S19+, 3x80.
        // - exact toolkit package member
        //   `vnishfarm-s19plus-xil-nand-v1.2.6-rc5-install.tar.gz`,
        //   13,029,668 B, SHA-256
        //   ae1a6498702419e25269b250890d9780ae6e3f688ecdbbd5002ead7efa7fd99b;
        //   its held `/etc/fw-info` spells model `s19plus`, platform `xil`,
        //   install type `nand`.
        //
        // The exact package's hwscan joins model constructor 0x7ed14 to
        // defaults constructor 0x7ebd8: BHB28701, 80 chips, ten domains of
        // eight, 645 MHz / 14.00 V. Its cgminer parses this model-info and
        // selects ASIC 0x1398 and Xilinx power callbacks. Native startup
        // still requires exact physical identity, PIC89/PSU71, controller
        // and fabric checks. The Bosminer 40x2 layout is not our authority.
        "s19+" | "s19plus" | "antminers19+" | "antminers19plus" => ModelSpec {
            model_key: "s19plus",
            family_key: "bm1398",
            chip_label: "BM1398",
            chip_id: Some(0x1398),
            chips_per_chain_hint: Some(80),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        "t19" => ModelSpec {
            model_key: "t19",
            family_key: "bm1398",
            chip_label: "BM1398",
            chip_id: Some(0x1398),
            // SETTLED desk-side first-party (Gauntlet B6, 2026-09-02): the stock
            // T19 topol.conf names hashboard NBT1903 = BM1398P with 76 ASICs/chain
            // (8x10 grid, 38 domains x 2, addr interval 3) — Phase A §3.7 row 9,
            // ,
            // pinned as `bm1398_protocol::T19_NBT1903_BOARD_GEOMETRY`. The
            // chain-population count (VNish says 3x76) remains a live-capture
            // question; the per-chain count here is stock-authoritative.
            chips_per_chain_hint: Some(76),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Experimental,
        },
        // Antminer S19j classic (non-Pro, hashboard BHB42701). Identity
        // CORRECTED 2026-09-02 (Gauntlet lane B5b): the prior "BM1398
        // identity-only" attribution is REFUTED by Bitmain's own stock
        // topology DB — the S19j merge image's 15-machine `config[]` DB
        // states BHB42701 = BM1362 (`asic_addr "0x1362"`), 108 ASICs/chain
        // (12x9 placement grid exactly populated), 36 voltage domains x 3,
        // address interval 2, 65 big + 514 small cores, chain MCU labeled
        // PIC1704 @ 0x20, PSU APW12 @ 0x10 gpio 907. Exact source:
        //
        // 02_Antminer_S19j_zynq7007/components/minerfs.image.gz.tree/etc/
        // topol.conf` (sha256 61a6404b..., entry BHB42701; byte-identical in
        // both zynq7007 records). Transcription + pins:
        // `dcentrald-silicon-profiles::s19_family_stock_topol`;
        // adjudication: PHASE_A_EVIDENCE_REPORT.md §3.6 (SETTLED).
        // Registered BoardDesc row: `am2-s19j-classic` — distinct from the
        // S19j Pro's `am2-s19j` key (different hashboard; Denied,
        // capture-first, no runtime sharing). Evidence-only tier unchanged:
        // no unit ever contacted, no callable runtime, no live PIC/PSU
        // contract.
        "s19j" => ModelSpec {
            model_key: "s19j",
            family_key: "bm1362",
            chip_label: "BM1362",
            chip_id: Some(0x1362),
            chips_per_chain_hint: Some(108),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::EvidenceOnly,
        },
        "s19jpro" => ModelSpec {
            model_key: "s19jpro",
            family_key: "bm1362",
            chip_label: "BM1362",
            chip_id: Some(0x1362),
            chips_per_chain_hint: Some(126),
            pic_type_hint: None,
            pic_addrs_hint: None,
            // The acceptance row is the Zynq AM2 target whose mining path is
            // offline/live proven at the Experimental tier. Keep the generic
            // SKU token aligned with that callable-runtime claim; the distinct
            // CV1835 target remains separately fail-closed in BoardDesc.
            support_tier: SupportTier::Experimental,
        },
        // S19j Pro on am2 X19 control board (Zynq + BM1362 + dsPIC33 @ 0x20-0x22).
        // Dedicated entry so `Model::S19jProAm2::spec()` has a registered ModelSpec
        // and the string key resolves unambiguously. Full hardware constants live
        // in `S19JPRO_AM2_SPEC` (ModelExtendedSpec).
        "s19jproam2" => ModelSpec {
            model_key: "s19jproam2",
            family_key: "bm1362",
            chip_label: "BM1362",
            chip_id: Some(0x1362),
            chips_per_chain_hint: Some(126),
            pic_type_hint: Some(ModelPicTypeHint::DsPic),
            pic_addrs_hint: Some(S19JPRO_AM2_PIC_ADDRS),
            support_tier: SupportTier::Experimental,
        },
        "s19xp" => ModelSpec {
            model_key: "s19xp",
            family_key: "bm1366",
            chip_label: "BM1366",
            chip_id: Some(0x1366),
            chips_per_chain_hint: Some(110),
            // R12 exact production factory selects the retained AML PSU owner.
            // NoPic describes software custody; populated factory PICs are untouched.
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            support_tier: SupportTier::Experimental,
        },
        "s19jxp" => ModelSpec {
            model_key: "s19jxp",
            family_key: "bm1366",
            chip_label: "BM1366",
            chip_id: Some(0x1366),
            chips_per_chain_hint: Some(110),
            // R12 exact production factory selects the retained AML PSU owner.
            // NoPic describes software custody; populated factory PICs are untouched.
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            support_tier: SupportTier::Experimental,
        },
        // Exact A126 and Plus120 factory profiles select PSU software custody.
        // Classic BHB42601/21/41 keeps its separate PIC-controlled route.
        "s19jproa" | "antminers19jproa" => ModelSpec {
            model_key: "s19jproa",
            family_key: "bm1362",
            chip_label: "BM1362",
            chip_id: Some(0x1362),
            chips_per_chain_hint: Some(126),
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            support_tier: SupportTier::Experimental,
        },
        "s19jpro+" | "s19jproplus" => ModelSpec {
            model_key: "s19jproplus",
            family_key: "bm1362",
            chip_label: "BM1362",
            chip_id: Some(0x1362),
            chips_per_chain_hint: Some(120),
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            support_tier: SupportTier::Experimental,
        },
        "s19k" | "s19kpro" => ModelSpec {
            model_key: "s19k",
            family_key: "bm1366",
            chip_label: "BM1366",
            chip_id: Some(0x1366),
            chips_per_chain_hint: Some(77),
            // S19K Pro is NoPic per `/etc/bosminer.toml` model
            // "Antminer S19K Pro NoPic" on .78 (BraiinsOS+ 25.07-plus,
            // 2026-04-29). Voltage via TAS5782M kernel-managed.
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            // The am3-s19k acceptance row is an explicit Experimental
            // callable runtime. Preserve that claim here; install and bench
            // readiness remain governed by their independent gates.
            support_tier: SupportTier::Experimental,
        },
        "s21" => ModelSpec {
            model_key: "s21",
            family_key: "bm1368",
            chip_label: "BM1368",
            chip_id: Some(0x1368),
            // FIRST-PARTY factory confirmation (Gauntlet B10, 2026-09-02):
            // Bitmain's own S21 test jig Config.ini (amtc-s21-jig, sha256
            // fab1a64d...) pins Board_Name BHB68603 = BM1368, Asic_Num 108,
            // 12 voltage domains x 9 — agreeing with the Lane I live/enum
            // resolution (3x108=324 full SKU; the .135 unit populates slot
            // 2). Transcribed in s21_family_stock_topol.
            chips_per_chain_hint: Some(108),
            // NoPic here is the live-proven Amlogic CONTROL-BOARD software
            // posture (TAS5782M kernel-DTB + PSU PMBus/GPIO; ftrace shows
            // zero PIC I2C traffic), NOT a silicon statement: the B10
            // factory evidence proves the BHB68603 hashboard POPULATES a
            // PIC1704 (the jig flashes it; the shipped bench config sets
            // Read_Temperature_From_Pic: false). The stock air AML record
            // is sealed — whether any AML build ever addresses the PIC at
            // runtime is unknown. Keep NoPic (it is the correct runtime
            // contract for the only held platform); a zynq-class board on
            // the same hashboards would face live PIC1704 silicon.
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            support_tier: SupportTier::Experimental,
        },
        "t21" => ModelSpec {
            model_key: "t21",
            family_key: "bm1368",
            chip_label: "BM1368",
            chip_id: Some(0x1368),
            // SETTLED desk-side first-party (Gauntlet B9, 2026-09-02): the
            // stock t21-merge-20240926 topol (machines BHB68701/03/05,
            // byte-identical except name fields) states BM1368 with 108
            // ASICs per chain (12 domains x 9, interval 2, 12x9 placement
            // grid exactly populated), chain_num 3 — Phase A §3.9, pinned
            // as `t21_stock_topol::T21_CHIPS_PER_CHAIN`. Catalog datum
            // only: the native-serial resolver still REFUSES t21 (BM1368
            // is a definitive-NoPic-family chip id while the T21 stock
            // record labels per-chain PIC1704 MCUs — a controller
            // contradiction flagged for DCENT_EE), so pic_type_hint stays
            // None and dispatch stays fail-closed.
            chips_per_chain_hint: Some(108),
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Planned,
        },
        // Geometry (Lane J, 2026-09-01): chips_per_chain_hint=65 is per-board;
        // the full SKU is 3 chains x 65 = 195. Two independent held sources agree:
        // bosminer `model-list.json` (A3HB70601/70602 -> BM1370, num_domains 13,
        // num_per_hb 65, num_per_domain 5; SHA-256 c79f56e2...) and the ePIC jig
        // hashboard DB (A3HB706xx chain_num=3, chain_asic_num=65). Daemon SSOT
        // `dcentrald-silicon-profiles/src/bm1370.rs` pins 3x65=195.
        //
        // Exact Pro/XP production models independently select the retained
        // AML PSU voltage-controller backend (R14, 2026-09-07). Factory
        // PIC presence remains distinct from this NoPic software ownership.
        "s21pro" => ModelSpec {
            model_key: "s21pro",
            family_key: "bm1370",
            chip_label: "BM1370",
            chip_id: Some(0x1370),
            chips_per_chain_hint: Some(65),
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            support_tier: SupportTier::Experimental,
        },
        // Antminer S21+ is a distinct BM1370 platform, not an S21 Pro alias.
        //
        // Exact held evidence:
        //
        //   03-bosminer/model-list.json` (16,854 bytes, SHA-256
        //   c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0)
        //   records S21+ / A3HB70701 as BM1370, 11 domains x 5 = 55 chips,
        //   while S21 Pro / A3HB70601,A3HB70602 is 13 x 5 = 65 chips.
        // This row is identity/geometry only. Its exact amlogic-s21plus
        // BoardDesc has no executable carrier contract, so dispatch refuses
        // it and the tier must not claim runtime support.
        "s21+" | "s21plus" | "antminers21+" | "antminers21plus" => ModelSpec {
            model_key: "s21plus",
            family_key: "bm1370",
            chip_label: "BM1370",
            chip_id: Some(0x1370),
            chips_per_chain_hint: Some(55),
            // Held vendor corpora conflict on controller/PSU/PIC routing for
            // A3HB707xx. Preserve only the closed silicon/geometry facts.
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::EvidenceOnly,
        },
        "s21xp" => ModelSpec {
            model_key: "s21xp",
            family_key: "bm1370",
            chip_label: "BM1370",
            chip_id: Some(0x1370),
            // Exact held
            // 2026-04-29/03-bosminer/model-list.json` (16,854 bytes, SHA-256
            // c79f56e2d2a3f1e593b21d8a79a5364b2997e76f09b2ee9167fac64d1bf7dfe0):
            // A3HB70501, 13 domains x 7 chips = 91 chips on one hashboard.
            // The former 230 value was an explicitly approximate support-
            // matrix scaffold and is refuted by both this roster and the
            // in-tree hashboard catalog.
            chips_per_chain_hint: Some(91),
            // The exact production model selects PsuAsVoltageController on
            // the AML key3 backend (R14, 2026-09-07). NoPic denotes this
            // software owner; physical factory PIC silicon remains recorded.
            pic_type_hint: Some(ModelPicTypeHint::NoPic),
            pic_addrs_hint: Some(&[]),
            support_tier: SupportTier::Experimental,
        },
        // S21 XP Immersion is a distinct product identity even though it uses
        // the same BM1370 13x7 hashboard geometry as S21 XP air. Exact held
        // evidence associates it with M1HB70602. Held stock package
        // `FR-1.38(251031-S21XP-Imm).bmu` is 16,749,568 bytes, SHA-256
        // 861bb50fab4e36c81c0fe4d3fdea671da5d2653604cf61a170b5e444f3d552a0,
        // but remains a root-unauthenticated opaque code-9 package. No exact
        // carrier/PIC/PSU tuple is admitted, so this row stays management-only.
        "s21xpimm" | "s21xpimmersion" | "antminers21xpimm" | "antminers21xpimmersion" => {
            ModelSpec {
                model_key: "s21xpimm",
                family_key: "bm1370",
                chip_label: "BM1370",
                chip_id: Some(0x1370),
                chips_per_chain_hint: Some(91),
                pic_type_hint: None,
                pic_addrs_hint: None,
                support_tier: SupportTier::EvidenceOnly,
            }
        }
        "t23" | "s23" => ModelSpec {
            model_key: "s23",
            family_key: "bm13xx-next",
            chip_label: "BM13??",
            chip_id: None,
            chips_per_chain_hint: None,
            pic_type_hint: None,
            pic_addrs_hint: None,
            support_tier: SupportTier::Blind,
        },
        _ => return None,
    };

    Some(spec)
}

pub fn model_chip_id(model: &str) -> Option<u16> {
    lookup_model(model).and_then(|spec| spec.chip_id)
}

pub fn model_family_key(model: &str) -> Option<&'static str> {
    lookup_model(model).map(|spec| spec.family_key)
}

pub fn model_key(model: &str) -> Option<&'static str> {
    lookup_model(model).map(|spec| spec.model_key)
}

pub fn model_chip_label(model: &str) -> Option<&'static str> {
    lookup_model(model).map(|spec| spec.chip_label)
}

/// Reconcile the ASIC chip label (e.g. `"BM1387"`) from a known
/// `/etc/dcentos/board_target` marker.
///
/// P1-1 (D-12): once the control board / board family is identified — either
/// from the baked `/etc/dcentos/board_target` overlay file or post-enumeration
/// — the ASIC silicon is no longer ambiguous. An `am1-s9` board is BM1387, an
/// `am2-s19pro` is BM1398, an `am3-s21` is BM1368, etc. Callers use this to
/// replace a placeholder `"Auto-detect"` `chip_type` with the real chip on the
/// REST / CGMiner / Prometheus surfaces, so fleet tools (pyasic / asic-rs /
/// Foreman) can classify the unit instead of seeing `"Antminer (Auto-detect)"`.
///
/// The accepted markers are the exact strings the Buildroot post-build hooks
/// write to `/etc/dcentos/board_target` (plus a few pyasic-friendly spelling
/// aliases). Returns `None` for any marker that does NOT pin a single chip
/// family — a bare `am2` / `am3-aml` / `am3-bb` with no model suffix,
/// `unknown`, or empty. Truth-contract: never fabricate a chip on an
/// unidentified board; the caller keeps its honest `"Auto-detect"` fallback in
/// that case.
pub fn board_target_chip_label(board_target: &str) -> Option<&'static str> {
    // `normalize_model_token` lower-cases and strips non-alphanumeric bytes
    // (keeping '+'), so e.g. "am1-s9" → "am1s9", "am3-s19jpro-aml" →
    // "am3s19jproaml".
    let marker = normalize_model_token(board_target);
    let label = match marker.as_str() {
        // am1 — Zynq S9 (BM1387).
        "am1s9" | "am1s9i" | "am1s9j" => "BM1387",
        // The registered Hydro row proves BM1387 lineage only. It has no
        // complete-miner ModelSpec and remains management-only.
        "am1s9hydro" => "BM1387",
        // am1 — Zynq S9 SE / S9k (BM1393), whose native C43 owner admits the
        // exact carrier and independently observed ASIC identity.
        "am1s9se" | "am1s9k" => "BM1393",
        // am1 — Zynq S15 (BM1391, 7nm). Exact native target (see skus.conf
        // `am1-s15`, chip_id 0x1391); the chip LABEL resolves here for
        // detection/identity so an S15 board_target is not mislabeled
        // "Auto-detect"; the native owner binds the exact carrier. Mirrors
        // lookup_model("s15") = BM1391 (the other resolution path).
        "am1s15" | "am1t15" | "s15" | "t15" => "BM1391",
        // am2 — Zynq X17/X19 control boards. The bare "am2" family is shared
        // by BM1398 (S19/S19 Pro) and BM1362 (S19j Pro), so only the
        // model-suffixed board_target pins the chip.
        "am2s19pro" | "am2s19" | "am2s19a" | "am2s19plus" | "am2t19" | "x19t19" => "BM1398",
        "am2s19j" | "am2s19jpro" | "am2s19jprozynq" | "am2s19jproxil25" | "am2xil25" => "BM1362",
        "am2s19xp" => "BM1366",
        "am2s17" | "am2s17p" | "am2s17pro" | "am2t17" => "BM1397",
        // Operator-confirmed 2026-08-03 and corrected repo-wide in `1eae28615`:
        // the '+' variants are BM1397; only the 'e' variants are BM1396. These two
        // rows were reversed, and `skus.conf` was corrected without them, which is
        // what `live_skus_conf_agrees_with_board_target_chip_label_for_every_target`
        // caught. These are identity labels; exact S17e/T17e native admission
        // remains separate from generic serial-chip registration.
        "am2s17plus" | "am2t17plus" => "BM1397",
        "am2s17e" | "am2t17e" | "x17s17edspicplanned" | "x17t17epic16planned" => "BM1396",
        // am3-aml — Amlogic A113D. Disambiguated by the model suffix.
        "am3s21" | "am3t21" => "BM1368",
        "am3s21pro" | "am3s21xp" => "BM1370",
        // Exact evidence-only registry identity; no Pro/XP carrier alias or
        // callable runtime is implied by this display label.
        "amlogics21plus" => "BM1370",
        "am3s19k" | "am3s19kpro" | "am3s19xp" | "am3s19jxp" => "BM1366",
        "am3s19jproplus" | "am3s19jproa" => "BM1362",
        "am3s19jproaml" => "BM1362",
        // am3-bb — BeagleBone S19j Pro (BM1362).
        "am3bbs19jpro" => "BM1362",
        // cv1835 — Cvitek S19j Pro / S19 XP / T19 carriers.
        "cv1835s19jpro" => "BM1362",
        "cv1835s19xp" | "cv183xs19xp" => "BM1366",
        "cv1835t19" | "cv183xt19" => "BM1398",
        _ => return None,
    };
    Some(label)
}

// NOTE: `model_pic_type_hint` is defined below at line ~601 — it consults
// the RuntimeProfile path (covers X17S17 → DsPic etc) AND falls through to
// the lookup_model spec.pic_type_hint we added in Phase A.2. That single
// implementation handles both old runtime-profile-based models and the
// new spec-based BM136x family (S19K Pro NoPic, S21, etc.).

pub fn model_runtime_profile(model: &str) -> Option<RuntimeProfile> {
    let normalized = normalize_model_token(model);

    match normalized.as_str() {
        "s17" => Some(RuntimeProfile::X17S17),
        "t17" => Some(RuntimeProfile::X17T17),
        "s17+" | "s17plus" => Some(RuntimeProfile::X17S17Plus),
        "t17+" | "t17plus" => Some(RuntimeProfile::X17T17Plus),
        "s17e" => Some(RuntimeProfile::X17S17e),
        "t17e" => Some(RuntimeProfile::X17T17e),
        _ => None,
    }
}

pub fn model_chip_count_hint(model: &str) -> Option<u8> {
    model_runtime_profile(model)
        .and_then(RuntimeProfile::chips_per_chain)
        .or_else(|| lookup_model(model).and_then(|spec| spec.chips_per_chain_hint))
}

pub fn model_pic_type_hint(model: &str) -> Option<ModelPicTypeHint> {
    model_runtime_profile(model)
        .map(RuntimeProfile::pic_type_hint)
        .or_else(|| lookup_model(model).and_then(|spec| spec.pic_type_hint))
}

pub fn model_pic_addrs_hint(model: &str) -> Option<&'static [u8]> {
    model_runtime_profile(model)
        .and_then(RuntimeProfile::pic_addrs_hint)
        .or_else(|| lookup_model(model).and_then(|spec| spec.pic_addrs_hint))
}

#[cfg(test)]
mod tests {
    use super::{
        board_target_chip_label, detect_model_from_platform, lookup_extended_spec, lookup_model,
        model_chip_count_hint, model_chip_id, model_chip_label, model_family_key, model_key,
        model_pic_addrs_hint, model_pic_type_hint, model_runtime_profile,
        Model, ModelPicTypeHint,
        RuntimeProfile, SupportTier,
    };

    #[test]
    fn s9i_s9j_use_exact_bm1387_pic16_beta_profiles() {
        for (model, target, label) in [
            ("s9i", "am1-s9i", "Antminer S9i"),
            ("s9j", "am1-s9j", "Antminer S9j"),
        ] {
            for alias in [model, label] {
                let spec = lookup_model(alias).unwrap();
                assert_eq!(spec.model_key, model);
                assert_eq!(spec.chip_id, Some(0x1387));
                assert_eq!(spec.chips_per_chain_hint, Some(63));
                assert_eq!(spec.pic_type_hint, Some(ModelPicTypeHint::Pic16));
                assert_eq!(spec.pic_addrs_hint, Some(&[0x55, 0x56, 0x57][..]));
                assert_eq!(spec.support_tier, SupportTier::Experimental);

            }
            assert_eq!(board_target_chip_label(target), Some("BM1387"));

        }
        assert_eq!(
            lookup_model("s9").unwrap().support_tier,
            SupportTier::Validated
        );

        assert_eq!(model_chip_id("s9se"), Some(0x1393));
        assert_eq!(model_chip_id("s9k"), Some(0x1393));
    }

    #[test]
    fn s9i_s9j_baked_beta_configs_validate_after_pool_and_start() {
        for source in [
            include_str!("../../configs/beta/am1-s9i-baked-default.toml"),
            include_str!("../../configs/beta/am1-s9j-baked-default.toml"),
            include_str!("../../configs/beta/am1-s9se-baked-default.toml"),
            include_str!("../../configs/beta/am1-s9k-baked-default.toml"),
        ] {
            let mut config: crate::config::DcentraldConfig = toml::from_str(source).unwrap();
            assert!(!config.mining.enabled);
            assert!(!config.has_configured_pool());
            config.validate().expect("initial idle image");
            config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
            config.pool.worker = "beta-test".into();
            config.mining.enabled = true;
            config.validate().expect("pool and Start require no acknowledgment file");
            assert!(config.mining_start_enabled());
        }
    }

    #[test]
    fn bm1366_xp_baked_configs_reach_pool_start_with_exact_native_model() {
        for (target, model, source) in [
            ("am3-s19xp", "s19xp", include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19xp/rootfs-overlay/etc/dcentrald.toml")),
            ("am3-s19jxp", "s19jxp", include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19jxp/rootfs-overlay/etc/dcentrald.toml")),
        ] {
            let mut config: crate::config::DcentraldConfig = toml::from_str(source).unwrap();
            assert!(!config.mining.enabled);
            assert!(!config.has_configured_pool());
            config.validate().expect("initial idle XP image");
            assert_eq!(config.mining.serial_chip_count, Some(110));
            assert!(!config.mining.passthrough);
            assert!(config.watchdog.enabled);
            assert_eq!(config.thermal.fan_max_pwm, 30);

            let spec = lookup_model(model).unwrap();
            assert_eq!(spec.support_tier, SupportTier::Experimental);
            assert_eq!(spec.pic_type_hint, Some(ModelPicTypeHint::NoPic));
            assert_eq!(spec.pic_addrs_hint, Some(&[][..]));
            config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
            config.pool.worker = "beta-test".into();
            config.mining.enabled = true;
            config.validate().expect("ordinary XP pool + Start");
            assert!(config.mining_start_enabled());
        }
        for target in ["am2-s19xp", "cv1835-s19xp", "cv1835-s19jxp"] {

        }
    }

    /// S19j classic vs S19j Pro (corrected 2026-09-02, Gauntlet B5b): both
    /// are BM1362 — Bitmain's own stock topology DB pins the classic's
    /// BHB42701 at `asic_addr "0x1362"` (refuting the old 0x1398
    /// identity-only claim). The two SKUs stay distinguished by per-chain
    /// geometry (classic 108 vs Pro 126), never by chip id.
    #[test]
    fn distinguishes_s19j_from_s19j_pro() {
        assert_eq!(model_chip_id("s19j"), Some(0x1362));
        assert_eq!(model_chip_id("s19jpro"), Some(0x1362));
        assert_eq!(model_chip_count_hint("s19j"), Some(108));
        assert_eq!(model_chip_count_hint("s19jpro"), Some(126));
        // The refuted attribution must not silently return.
        assert_ne!(model_chip_id("s19j"), Some(0x1398));
        assert_eq!(model_family_key("s19j"), Some("bm1362"));
    }

    /// P1-1 (D-12): the S9 `.100` audit found `chip_type` surfacing as
    /// "Auto-detect" (and CGMiner `Type` as "Antminer (Auto-detect)") even
    /// though the board was already identified as `am1-s9`. Once the board is
    /// known the ASIC is pinned, so `board_target_chip_label` must reconcile
    /// the real chip from `/etc/dcentos/board_target` — and downstream the
    /// chip label must resolve to a real model name, NOT "Auto-detect".
    #[test]
    fn board_target_reconciles_chip_label_so_auto_detect_never_surfaces() {
        use super::board_target_chip_label;
        use dcentrald_asic::drivers::MinerProfile;

        // The exact bug: am1-s9 must yield BM1387 / "Antminer S9".
        assert_eq!(board_target_chip_label("am1-s9"), Some("BM1387"));
        // am1-s15: skus.conf declares it BM1391 and lookup_model("s15") agrees;
        // the board_target path was MISSING it (returned None -> "Auto-detect"),
        // unlike every other target SKU. Cross-source pin so it stays resolved.
        assert_eq!(board_target_chip_label("am1-s15"), Some("BM1391"));
        let s9 = MinerProfile::for_chip(0x1387).expect("S9 profile registered");
        assert_eq!(
            s9.name, "Antminer S9",
            "am1-s9 → BM1387 → 'Antminer S9' (never 'Auto-detect')"
        );

        // Every other identified board_target also pins its silicon — these
        // are the exact strings the Buildroot post-build hooks write to
        // /etc/dcentos/board_target.
        assert_eq!(board_target_chip_label("am2-s19pro"), Some("BM1398"));
        assert_eq!(board_target_chip_label("am2-s19j"), Some("BM1362"));
        assert_eq!(board_target_chip_label("am2-s19jpro-zynq"), Some("BM1362"));
        assert_eq!(
            board_target_chip_label("am2-s19jpro-xil"),
            Some("BM1362")
        );
        assert_eq!(board_target_chip_label("am1-t15"), Some("BM1391"));
        assert_eq!(board_target_chip_label("am2-s17p"), Some("BM1397"));
        // '+' = BM1397, 'e' = BM1396 (operator-confirmed; see the match arm).
        assert_eq!(board_target_chip_label("am2-s17plus"), Some("BM1397"));
        assert_eq!(board_target_chip_label("am2-t17"), Some("BM1397"));
        assert_eq!(board_target_chip_label("am2-t17plus"), Some("BM1397"));
        assert_eq!(
            board_target_chip_label("x17-s17e-dspic-planned"),
            Some("BM1396")
        );
        assert_eq!(
            board_target_chip_label("x17-t17e-pic16-planned"),
            Some("BM1396")
        );
        assert_eq!(board_target_chip_label("am3-s21"), Some("BM1368"));
        assert_eq!(board_target_chip_label("am3-t21"), Some("BM1368"));
        assert_eq!(board_target_chip_label("am3-s21pro"), Some("BM1370"));
        assert_eq!(board_target_chip_label("am3-s21xp"), Some("BM1370"));
        assert_eq!(board_target_chip_label("am3-s19k"), Some("BM1366"));
        assert_eq!(board_target_chip_label("am3-s19xp"), Some("BM1366"));
        assert_eq!(board_target_chip_label("am3-s19jxp"), Some("BM1366"));
        assert_eq!(board_target_chip_label("am3-s19jproplus"), Some("BM1362"));
        assert_eq!(board_target_chip_label("am3-s19jpro-aml"), Some("BM1362"));
        assert_eq!(board_target_chip_label("am3-bb-s19jpro"), Some("BM1362"));
        assert_eq!(board_target_chip_label("cv1835-s19jpro"), Some("BM1362"));
        assert_eq!(board_target_chip_label("cv1835-s19xp"), Some("BM1366"));
        assert_eq!(board_target_chip_label("cv1835-t19"), Some("BM1398"));

        // Each reconciled chip label resolves to a real Antminer model name.
        for (label, chip_id, model) in [
            ("BM1398", 0x1398u16, "Antminer S19 Pro"),
            ("BM1362", 0x1362, "Antminer S19j Pro"),
            ("BM1368", 0x1368, "Antminer S21"),
        ] {
            let p = MinerProfile::for_chip(chip_id)
                .unwrap_or_else(|| panic!("{label} profile registered"));
            assert_eq!(p.name, model);
        }

        // Ambiguous / unidentified markers must NOT fabricate a chip — the
        // caller keeps its honest "Auto-detect" fallback (truth-contract).
        assert_eq!(board_target_chip_label("am3-aml"), None);
        assert_eq!(board_target_chip_label("am2"), None);
        assert_eq!(board_target_chip_label("am3-bb"), None);
        assert_eq!(board_target_chip_label("unknown"), None);
        assert_eq!(board_target_chip_label(""), None);
    }

    #[test]
    fn normalizes_requested_safe_aliases() {
        assert_eq!(model_chip_id("T9+"), Some(0x1387));
        assert_eq!(model_chip_id("s21_plus"), Some(0x1370));
        assert_eq!(model_family_key("S19_Pro"), Some("bm1398"));
        assert_eq!(model_key("s19k_pro"), Some("s19k"));
        assert_eq!(model_key("T9+"), Some("t9+"));
        assert_eq!(model_key("S9_plus"), Some("s9+"));
        assert_eq!(model_chip_count_hint("s9"), Some(63));
        assert_eq!(model_chip_count_hint("s9+"), Some(84));
        assert_eq!(model_chip_count_hint("t9"), Some(57));
        assert_eq!(model_chip_count_hint("t9+"), Some(18));
        assert_eq!(model_chip_count_hint("t17+"), Some(44));
        assert_eq!(model_chip_count_hint("s17+"), Some(65));
        assert_eq!(model_chip_count_hint("s21xp"), Some(91));
        assert_eq!(model_pic_type_hint("t17"), Some(ModelPicTypeHint::Pic16));
        assert_eq!(model_pic_type_hint("s17"), Some(ModelPicTypeHint::DsPic));
        assert_eq!(
            model_pic_addrs_hint("t17+").expect("x17 pic addrs")[0],
            0x50
        );
        assert_eq!(
            model_runtime_profile("S17+"),
            Some(RuntimeProfile::X17S17Plus)
        );
        assert_eq!(
            model_runtime_profile("t17e").expect("t17e profile").key(),
            "x17-t17e-pic16-planned"
        );
    }

    /// S7 is identity-only, from Bitmain's AMTC jig configs.
    ///
    /// The `None` chip-count is the load-bearing assertion, not an oversight:
    /// `Config.ini-S7-45` and `Config.ini-S7-54` describe two different S7
    /// boards (`AsicNum` 45 vs 54) and nothing in the held corpus says which a
    /// given unit carries. Pinning either would fabricate enumeration geometry.
    /// Mutation-check: setting `chips_per_chain_hint: Some(45)` fails here.
    #[test]
    fn s7_is_identity_only_and_never_declares_a_chip_count() {
        assert_eq!(model_key("S7"), Some("s7"));
        assert_eq!(model_chip_id("S7"), Some(0x1385));
        assert_eq!(model_family_key("s7"), Some("bm1385"));
        assert_eq!(
            model_chip_count_hint("s7"),
            None,
            "jig ships S7 at BOTH 45 and 54 chips; declaring one fabricates geometry"
        );

        // The chip label is the whole point of the row: an S7 stops resolving
        // to nothing and reports its jig-evidenced silicon instead.
        assert_eq!(model_chip_label("S7"), Some("BM1385"));

        // Identity must not leak into geometry or controller assumptions.
        assert_eq!(model_pic_type_hint("s7"), None);
        assert_eq!(model_pic_addrs_hint("s7"), None);
    }

    /// S9++ is identity-only too, but — unlike S7 — its chip count IS declared.
    ///
    /// The contrast is the point: the AMTC symbol
    /// `set_Voltage_S9_plus_plus_BM1387_54` encodes exactly one count, whereas
    /// the S7 configs ship two. Evidence quality, not convenience, decides
    /// whether a geometry field may be filled in.
    #[test]
    fn s9pp_declares_its_jig_symbol_chip_count_unlike_s7() {
        assert_eq!(model_key("S9++"), Some("s9++"));
        assert_eq!(model_key("s9plusplus"), Some("s9++"));
        assert_eq!(model_chip_id("S9++"), Some(0x1387));
        assert_eq!(model_chip_label("S9++"), Some("BM1387"));
        assert_eq!(
            model_chip_count_hint("s9++"),
            Some(54),
            "set_Voltage_S9_plus_plus_BM1387_54 names exactly one count"
        );

        // S9++ must not be confused with S9+ (84) or S9 (63).
        assert_ne!(model_chip_count_hint("s9++"), model_chip_count_hint("s9+"));
        assert_ne!(model_chip_count_hint("s9++"), model_chip_count_hint("s9"));

        // The evidence-quality contrast with S7 is itself load-bearing.
        assert!(
            model_chip_count_hint("s7").is_none() && model_chip_count_hint("s9++").is_some(),
            "one jig source names a single count, the other names two"
        );
    }

    /// S9k is the first BM1393 model — identity-only, from the held S9k jig.
    /// Its 60-chip count is triple-byte-stated in that jig, so it IS declared;
    /// its chip is the first `bm1393` family entry among the model rows.
    #[test]
    fn s9k_is_registered_as_bm1393_with_the_jig_stated_60_chips() {
        assert_eq!(model_key("S9k"), Some("s9k"));
        assert_eq!(model_chip_id("s9k"), Some(0x1393));
        assert_eq!(model_chip_label("S9k"), Some("BM1393"));
        assert_eq!(model_family_key("s9k"), Some("bm1393"));
        assert_eq!(
            model_chip_count_hint("s9k"),
            Some(60),
            "soc_config.asic_num=60 + two ==60 validators in the S9k jig"
        );

        // S9k is NOT any of the BM1387 S9-family SKUs — distinct silicon.
        assert_ne!(model_chip_id("s9k"), model_chip_id("s9"));
        assert_ne!(model_chip_label("s9k"), model_chip_label("s9"));

        // Identity must not leak into a controller or install claim.
        assert_eq!(model_pic_type_hint("s9k"), None);
        assert_eq!(model_pic_addrs_hint("s9k"), None);
    }

    #[test]
    fn model_spec_chip_ids_match_skus_conf_for_all_target_skus_with_model_specs() {
        // Cross-source pin: the daemon's ModelSpec chip_id (which drives
        // registry.detect() -> driver dispatch) MUST match skus.conf (the
        // acceptance-harness source of truth) for every confirmed target, or a
        // board would dispatch to the wrong driver at first-light. Both exact
        // BM1396 native rows retain their independent live carrier admission.
        let id = |key: &str| lookup_model(key).expect("model spec").chip_id;
        assert_eq!(id("s9"), Some(0x1387)); // skus.conf am1-s9
        assert_eq!(id("t15"), Some(0x1391)); // exact retained T15 native route
        assert_eq!(id("s17"), Some(0x1397)); // am2-s17p
        assert_eq!(id("s17pro"), Some(0x1397)); // am2-s17p
                                                // RECONCILED 2026-08-03 by operator decision: skus.conf,
                                                // `board_target_chip_label`, `asic_protocol` and this `chip_id` all now
                                                // say S17+/T17+ = BM1397. There is no remaining carve-out on this axis.
        assert_eq!(id("s17+"), Some(0x1397)); // am2-s17plus
        assert_eq!(id("t17"), Some(0x1397)); // am2-t17
        assert_eq!(id("t17+"), Some(0x1397)); // am2-t17plus
        assert_eq!(id("s17e"), Some(0x1396)); // exact native S17e factory identity
        assert_eq!(id("t17e"), Some(0x1396)); // exact native T17e identity
        assert_eq!(id("s19"), Some(0x1398)); // am2-s19
        assert_eq!(id("s19pro"), Some(0x1398)); // am2-s19pro
        assert_eq!(id("s19jpro"), Some(0x1362)); // am2-s19jpro-zynq
        assert_eq!(id("s19kpro"), Some(0x1366)); // am3-s19k
        assert_eq!(id("t19"), Some(0x1398)); // am2-t19
        assert_eq!(id("s19xp"), Some(0x1366)); // am3-s19xp
        assert_eq!(id("s19jxp"), Some(0x1366)); // am3-s19jxp
        assert_eq!(id("s19jproplus"), Some(0x1362)); // am3-s19jproplus
        assert_eq!(id("s21"), Some(0x1368)); // am3-s21
        assert_eq!(id("t21"), Some(0x1368)); // am3-t21
        assert_eq!(id("s21pro"), Some(0x1370)); // am3-s21pro
        assert_eq!(id("s21xp"), Some(0x1370)); // am3-s21xp dedicated BM1370 geometry
        assert_eq!(id("s15"), Some(0x1391));
        assert_eq!(lookup_model("s15").expect("s15 spec").chip_label, "BM1391");
        assert_eq!(lookup_model("t15").expect("t15 spec").chip_label, "BM1391");
        assert_eq!(
            lookup_model("s17e").expect("s17e spec").chip_label,
            "BM1396"
        );
        assert_eq!(
            lookup_model("t17e").expect("t17e spec").chip_label,
            "BM1396"
        );
    }

    #[test]
    fn bm1397_s17plus_t17plus_recognize_experimental_driver_and_promoted_models() {
        use dcentrald_asic::drivers::{ChipDriverMaturity, ChipRegistry};

        for model in ["s17+", "s17plus", "t17+", "t17plus"] {
            let spec = lookup_model(model).expect("BM1397 plus-family model");
            assert_eq!(spec.chip_label, "BM1397");
            assert_eq!(spec.chip_id, Some(0x1397));
            // 2026-08-27 unlock-armada (C1 convergence): the four BM1397
            // 17-series rows are promoted to the desk-validated s17-hybrid
            // lane and their acceptance rows claim EXPERIMENTAL, so the
            // complete-model tier follows. Live energize stays bench-gated.
            assert_eq!(spec.support_tier, SupportTier::Experimental);
        }

        // Same silicon as S17/S17 Pro/T17, DIFFERENT geometry. Promoting the chip
        // family must never drag S17's 48 chips/chain onto the '+' variants --
        // that is exactly the confusion the vendor catalog header caused.
        assert_eq!(model_chip_count_hint("s17+"), Some(65));
        assert_eq!(model_chip_count_hint("t17+"), Some(44));
        assert_ne!(model_chip_count_hint("s17+"), model_chip_count_hint("s17"));
        assert_eq!(model_pic_type_hint("s17+"), Some(ModelPicTypeHint::Pic16));
        assert_eq!(model_pic_type_hint("t17+"), Some(ModelPicTypeHint::Pic16));

        // Model support and chip-driver maturity are orthogonal. 0x1397 is a
        // recognized Experimental driver identity; production dispatch still
        // requires its own opt-in regardless of the promoted model tier.
        let production = ChipRegistry::production();
        let recognition = production
            .recognize(0x1397)
            .expect("S17+/T17+ must reach the recognized BM1397 identity");
        assert_eq!(recognition.chip_name(), "BM1397");
        assert_eq!(recognition.maturity(), ChipDriverMaturity::Experimental);
        assert!(
            production.detect(0x1397).is_none(),
            "Experimental maturity must still gate production dispatch"
        );
        assert!(
            ChipRegistry::with_experimental_driver(0x1397)
                .detect(0x1397)
                .is_some(),
            "explicit Experimental opt-in must reach the BM1397 driver"
        );
        assert!(
            production.recognize(0x1396).is_none(),
            "BM1396 (S17e/T17e) remains entirely unregistered"
        );
    }

    #[test]
    fn live_skus_conf_agrees_with_board_target_chip_label_for_every_target() {
        // Authoritative cross-source gate: read the LIVE skus.conf (the
        // acceptance-harness source of truth) and verify the daemon's
        // board_target_chip_label resolves each board_target to the SAME chip.
        // Unlike the hardcoded pins above, this catches a divergence introduced on
        // EITHER side (a skus.conf edit OR a model.rs edit) — the exact class of the
        // am1-s15 gap. skus.conf columns: SKU|board_target|arch|chip|chip_id|...
        use super::board_target_chip_label;
        let skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        let mut checked = 0;
        for line in skus.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('|').collect();
            assert!(cols.len() >= 5, "malformed skus.conf line: {line}");
            let board_target = cols[1].trim();
            let chip = cols[3].trim();
            assert_eq!(
                board_target_chip_label(board_target),
                Some(chip),
                "skus.conf declares {board_target} = {chip}, but board_target_chip_label disagrees"
            );
            checked += 1;
        }
        assert_eq!(
            checked, 30,
            "skus.conf must list exactly the 30 target SKUs; cross-checked {checked}"
        );
    }

    /// Model support tiers and acceptance release labels must make the same
    /// callable-runtime claim. Driver recognition, firmware evidence, and a
    /// build artifact do not promote a complete miner model to Experimental.
    #[test]
    fn model_support_tiers_match_acceptance_callable_runtime_claims() {
        let skus = include_str!("../../../scripts/hw-acceptance/skus.conf");
        let mut checked = 0;
        let mut without_model_spec = Vec::new();
        for line in skus.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('|').collect();
            assert_eq!(cols.len(), 11, "malformed skus.conf line: {line}");
            let Some(spec) = lookup_model(cols[0]) else {
                if cols[0] == "S9Hydro" {
                    assert_eq!((cols[4], cols[5], cols[8]), ("0", "0", "NOT-IMPLEMENTED"));
                    let board = dcentrald_common::BoardDesc::lookup(cols[1]).unwrap();
                    assert_eq!(board.release_channel, dcentrald_common::ReleaseChannel::Unsupported);
                    assert_eq!(board.work_engine, dcentrald_common::WorkEngineKind::ManagementOnly);
                }
                without_model_spec.push(cols[0]);
                continue;
            };
            assert_eq!(
                spec.chip_label, cols[3],
                "{} ModelSpec ASIC {} contradicts skus.conf ASIC {}",
                cols[0], spec.chip_label, cols[3]
            );
            let release_claims_callable = matches!(cols[8], "PRODUCTION" | "EXPERIMENTAL");
            assert_eq!(
                spec.support_tier.claims_callable_runtime(),
                release_claims_callable,
                "{} support_tier={:?} contradicts skus.conf release_state={}",
                cols[0],
                spec.support_tier,
                cols[8]
            );
            checked += 1;
        }
        // S9Hydro has identity lineage only and no callable miner model.
        // S19jProBB has no complete-miner ModelSpec (board lane only);
        // S19jProAML (2026-08-26 campaign) carries exact identity in
        // `board_target_chip_label` but no complete-miner ModelSpec yet.
        assert_eq!(without_model_spec, vec!["S9Hydro", "S19jProBB", "S19jProAML"]);
        assert_eq!(checked, 27, "model/acceptance support roster changed");
    }

    #[test]
    fn native_and_planned_families_keep_distinct_support_tiers() {
        for target in ["s9se", "s9k"] {
            let c43 = lookup_model(target).unwrap();
            assert_eq!(c43.chip_id, Some(0x1393));
            assert_eq!(c43.chips_per_chain_hint, Some(60));
            assert_eq!(c43.support_tier, SupportTier::Experimental);
            assert_eq!(
                board_target_chip_label(&format!("am1-{target}")),
                Some("BM1393")
            );
        }



        let s15 = lookup_model("s15").expect("s15 spec");
        assert_eq!(s15.chip_label, "BM1391");
        assert_eq!(s15.chip_id, Some(0x1391));
        assert_eq!(s15.chips_per_chain_hint, Some(72));
        assert_eq!(s15.pic_type_hint, None);
        assert_eq!(s15.support_tier, SupportTier::Experimental);
        let t15 = lookup_model("t15").expect("t15 spec");
        assert_eq!(t15.model_key, "t15");
        assert_eq!(t15.chips_per_chain_hint, Some(60));

        let t17e = lookup_model("t17e").expect("t17e spec");
        assert_eq!(t17e.model_key, "t17e");
        assert_eq!(t17e.chip_label, "BM1396");
        assert_eq!(t17e.chip_id, Some(0x1396));
        assert_eq!(t17e.chips_per_chain_hint, Some(78));
        assert_eq!(t17e.pic_type_hint, None);
        assert_eq!(t17e.pic_addrs_hint, None);
        assert_eq!(t17e.support_tier, SupportTier::Experimental);

        let s17e = lookup_model("s17e").unwrap();
        assert_eq!(s17e.support_tier, SupportTier::Experimental);
        assert_eq!(s17e.chips_per_chain_hint, Some(135));
        assert_eq!(s17e.pic_type_hint, None);
        assert_eq!(s17e.pic_addrs_hint, None);

        let t21 = lookup_model("t21").expect("t21 spec");
        assert_eq!(t21.chip_label, "BM1368");
        // Stock-settled per-chain geometry (B9): t21-merge topol BHB68701 =
        // 108/chain. The hint is a catalog datum; pic hints stay None (the
        // controller contradiction is flagged, not adjudicated).
        assert_eq!(t21.chips_per_chain_hint, Some(108));
        assert_eq!(t21.pic_type_hint, None);
        assert_eq!(t21.pic_addrs_hint, None);
        assert_eq!(model_pic_type_hint("t21"), None);
        assert_eq!(model_pic_addrs_hint("t21"), None);
        assert_eq!(t21.support_tier, SupportTier::Planned);
    }

    #[test]
    fn s19jpro_plus_resolves_to_its_distinct_nopic_profile() {
        let base = lookup_model("s19jpro").expect("s19jpro spec");
        assert_eq!(base.model_key, "s19jpro");
        assert_eq!(base.chips_per_chain_hint, Some(126));
        assert_eq!(base.pic_type_hint, None);

        for alias in ["s19jpro+", "s19jproplus"] {
            let plus = lookup_model(alias).expect("s19jpro+ spec");
            assert_eq!(plus.model_key, "s19jproplus");
            assert_eq!(plus.chips_per_chain_hint, Some(120));
            assert_eq!(plus.pic_type_hint, Some(ModelPicTypeHint::NoPic));
            assert_eq!(plus.pic_addrs_hint, Some(&[][..]));
        }
    }

    #[test]
    fn bm1362_aml_a_and_plus_baked_configs_reach_pool_start_with_exact_geometry() {
        for (target, model, count, source) in [
            ("am3-s19jproa", "s19jproa", 126, include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19jproa/rootfs-overlay/etc/dcentrald.toml")),
            ("am3-s19jproplus", "s19jproplus", 120, include_str!("../../../br2_external_dcentos/board/amlogic/am3-s19jproplus/rootfs-overlay/etc/dcentrald.toml")),
        ] {
            let mut config: crate::config::DcentraldConfig = toml::from_str(source).unwrap();
            config.validate().expect("initial idle BM1362 AML image");
            assert!(!config.mining_start_enabled());
            assert!(!config.has_configured_pool());
            assert_eq!(config.mining.serial_chip_count, Some(count));
            assert_eq!(config.thermal.fan_max_pwm, 30);
            assert!(config.watchdog.enabled);


            let spec = lookup_model(model).unwrap();
            assert_eq!(spec.chips_per_chain_hint, Some(count as u8));
            assert_eq!(spec.pic_type_hint, Some(ModelPicTypeHint::NoPic));
            assert_eq!(spec.support_tier, SupportTier::Experimental);
            config.pool.url = "stratum+tcp://127.0.0.1:3333".into();
            config.pool.worker = "beta-test".into();
            config.mining.enabled = true;
            config.validate().expect("ordinary BM1362 AML pool + Start");
            assert!(config.mining_start_enabled());
        }
        assert_eq!(lookup_model("s19jpro").unwrap().pic_type_hint, None);
    }

    #[test]
    fn s19plus_is_an_exact_native_bm1398_profile_without_sibling_geometry() {
        let s19 = lookup_model("s19").expect("S19 spec");
        let pro = lookup_model("s19pro").expect("S19 Pro spec");
        let plus = lookup_model("s19plus").expect("S19+ spec");

        assert_eq!(s19.support_tier, SupportTier::Experimental);
        assert_eq!(pro.support_tier, SupportTier::Experimental);
        assert!(dcentrald_common::BoardDesc::am2_s19pro().release_channel.is_publishable());

        assert_eq!(plus.model_key, "s19plus");
        assert_eq!(plus.family_key, "bm1398");
        assert_eq!(plus.chip_label, "BM1398");
        assert_eq!(plus.chip_id, Some(0x1398));
        assert_eq!(plus.chips_per_chain_hint, Some(80));
        assert_eq!(plus.pic_type_hint, None);
        assert_eq!(plus.pic_addrs_hint, None);
        assert_eq!(plus.support_tier, SupportTier::Experimental);
        assert!(plus.support_tier.claims_callable_runtime());

        // The S19+ must never inherit the plain S19's 76-chip observation or
        // the S19 Pro's 114-chip geometry merely because all use BM1398.
        assert_ne!(plus.chips_per_chain_hint, s19.chips_per_chain_hint);
        assert_ne!(plus.chips_per_chain_hint, pro.chips_per_chain_hint);
        assert_eq!(board_target_chip_label("am2-s19plus"), Some("BM1398"));
        let row = dcentrald_common::BoardDesc::lookup("am2-s19plus").unwrap();
        assert_eq!(row.work_engine, dcentrald_common::WorkEngineKind::FpgaWorkFifo);
        assert!(!row.first_install_supported);
        assert!(!row.mining_default_enabled);

        for alias in ["s19+", "s19_plus", "s19plus", "Antminer S19+"] {
            assert_eq!(lookup_model(alias), Some(plus), "alias {alias}");

        }
    }


    #[test]
    fn s21plus_is_not_s21pro_and_stays_management_only() {
        let pro = lookup_model("s21pro").expect("S21 Pro spec");
        let plus = lookup_model("s21plus").expect("S21+ spec");

        assert_eq!(pro.model_key, "s21pro");
        assert_eq!(pro.chips_per_chain_hint, Some(65));
        assert_eq!(pro.support_tier, SupportTier::Experimental);

        assert_eq!(plus.model_key, "s21plus");
        assert_eq!(plus.family_key, "bm1370");
        assert_eq!(plus.chip_id, Some(0x1370));
        assert_eq!(plus.chips_per_chain_hint, Some(55));
        assert_eq!(plus.pic_type_hint, None);
        assert_eq!(plus.pic_addrs_hint, None);
        assert_eq!(plus.support_tier, SupportTier::EvidenceOnly);
        assert!(!plus.support_tier.claims_callable_runtime());
        assert_eq!(board_target_chip_label("amlogic-s21plus"), Some("BM1370"));
        assert_eq!(board_target_chip_label("am3-s21plus"), None);
        let board = dcentrald_common::BoardDesc::lookup("amlogic-s21plus").unwrap();
        assert_eq!(
            board.asic_protocol,
            dcentrald_common::AsicProtocolIdentity::Bm1370
        );
        assert_eq!(
            board.release_channel,
            dcentrald_common::ReleaseChannel::Unsupported
        );
        assert_eq!(
            board.work_engine,
            dcentrald_common::WorkEngineKind::ManagementOnly
        );
        assert!(!board.runtime_status.permits_mining_lane());
        assert!(dcentrald_common::BoardDesc::lookup("am3-s21plus").is_none());

        for alias in ["s21+", "s21_plus", "s21plus", "Antminer S21+"] {
            assert_eq!(lookup_model(alias), Some(plus), "alias {alias}");

        }
    }

    #[test]
    fn s21xp_and_immersion_use_exact_91_chip_hashboard_geometry() {
        let air = lookup_model("s21xp").expect("S21 XP spec");
        assert_eq!(air.model_key, "s21xp");
        assert_eq!(air.family_key, "bm1370");
        assert_eq!(air.chip_id, Some(0x1370));
        assert_eq!(air.chips_per_chain_hint, Some(91));
        assert_eq!(air.pic_type_hint, Some(ModelPicTypeHint::NoPic));
        assert_eq!(air.pic_addrs_hint, Some(&[][..]));
        assert_eq!(air.support_tier, SupportTier::Experimental);
        assert!(air.support_tier.claims_callable_runtime());


        let immersion = lookup_model("s21xpimm").expect("S21 XP Immersion spec");
        assert_eq!(immersion.model_key, "s21xpimm");
        assert_eq!(immersion.family_key, "bm1370");
        assert_eq!(immersion.chip_id, Some(0x1370));
        assert_eq!(immersion.chips_per_chain_hint, Some(91));
        assert_eq!(immersion.pic_type_hint, None);
        assert_eq!(immersion.pic_addrs_hint, None);
        assert_eq!(immersion.support_tier, SupportTier::EvidenceOnly);
        assert!(!immersion.support_tier.claims_callable_runtime());
        assert_eq!(board_target_chip_label("am3-s21xpimm"), None);

        for alias in [
            "s21xpimm",
            "s21_xp_immersion",
            "Antminer S21 XP Imm.",
            "Antminer S21 XP Immersion",
        ] {
            assert_eq!(lookup_model(alias), Some(immersion), "alias {alias}");

        }
    }
    #[test]
    fn public_first_install_support_remains_separate_from_channel() {
        for desc in dcentrald_common::BoardDesc::all_registered() {
            if !desc.public_beta_install() {
                continue;
            }

            assert!(
                dcentrald_common::BoardDesc::is_public_beta_install_target(desc.board_target),
                "{}",
                desc.board_target
            );
        }
        // Sanity: only S9 has a public first-install route. AM2 public-beta
        // authorization is scoped to self-update on an existing DCENT_OS image.
        let beta: Vec<_> = dcentrald_common::BoardDesc::all_registered()
            .iter()
            .filter(|d| d.public_beta_install())
            .map(|d| d.board_target)
            .collect();
        assert_eq!(beta, vec!["am1-s9"]);
    }
    /// BM1387/BM1393 S9 siblings, exact BM1391 S15/T15, four BM1397
    /// S17-family rows and NBP1901 S19 Pro.
    /// BM1398 admission before constructing each native hardware owner.


    #[test]
    fn exposes_future_family_as_blind() {
        let s23 = lookup_model("s23").expect("s23 spec");
        assert_eq!(s23.chip_label, "BM13??");
        assert_eq!(s23.chip_id, None);
        assert_eq!(s23.support_tier, SupportTier::Blind);
        assert_eq!(model_chip_label("t23"), Some("BM13??"));
    }

    #[test]
    fn s19jpro_am2_variant_registers_string_key_and_extended_spec() {
        // Enum variant → ModelSpec round-trip.
        let m = Model::S19jProAm2;
        assert_eq!(m.model_key(), "s19jproam2");
        assert_eq!(m.platform_key(), "zynq-bm3-am2");
        assert_eq!(m.board_family(), "am2");
        assert_eq!(m.board_target(), "am2-s19j");

        let spec = lookup_model("s19jproam2").expect("s19jproam2 ModelSpec registered");
        assert_eq!(spec.chip_id, Some(0x1362));
        assert_eq!(spec.chips_per_chain_hint, Some(126));
        assert_eq!(spec.pic_type_hint, Some(ModelPicTypeHint::DsPic));
        assert_eq!(
            spec.pic_addrs_hint.expect("am2 pic addrs"),
            &[0x20, 0x21, 0x22]
        );

        // Extended spec content sanity.
        let ext = m.extended_spec();
        assert_eq!(ext.chain_count, 3);
        assert_eq!(ext.chips_per_chain, 126);
        assert_eq!(ext.cores_per_chip, 4);
        assert_eq!(ext.rated_hashrate_th, 104);
        assert_eq!(ext.rated_power_w, 3068);
        assert_eq!(ext.default_voltage_mv, 13_700);
        assert_eq!(ext.voltage_min_mv, 11_960);
        assert_eq!(ext.voltage_max_mv, 15_200);
        assert_eq!(ext.mining_baud, 3_125_000);
        assert_eq!(ext.init_baud, 115_200);
        assert_eq!(ext.thermal.target_c, 60);
        assert_eq!(ext.thermal.dangerous_internal_c, 110);
        assert_eq!(ext.fan_count, 4);
        assert_eq!(ext.fan_pwm_cap_industrial, 80);
        assert_eq!(ext.pic_fw_byte_expected, 0x89);
        assert_eq!(ext.board_target, "am2-s19j");

        // String-keyed extended lookup returns the same constant.
        assert_eq!(lookup_extended_spec("s19jproam2"), Some(ext));
        assert_eq!(lookup_extended_spec("s19jproam2"), Some(m.extended_spec()));
    }

    #[test]
    fn detect_model_disambiguates_am2_by_chip_id() {
        // zynq-bm3-am2 is shared by S19 Pro (BM1398) and S19j Pro (BM1362).
        // Only the BM1362 pair maps to a concrete enum variant today.
        assert_eq!(
            detect_model_from_platform("zynq-bm3-am2", Some(0x1362)),
            Some(Model::S19jProAm2)
        );
        assert_eq!(
            detect_model_from_platform("zynq-bm3-am2", Some(0x1398)),
            None
        );
        assert_eq!(detect_model_from_platform("zynq-bm3-am2", None), None);
        assert_eq!(
            detect_model_from_platform("zynq-bm1-s9", Some(0x1387)),
            None
        );
        // Whitespace tolerated (bos_platform often includes a trailing newline).
        assert_eq!(
            detect_model_from_platform("  zynq-bm3-am2\n", Some(0x1362)),
            Some(Model::S19jProAm2)
        );
    }
}
