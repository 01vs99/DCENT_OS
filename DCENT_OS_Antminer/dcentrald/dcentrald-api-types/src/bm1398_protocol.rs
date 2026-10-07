//! Evidence-scoped BM1398 protocol contracts.
//!
//! Chip behavior, NBP1901/S19 Pro chain geometry, and FPGA FIFO layout are
//! separate types. The aggregate constant names the complete composition so
//! no caller can mistake one board's topology or transport for universal
//! BM1398 behavior.
//!
//! PLL search and field layout are independently witnessed by the local stock
//! NBP1901 `bmminer` (SHA-256
//! `e91e6d9fa7b8524abdb05ac5ca4b7118c6f50a58b6075541139c6f56c1b21d14`,
//! search VA `0x502c0`, encoder VA `0x4fa9c`) and BM1398 repair-jig binary (SHA-256
//! `ddb73ebe334908767360a1b9a15144daa751d45c7f22a4965788371957ff6317`,
//! search VA `0x29b48`, encoder VA `0x29558`).

use serde::Serialize;

use crate::asic_command::LinearAddressPlan;
use crate::asic_protocol_spec::{AsicResponseLengthSpec, RESPONSE_PREAMBLE_BYTES};
use crate::bm13xx_pll::{FourDividerPll, FourDividerPllSearchSpec};

/// Byte identity of the held stock NBP1901 miner used for this contract.
pub const NBP1901_STOCK_BMMINER_SHA256: &str =
    "e91e6d9fa7b8524abdb05ac5ca4b7118c6f50a58b6075541139c6f56c1b21d14";
/// Byte identity of the independently held BM1398 repair jig.
pub const BM1398_REPAIR_JIG_SHA256: &str =
    "ddb73ebe334908767360a1b9a15144daa751d45c7f22a4965788371957ff6317";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RegisterWrite {
    pub register: u8,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AddressedRegisterWrite {
    pub chip_address: u8,
    pub register: u8,
    pub value: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Bm1398ChipSpec {
    pub chip_id: u16,
    pub response: AsicResponseLengthSpec,
    pub pll_register: u8,
    pub core_register_control: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Bm1398PllSolution {
    pub dividers: FourDividerPll,
    pub register_value: u32,
}

/// Stock NBP1901 and BM1398 repair-jig search envelope. Both independent
/// binaries search refdiv 2 before 1, fbdiv 16..=250, postdivs 1..=7, VCO
/// 2000..=3200 MHz, and cap refdiv-1 VCO at 3125 MHz.
pub const BM1398_PLL_SEARCH_SPEC: FourDividerPllSearchSpec = FourDividerPllSearchSpec {
    reference_mhz: 25,
    refdiv_order: [2, 1],
    fbdiv_min: 16,
    fbdiv_max: 250,
    postdiv_min: 1,
    postdiv_max: 7,
    vco_min_mhz: 2_000,
    vco_max_mhz: 3_200,
    refdiv_one_vco_max_mhz: 3_125,
    max_error_millimhz_exclusive: 10_000,
};

/// Encode a BM1398 PLL0 word. FBDIV occupies bits `[27:16]`; post-divider
/// fields are raw values, not the minus-one encoding used by later families.
///
/// G19 pure SSOT: thin-wrap of `dcentrald_common::bm1398_pll_register_value`.
pub const fn bm1398_pll_register_value(params: FourDividerPll) -> u32 {
    dcentrald_common::bm1398_pll_register_value(dcentrald_common::Bm1398PllDividers {
        fb_div: params.fbdiv,
        ref_div: params.refdiv,
        post_div1: params.postdiv1,
        post_div2: params.postdiv2,
    })
}

/// Resolve BM1398 PLL0 (G19 pure SSOT in dcentrald-common).
///
/// Thin-wraps `dcentrald_common::resolve_bm1398_pll` so api-types and common
/// share one vendor search. `BM1398_PLL_SEARCH_SPEC` remains the documented
/// envelope pin (must stay byte-identical to common constants).
pub fn resolve_bm1398_pll(target_mhz: u16) -> Option<Bm1398PllSolution> {
    let (sol, div) = dcentrald_common::resolve_bm1398_pll(target_mhz)?;
    Some(Bm1398PllSolution {
        dividers: FourDividerPll {
            refdiv: div.ref_div,
            fbdiv: div.fb_div,
            postdiv1: div.post_div1,
            postdiv2: div.post_div2,
        },
        register_value: sol.register_value,
    })
}

pub const BM1398_CHIP_SPEC: Bm1398ChipSpec = Bm1398ChipSpec {
    chip_id: 0x1398,
    response: AsicResponseLengthSpec {
        body_bytes: 7,
        preamble_bytes: RESPONSE_PREAMBLE_BYTES,
    },
    pll_register: 0x08,
    core_register_control: 0x3c,
};

/// Exact staged core-control writes proven in both the stock NBP1901 binary
/// and the repair jig. These are evidence fragments, not a claimed complete
/// cold-boot recipe.
pub const BM1398_PROVEN_CORE_WRITES: [RegisterWrite; 2] = [
    RegisterWrite {
        register: 0x3c,
        value: 0x8000_8710,
    },
    RegisterWrite {
        register: 0x3c,
        value: 0x8000_8050,
    },
];

pub const S19_PRO_NBP1901_ADDRESS_PLAN: LinearAddressPlan =
    match LinearAddressPlan::try_new(0, 114, 2) {
        Ok(plan) => plan,
        Err(_) => panic!("invalid built-in NBP1901 address plan"),
    };

/// Stock production NBP1901 relay dialect. The repair-jig dialect is
/// intentionally not represented by this array because its topology formula
/// differs; conflating the two would create another unsupported constant.
pub const S19_PRO_NBP1901_PRODUCTION_UART_RELAY_WRITES: [AddressedRegisterWrite; 12] = [
    AddressedRegisterWrite {
        chip_address: 214,
        register: 0x2c,
        value: 0x0017_0003,
    },
    AddressedRegisterWrite {
        chip_address: 196,
        register: 0x2c,
        value: 0x0020_0003,
    },
    AddressedRegisterWrite {
        chip_address: 178,
        register: 0x2c,
        value: 0x0029_0003,
    },
    AddressedRegisterWrite {
        chip_address: 160,
        register: 0x2c,
        value: 0x0032_0003,
    },
    AddressedRegisterWrite {
        chip_address: 142,
        register: 0x2c,
        value: 0x003b_0003,
    },
    AddressedRegisterWrite {
        chip_address: 124,
        register: 0x2c,
        value: 0x0044_0003,
    },
    AddressedRegisterWrite {
        chip_address: 106,
        register: 0x2c,
        value: 0x004d_0003,
    },
    AddressedRegisterWrite {
        chip_address: 88,
        register: 0x2c,
        value: 0x0056_0003,
    },
    AddressedRegisterWrite {
        chip_address: 70,
        register: 0x2c,
        value: 0x005f_0003,
    },
    AddressedRegisterWrite {
        chip_address: 52,
        register: 0x2c,
        value: 0x0068_0003,
    },
    AddressedRegisterWrite {
        chip_address: 34,
        register: 0x2c,
        value: 0x0071_0003,
    },
    AddressedRegisterWrite {
        chip_address: 16,
        register: 0x2c,
        value: 0x007a_0003,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Nbp1901S19ProChainSpec {
    pub expected_chip_count: u16,
    pub voltage_domain_count: u8,
    pub chips_per_voltage_domain: u8,
    pub address_plan: LinearAddressPlan,
    pub proven_core_register_writes: &'static [RegisterWrite],
    pub production_uart_relay_writes: &'static [AddressedRegisterWrite],
}

pub const S19_PRO_NBP1901_CHAIN_SPEC: Nbp1901S19ProChainSpec = Nbp1901S19ProChainSpec {
    expected_chip_count: 114,
    voltage_domain_count: 38,
    chips_per_voltage_domain: 3,
    address_plan: S19_PRO_NBP1901_ADDRESS_PLAN,
    proven_core_register_writes: &BM1398_PROVEN_CORE_WRITES,
    production_uart_relay_writes: &S19_PRO_NBP1901_PRODUCTION_UART_RELAY_WRITES,
};

/// First-party stock per-board geometry for one BM1398-family hashboard
/// bin (Gauntlet B6, 2026-09-02).
///
/// Geometry ONLY. Unlike [`Nbp1901S19ProChainSpec`], this type carries no
/// core-register or UART-relay dialect: those arrays are recovered from
/// the stock **NBP1901** miner binary and are not proven for the other
/// bins' separate stock builds. Nothing here authorizes a runtime — the
/// Lane-F identity-joined admission and fail-closed energize intercept
/// stay the only path to a native runtime, and the post-energize
/// GetAddress confirmation stays sealed to NBP1901's 114-frame window
/// (a 76-chip bin's window expectation is recorded as data below, with
/// no admission consumer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Bm1398BoardGeometry {
    /// Stock `topol.conf` `machine` field (hashboard bin name).
    pub board_name: &'static str,
    pub model: &'static str,
    /// Stock `chain.chain_asic_num`.
    pub expected_chip_count: u16,
    /// Stock `chain.chain_row` × `chain.chain_column` placement grid.
    pub chain_row: u8,
    pub chain_column: u8,
    /// Stock `chain.chain_domain_num`.
    pub voltage_domain_count: u8,
    /// Stock `chain.domain_asic_num`.
    pub chips_per_voltage_domain: u8,
    /// Stock `asic.asic_addr_interval`.
    pub address_interval: u8,
    pub address_plan: LinearAddressPlan,
}

/// The shared 76-chip / interval-3 address plan for the two 76-chip BM1398
/// air bins (S19 NBS1902 and T19 NBT1903 — identical geometry, different
/// boards). One const so both bins provably use the same plan.
pub const BM1398_76CHIP_INTERVAL3_ADDRESS_PLAN: LinearAddressPlan =
    match LinearAddressPlan::try_new(0, 76, 3) {
        Ok(plan) => plan,
        Err(_) => panic!("invalid built-in 76-chip interval-3 address plan"),
    };

/// S19 classic (NBS1902): 76 BM1398P/chain, 8×10 grid, 38 domains × 2,
/// address interval 3. First-party source: stock
/// `s19-20211116/components/minerfs.image.gz.tree/etc/topol.conf`
/// (asicminingsupplies mirror, Phase A §3.7) — the settle for the
/// dossier's "76-hint vs 114" divergence: the two boards are genuinely
/// different bins shipped under one model line.
pub const S19_NBS1902_BOARD_GEOMETRY: Bm1398BoardGeometry = Bm1398BoardGeometry {
    board_name: "NBS1902",
    model: "S19",
    expected_chip_count: 76,
    chain_row: 8,
    chain_column: 10,
    voltage_domain_count: 38,
    chips_per_voltage_domain: 2,
    address_interval: 3,
    address_plan: BM1398_76CHIP_INTERVAL3_ADDRESS_PLAN,
};

/// S19 Pro (NBP1901): 114 BM1398P/chain, 12×10 grid, 38 domains × 3,
/// interval 2 — the geometry row of the fully-RE'd
/// [`S19_PRO_NBP1901_CHAIN_SPEC`], restated here so all three bins share
/// one first-party-sourced table.
pub const S19_PRO_NBP1901_BOARD_GEOMETRY: Bm1398BoardGeometry = Bm1398BoardGeometry {
    board_name: "NBP1901",
    model: "S19 Pro",
    expected_chip_count: 114,
    chain_row: 12,
    chain_column: 10,
    voltage_domain_count: 38,
    chips_per_voltage_domain: 3,
    address_interval: 2,
    address_plan: S19_PRO_NBP1901_ADDRESS_PLAN,
};

/// T19 (NBT1903): 76 BM1398P/chain, 8×10 grid, 38 domains × 2, interval
/// 3 — the same physical bin family as S19 NBS1902 under the T19 model.
/// First-party source: stock
/// `t19-20230320/components/minerfs.image.gz.tree/etc/topol.conf`
/// (Phase A §3.7). This settles the dossier's G7 T19 row desk-side; the
/// VNish "3×76" chain-population reading stays a live-capture question.
pub const T19_NBT1903_BOARD_GEOMETRY: Bm1398BoardGeometry = Bm1398BoardGeometry {
    board_name: "NBT1903",
    model: "T19",
    expected_chip_count: 76,
    chain_row: 8,
    chain_column: 10,
    voltage_domain_count: 38,
    chips_per_voltage_domain: 2,
    address_interval: 3,
    address_plan: BM1398_76CHIP_INTERVAL3_ADDRESS_PLAN,
};

/// Exact BHB28611 stock topology, from Bitmain S19a 20221206
/// `components/minerfs.image.gz.tree/etc/topol.conf`. BM1398S has four
/// internal ASIC domains; the PCB has nine series domains of eight chips.
/// Neither quantity may be replaced by the NBS1902 38-by-two layout.
pub const S19A_BHB28611_BOARD_GEOMETRY: Bm1398BoardGeometry = Bm1398BoardGeometry {
    board_name: "BHB28611",
    model: "S19a",
    expected_chip_count: 72,
    chain_row: 9,
    chain_column: 8,
    voltage_domain_count: 9,
    chips_per_voltage_domain: 8,
    address_interval: 3,
    address_plan: match LinearAddressPlan::try_new(0, 72, 3) {
        Ok(plan) => plan,
        Err(_) => panic!("invalid BHB28611 address plan"),
    },
};

/// Exact S19+ model-info from the held VNish rc5 hwscan constructor 0x7ed14
/// and serializer 0x22310: BHB28701, three chains of 80, interval 3,
/// num_rows=8 / num_cols=10, ten domains of eight. Bitmain's maintenance
/// guide independently states the 80-chip / ten-domain topology. Neither
/// source establishes a measured physical EEPROM page or runtime result.
pub const S19_PLUS_BHB28701_BOARD_GEOMETRY: Bm1398BoardGeometry = Bm1398BoardGeometry {
    board_name: "BHB28701",
    model: "S19+",
    expected_chip_count: 80,
    chain_row: 8,
    chain_column: 10,
    voltage_domain_count: 10,
    chips_per_voltage_domain: 8,
    address_interval: 3,
    address_plan: match LinearAddressPlan::try_new(0, 80, 3) {
        Ok(plan) => plan,
        Err(_) => panic!("invalid BHB28701 address plan"),
    },
};

/// Exact vendor topology rows. These data alone grant no energization.
pub const BM1398_AIR_BOARD_GEOMETRIES: [Bm1398BoardGeometry; 5] = [
    S19_NBS1902_BOARD_GEOMETRY,
    S19_PRO_NBP1901_BOARD_GEOMETRY,
    T19_NBT1903_BOARD_GEOMETRY,
    S19A_BHB28611_BOARD_GEOMETRY,
    S19_PLUS_BHB28701_BOARD_GEOMETRY,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bm1398FpgaMidstateMode {
    Four,
    Eight,
}

impl Bm1398FpgaMidstateMode {
    pub const fn log2_count(self) -> u8 {
        match self {
            Self::Four => 2,
            Self::Eight => 3,
        }
    }

    pub const fn midstate_count(self) -> u8 {
        1 << self.log2_count()
    }

    pub const fn payload_words(self) -> u16 {
        4 + self.midstate_count() as u16 * 8
    }

    pub const fn payload_bytes(self) -> u16 {
        self.payload_words() * 4
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Bm1398FpgaFifoSpec {
    supported_modes: [Bm1398FpgaMidstateMode; 2],
    nonce_chip_address_shift: u8,
    nonce_chip_address_mask: u8,
    /// Width of the carrier's raw extended-work-id echo.
    echoed_work_id_bits: u8,
    /// Width of the logical dispatcher ring before slot bits are appended.
    logical_work_id_bits: u8,
}

impl Bm1398FpgaFifoSpec {
    pub const fn supported_modes(self) -> [Bm1398FpgaMidstateMode; 2] {
        self.supported_modes
    }

    pub const fn nonce_chip_address_shift(self) -> u8 {
        self.nonce_chip_address_shift
    }

    pub const fn nonce_chip_address_mask(self) -> u8 {
        self.nonce_chip_address_mask
    }

    pub const fn echoed_work_id_bits(self) -> u8 {
        self.echoed_work_id_bits
    }

    pub const fn logical_work_id_bits(self) -> u8 {
        self.logical_work_id_bits
    }

    pub const fn supports_mode(self, mode: Bm1398FpgaMidstateMode) -> bool {
        matches!(
            (self.supported_modes[0], self.supported_modes[1], mode),
            (
                Bm1398FpgaMidstateMode::Four,
                _,
                Bm1398FpgaMidstateMode::Four
            ) | (
                _,
                Bm1398FpgaMidstateMode::Four,
                Bm1398FpgaMidstateMode::Four
            ) | (
                Bm1398FpgaMidstateMode::Eight,
                _,
                Bm1398FpgaMidstateMode::Eight
            ) | (
                _,
                Bm1398FpgaMidstateMode::Eight,
                Bm1398FpgaMidstateMode::Eight
            )
        )
    }

    pub const fn raw_chip_address(self, nonce: u32) -> Option<u8> {
        if self.nonce_chip_address_shift >= u32::BITS as u8 {
            return None;
        }
        Some(((nonce >> self.nonce_chip_address_shift) & self.nonce_chip_address_mask as u32) as u8)
    }

    pub const fn dense_chip_index(
        self,
        nonce: u32,
        address_plan: LinearAddressPlan,
    ) -> Option<u16> {
        match self.raw_chip_address(nonce) {
            Some(address) => address_plan.dense_index(address),
            None => None,
        }
    }

    pub const fn encode_work_id(
        self,
        mode: Bm1398FpgaMidstateMode,
        logical_work_id: u16,
        slot_index: u8,
    ) -> Option<u16> {
        let slot_bits = mode.log2_count();
        if !self.supports_mode(mode)
            || self.logical_work_id_bits >= u32::BITS as u8
            || self.echoed_work_id_bits > u16::BITS as u8
            || self.logical_work_id_bits.saturating_add(slot_bits) > self.echoed_work_id_bits
        {
            return None;
        }
        let logical_limit = 1u32 << self.logical_work_id_bits;
        if logical_work_id as u32 >= logical_limit || slot_index >= mode.midstate_count() {
            return None;
        }
        match logical_work_id.checked_shl(slot_bits as u32) {
            Some(encoded) => Some(encoded | slot_index as u16),
            None => None,
        }
    }

    pub const fn decode_work_id(
        self,
        mode: Bm1398FpgaMidstateMode,
        echoed_work_id: u16,
    ) -> Option<(u16, u8)> {
        let slot_bits = mode.log2_count();
        if !self.supports_mode(mode)
            || self.echoed_work_id_bits != u16::BITS as u8
            || self.logical_work_id_bits >= u32::BITS as u8
            || self.logical_work_id_bits.saturating_add(slot_bits) > self.echoed_work_id_bits
        {
            return None;
        }
        let slot_mask = (1u16 << slot_bits) - 1;
        let logical_work_id = echoed_work_id >> slot_bits;
        if logical_work_id as u32 >= (1u32 << self.logical_work_id_bits) {
            return None;
        }
        Some((logical_work_id, (echoed_work_id & slot_mask) as u8))
    }
}

pub const BM1398_FPGA_FIFO_SPEC: Bm1398FpgaFifoSpec = Bm1398FpgaFifoSpec {
    supported_modes: [Bm1398FpgaMidstateMode::Four, Bm1398FpgaMidstateMode::Eight],
    nonce_chip_address_shift: 17,
    nonce_chip_address_mask: 0xff,
    echoed_work_id_bits: 16,
    logical_work_id_bits: 8,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Bm1398ProtocolProfile {
    pub chip: Bm1398ChipSpec,
    pub chain: Nbp1901S19ProChainSpec,
    pub fifo: Bm1398FpgaFifoSpec,
}

pub const S19_PRO_NBP1901_BM1398_PROFILE: Bm1398ProtocolProfile = Bm1398ProtocolProfile {
    chip: BM1398_CHIP_SPEC,
    chain: S19_PRO_NBP1901_CHAIN_SPEC,
    fifo: BM1398_FPGA_FIFO_SPEC,
};

/// Maturity of the evidence-scoped software protocol surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bm1398Nbp1901SoftwareMaturity {
    /// Chip identity/response, geometry, PLL, staged core writes, production
    /// relay writes, FPGA FIFO/work-id semantics, and the driver codec are
    /// reconstructed and host-tested. This says nothing about physical-board
    /// admission or live accepted shares.
    ReconstructedHostTested,
}

/// Independent physical-identity evidence available to native admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bm1398Nbp1901PhysicalIdentityMaturity {
    /// No held deployed S19 Pro EEPROM page currently supplies a decoded exact
    /// board name that can be independently bound to BM1398.
    MissingHeldDeployedPage,
}

/// Native runtime posture resulting from the independent evidence axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Bm1398Nbp1901NativeRuntimeMaturity {
    /// `serial_mining` must refuse before hardware observation/construction.
    RefusedMissingPhysicalIdentity,
}

/// Machine-readable BM1398/NBP1901 readiness split.
///
/// This is deliberately data, not an admission token. There is no conversion
/// from this record to hardware authority: reconstructed software evidence and
/// an admitted physical runtime are different axes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Bm1398Nbp1901Readiness {
    pub software: Bm1398Nbp1901SoftwareMaturity,
    pub physical_identity: Bm1398Nbp1901PhysicalIdentityMaturity,
    pub native_runtime: Bm1398Nbp1901NativeRuntimeMaturity,
    pub mining_default_enabled: bool,
    pub stock_bmminer_sha256: &'static str,
    pub repair_jig_sha256: &'static str,
}

impl Bm1398Nbp1901Readiness {
    /// Explicit non-authority predicate for API/tooling consumers.
    pub const fn permits_native_runtime(self) -> bool {
        false
    }
}

pub const S19_PRO_NBP1901_BM1398_READINESS: Bm1398Nbp1901Readiness = Bm1398Nbp1901Readiness {
    software: Bm1398Nbp1901SoftwareMaturity::ReconstructedHostTested,
    physical_identity: Bm1398Nbp1901PhysicalIdentityMaturity::MissingHeldDeployedPage,
    native_runtime: Bm1398Nbp1901NativeRuntimeMaturity::RefusedMissingPhysicalIdentity,
    mining_default_enabled: false,
    stock_bmminer_sha256: NBP1901_STOCK_BMMINER_SHA256,
    repair_jig_sha256: BM1398_REPAIR_JIG_SHA256,
};

// ============================================================================
// BM1398 native bring-up spec, as inert host-testable data (jig-recovered)
// ============================================================================
//
// # Provenance
//
// Recovered 2026-07-24 from Bitmain's factory jig
//  via GhidraMCP,
// orchestrator `FUN_0001d124` and its callees. Documented in
//  (ledger L3).
//
// This is a **spec expressed as data and pure arithmetic** — it commands no
// silicon. Its purpose is (a) to make the two previously-opaque
// [`BM1398_PROVEN_CORE_WRITES`] magic constants auditable by re-deriving them from
// named `Asic_Register` fields, (b) to add the config writes the jig always issues
// that DCENT was missing (Diode_Vdd_Mux reg 0x54; the ticket-mask reg 0x14 LUT), and
// (c) to record the exact cold-boot step ORDER. Wiring any of this into a live serial
// dispatch stays behind the `serial_mining.rs` native-BM1398 refusal + a two-source
// `AsicProtocolAdmission` until bench proof; the jig's 15.0 V pre-open-core voltage is
// a **fixture-only** value and must never enter a production cold boot (see the
// `PRE_OPEN_CORE` note below).

/// BM1398 core-control register (`0x3c`), first write: encodes `Pulse_Mode` (bits
/// [5:4]) and `Clk_Sel` (bits [2:0]) over the fixed base `0x8000_8700`.
/// From jig `FUN_0002a8ec`. For the AMTC config (Pulse=1, Clk=0) this is `0x8000_8710`
/// — byte-identical to `BM1398_PROVEN_CORE_WRITES[0]`.
pub const fn bm1398_core_reg_pulse_clk(pulse_mode: u8, clk_sel: u8) -> u32 {
    0x8000_8700 | (((pulse_mode as u32) & 0x3) << 4) | ((clk_sel as u32) & 0x7)
}

/// BM1398 core-control register (`0x3c`), second write: encodes `Pwth_Sel` (bits
/// [5:4]), `CCdly_Sel` (bits [7:6]) and `Swpf_Mode` (bit 0) over base `0x8000_8000`.
/// From jig `FUN_000297c4`. For the AMTC config (Pwth=1, CCdly=1, Swpf=0) this is
/// `0x8000_8050` — byte-identical to `BM1398_PROVEN_CORE_WRITES[1]`.
pub const fn bm1398_core_reg_pwth_ccdly_swpf(pwth_sel: u8, ccdly_sel: u8, swpf_mode: u8) -> u32 {
    0x8000_8000
        | (((pwth_sel as u32) & 0x3) << 4)
        | (((ccdly_sel as u32) & 0x3) << 6)
        | if swpf_mode != 0 { 1 } else { 0 }
}

/// Diode-Vdd-mux register. The jig (`FUN_00029fa4`) writes this FIRST in the chain
/// bring-up, broadcast, value `Diode_Vdd_Mux_Sel & 7`. DCENT was missing this write
/// entirely.
pub const BM1398_DIODE_VDD_MUX_REG: u8 = 0x54;

/// Value for [`BM1398_DIODE_VDD_MUX_REG`] from the `Diode_Vdd_Mux_Sel` config field.
pub const fn bm1398_diode_vdd_mux_value(sel: u8) -> u32 {
    (sel as u32) & 0x7
}

/// Ticket-mask register (same id as BM1387/BM1397: `0x14`). The jig
/// (`FUN_00029ad4`) writes the mask with **each byte bit-reversed** via the
/// [`BM1398_BIT_SWAP_TABLE`], byte order preserved.
pub const BM1398_TICKET_MASK_REG: u8 = 0x14;

/// 256-byte 8-bit bit-reversal LUT read from jig `.rodata` at `ram:0x00035df0`.
/// `BM1398_BIT_SWAP_TABLE[i] == (i as u8).reverse_bits()` for all `i` — the test
/// below pins that equivalence for every entry, so the table is self-verifying.
/// Twin of the documented BM1397 table at `0x00030b3c`.
#[rustfmt::skip]
pub const BM1398_BIT_SWAP_TABLE: [u8; 256] = [
    0x00, 0x80, 0x40, 0xC0, 0x20, 0xA0, 0x60, 0xE0, 0x10, 0x90, 0x50, 0xD0, 0x30, 0xB0, 0x70, 0xF0,
    0x08, 0x88, 0x48, 0xC8, 0x28, 0xA8, 0x68, 0xE8, 0x18, 0x98, 0x58, 0xD8, 0x38, 0xB8, 0x78, 0xF8,
    0x04, 0x84, 0x44, 0xC4, 0x24, 0xA4, 0x64, 0xE4, 0x14, 0x94, 0x54, 0xD4, 0x34, 0xB4, 0x74, 0xF4,
    0x0C, 0x8C, 0x4C, 0xCC, 0x2C, 0xAC, 0x6C, 0xEC, 0x1C, 0x9C, 0x5C, 0xDC, 0x3C, 0xBC, 0x7C, 0xFC,
    0x02, 0x82, 0x42, 0xC2, 0x22, 0xA2, 0x62, 0xE2, 0x12, 0x92, 0x52, 0xD2, 0x32, 0xB2, 0x72, 0xF2,
    0x0A, 0x8A, 0x4A, 0xCA, 0x2A, 0xAA, 0x6A, 0xEA, 0x1A, 0x9A, 0x5A, 0xDA, 0x3A, 0xBA, 0x7A, 0xFA,
    0x06, 0x86, 0x46, 0xC6, 0x26, 0xA6, 0x66, 0xE6, 0x16, 0x96, 0x56, 0xD6, 0x36, 0xB6, 0x76, 0xF6,
    0x0E, 0x8E, 0x4E, 0xCE, 0x2E, 0xAE, 0x6E, 0xEE, 0x1E, 0x9E, 0x5E, 0xDE, 0x3E, 0xBE, 0x7E, 0xFE,
    0x01, 0x81, 0x41, 0xC1, 0x21, 0xA1, 0x61, 0xE1, 0x11, 0x91, 0x51, 0xD1, 0x31, 0xB1, 0x71, 0xF1,
    0x09, 0x89, 0x49, 0xC9, 0x29, 0xA9, 0x69, 0xE9, 0x19, 0x99, 0x59, 0xD9, 0x39, 0xB9, 0x79, 0xF9,
    0x05, 0x85, 0x45, 0xC5, 0x25, 0xA5, 0x65, 0xE5, 0x15, 0x95, 0x55, 0xD5, 0x35, 0xB5, 0x75, 0xF5,
    0x0D, 0x8D, 0x4D, 0xCD, 0x2D, 0xAD, 0x6D, 0xED, 0x1D, 0x9D, 0x5D, 0xDD, 0x3D, 0xBD, 0x7D, 0xFD,
    0x03, 0x83, 0x43, 0xC3, 0x23, 0xA3, 0x63, 0xE3, 0x13, 0x93, 0x53, 0xD3, 0x33, 0xB3, 0x73, 0xF3,
    0x0B, 0x8B, 0x4B, 0xCB, 0x2B, 0xAB, 0x6B, 0xEB, 0x1B, 0x9B, 0x5B, 0xDB, 0x3B, 0xBB, 0x7B, 0xFB,
    0x07, 0x87, 0x47, 0xC7, 0x27, 0xA7, 0x67, 0xE7, 0x17, 0x97, 0x57, 0xD7, 0x37, 0xB7, 0x77, 0xF7,
    0x0F, 0x8F, 0x4F, 0xCF, 0x2F, 0xAF, 0x6F, 0xEF, 0x1F, 0x9F, 0x5F, 0xDF, 0x3F, 0xBF, 0x7F, 0xFF,
];

/// Encode a ticket mask for [`BM1398_TICKET_MASK_REG`]: bit-reverse each of the four
/// bytes (byte order preserved). `0xFFFF_FFFF` (all-accept) maps to itself, matching
/// the jig's `TM = 0xff` broadcast.
///
/// G24: pure SSOT is `reverse_bits().swap_bytes()` in `dcentrald_common` (equivalent
/// to indexing [`BM1398_BIT_SWAP_TABLE`] per LE byte). Kept as `const fn` for
/// static init paths; must stay byte-identical to the pure encode.
pub const fn bm1398_ticket_mask_value(mask: u32) -> u32 {
    // G24/G25: shared pure bit-swap transform (const twin of
    // `dcentrald_common::bit_reverse_u32_bytewise`).
    dcentrald_common::bit_reverse_u32_bytewise(mask)
}

/// One ordered step in the BM1398 chain bring-up, as recovered from `FUN_0001d124`.
/// Command lengths: a register write is a 9-byte frame; chain-inactive and
/// set-chip-address are 5-byte frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Bm1398ChainInitStep {
    /// Broadcast register write (9-byte frame): diode-mux, core writes, PLL, baud,
    /// ticket-mask.
    RegisterWrite { register: u8 },
    /// Chain-Inactive broadcast (5-byte frame).
    ChainInactive,
    /// Per-chip Set-Chip-Address sweep (5-byte frames), `hw_addr` stepping by the
    /// address-plan interval.
    SetChipAddress,
}

/// The recovered cold-boot step ORDER for BM1398 (jig `FUN_0001d124`). This is the
/// sequence a native driver must follow; it is inert until wired behind the refusal
/// gate. The jig's UART-relay step (its topology formula addresses nonexistent chip
/// addresses) is intentionally excluded — production uses
/// [`S19_PRO_NBP1901_PRODUCTION_UART_RELAY_WRITES`] instead.
pub const BM1398_CHAIN_INIT_STEPS: [Bm1398ChainInitStep; 9] = [
    Bm1398ChainInitStep::RegisterWrite {
        register: BM1398_DIODE_VDD_MUX_REG,
    },
    Bm1398ChainInitStep::ChainInactive,
    Bm1398ChainInitStep::SetChipAddress,
    Bm1398ChainInitStep::RegisterWrite {
        register: BM1398_CHIP_SPEC.core_register_control, // core write #1 (0x3c)
    },
    Bm1398ChainInitStep::RegisterWrite {
        register: BM1398_CHIP_SPEC.core_register_control, // core write #2 (0x3c)
    },
    // Both PLL0 writes are ADJACENT and PRECEDE baud (jig FUN_0001d124): the
    // user-divider zero-write comes first, then the PLL-frequency write. The sequence
    // ends on ticket-mask.
    Bm1398ChainInitStep::RegisterWrite {
        register: BM1398_CHIP_SPEC.pll_register, // PLL0 user-divider zero-write (0x08)
    },
    Bm1398ChainInitStep::RegisterWrite {
        register: BM1398_CHIP_SPEC.pll_register, // PLL0 frequency write (0x08)
    },
    Bm1398ChainInitStep::RegisterWrite { register: 0x18 }, // baud
    Bm1398ChainInitStep::RegisterWrite {
        register: BM1398_TICKET_MASK_REG, // ticket-mask (0x14) — last wire op
    },
];

/// **Fixture-only voltage — NOT for production.** The AMTC `Config.ini`
/// `Pre_Open_Core_Voltage = 1500` (15.00 V, centivolts) is a pattern-test fixture
/// voltage read by the jig's pattern checker, NOT part of the chain-init orchestrator.
/// A native BM1398 cold boot must use the ~13.8 V nameplate rail; commanding 15.0 V
/// would over-volt the chain. Recorded as a named constant purely so the value is
/// documented as forbidden, never so it is used.
pub const BM1398_JIG_PRE_OPEN_CORE_FIXTURE_MILLIVOLTS: u16 = 15_000;

#[cfg(test)]
mod tests {
    use super::*;

    /// Gauntlet B6 (2026-09-02): the three first-party stock bins. Every
    /// row is pinned to the stock `topol.conf` values verbatim (Phase A
    /// §3.7), and the NBP1901 row must agree exactly with the fully-RE'd
    /// [`S19_PRO_NBP1901_CHAIN_SPEC`] so the two tables can never drift.
    #[test]
    fn air_board_geometries_match_first_party_stock_topol() {
        let s19 = S19_NBS1902_BOARD_GEOMETRY;
        assert_eq!(
            (s19.expected_chip_count, s19.chain_row, s19.chain_column),
            (76, 8, 10)
        );
        assert_eq!(
            (
                s19.voltage_domain_count,
                s19.chips_per_voltage_domain,
                s19.address_interval
            ),
            (38, 2, 3)
        );
        // row × column is the physical PLACEMENT GRID (80 positions,
        // 76 populated — the topol `domain` coordinate table skips the
        // empty slots); domains × per-domain is the populated count.
        assert_eq!(s19.chain_row as u16 * s19.chain_column as u16, 80);
        assert_eq!(
            s19.voltage_domain_count as u16 * s19.chips_per_voltage_domain as u16,
            s19.expected_chip_count
        );
        let pro = S19_PRO_NBP1901_BOARD_GEOMETRY;
        assert_eq!(
            (pro.expected_chip_count, pro.chain_row, pro.chain_column),
            (114, 12, 10)
        );
        assert_eq!(
            (
                pro.voltage_domain_count,
                pro.chips_per_voltage_domain,
                pro.address_interval
            ),
            (38, 3, 2)
        );
        let t19 = T19_NBT1903_BOARD_GEOMETRY;
        assert_eq!(
            (t19.expected_chip_count, t19.chain_row, t19.chain_column),
            (76, 8, 10)
        );
        assert_eq!(
            (
                t19.voltage_domain_count,
                t19.chips_per_voltage_domain,
                t19.address_interval
            ),
            (38, 2, 3)
        );
        // T19 shares the S19 physical bin geometry but is its own board.
        assert_eq!(t19.board_name, "NBT1903");
        assert_ne!(t19.board_name, s19.board_name);
        let s19a = S19A_BHB28611_BOARD_GEOMETRY;
        assert_eq!(
            (s19a.expected_chip_count, s19a.chain_row, s19a.chain_column),
            (72, 9, 8)
        );
        assert_eq!(
            (
                s19a.voltage_domain_count,
                s19a.chips_per_voltage_domain,
                s19a.address_interval
            ),
            (9, 8, 3)
        );
        assert_eq!(s19a.address_plan.hardware_address(71), Some(213));
        assert_eq!(s19a.address_plan.hardware_address(72), None);
    }

    /// The NBP1901 geometry row must be exactly the RE-confirmed spec's
    /// geometry — a mismatch here means one of the two tables went stale.
    #[test]
    fn nbp1901_geometry_row_agrees_with_the_re_chain_spec() {
        let spec = &S19_PRO_NBP1901_CHAIN_SPEC;
        let geo = &S19_PRO_NBP1901_BOARD_GEOMETRY;
        assert_eq!(geo.expected_chip_count, spec.expected_chip_count);
        assert_eq!(geo.voltage_domain_count, spec.voltage_domain_count);
        assert_eq!(geo.chips_per_voltage_domain, spec.chips_per_voltage_domain);
        assert_eq!(geo.address_plan, spec.address_plan);
    }

    /// The 76-chip bins' address plans end at 75×3 = 225 with interval 3
    /// (the NBP1901 plan is interval 2 — deliberately NOT reused).
    #[test]
    fn seventy_six_chip_bins_use_interval_three_plans() {
        for geo in [S19_NBS1902_BOARD_GEOMETRY, T19_NBT1903_BOARD_GEOMETRY] {
            assert_eq!(geo.address_plan.hardware_address(0), Some(0x00));
            assert_eq!(geo.address_plan.hardware_address(75), Some(225));
            assert_eq!(geo.address_plan.hardware_address(1), Some(3));
            assert_eq!(geo.address_plan.hardware_address(76), None);
        }
    }

    /// The two core-write encoders must reproduce the already-shipped, .129-cold-boot-
    /// proven magic constants for the AMTC config. This ties the opaque constants to
    /// their named-field derivation with zero behavioral change.
    #[test]
    fn core_reg_encoders_reproduce_proven_magic_constants() {
        assert_eq!(bm1398_core_reg_pulse_clk(1, 0), 0x8000_8710);
        assert_eq!(bm1398_core_reg_pwth_ccdly_swpf(1, 1, 0), 0x8000_8050);
        assert_eq!(
            BM1398_PROVEN_CORE_WRITES[0].value,
            bm1398_core_reg_pulse_clk(1, 0)
        );
        assert_eq!(
            BM1398_PROVEN_CORE_WRITES[1].value,
            bm1398_core_reg_pwth_ccdly_swpf(1, 1, 0)
        );
    }

    /// Field masking must not spill into the fixed base bits.
    #[test]
    fn core_reg_encoders_mask_fields() {
        // pulse_mode is 2 bits, clk_sel 3 bits.
        assert_eq!(bm1398_core_reg_pulse_clk(0xFF, 0xFF), 0x8000_8737);
        // pwth 2 bits @4, ccdly 2 bits @6, swpf 1 bit @0.
        assert_eq!(
            bm1398_core_reg_pwth_ccdly_swpf(0xFF, 0xFF, 0xFF),
            0x8000_80F1
        );
    }

    #[test]
    fn readiness_separates_reconstructed_protocol_from_native_authority() {
        use dcentrald_common::bm1398_nbp1901_stub as legacy;

        let readiness = S19_PRO_NBP1901_BM1398_READINESS;
        assert_eq!(
            readiness.software,
            Bm1398Nbp1901SoftwareMaturity::ReconstructedHostTested
        );
        assert_eq!(
            readiness.physical_identity,
            Bm1398Nbp1901PhysicalIdentityMaturity::MissingHeldDeployedPage
        );
        assert_eq!(
            readiness.native_runtime,
            Bm1398Nbp1901NativeRuntimeMaturity::RefusedMissingPhysicalIdentity
        );
        assert!(!readiness.mining_default_enabled);
        assert!(!readiness.permits_native_runtime());
        assert_eq!(readiness.stock_bmminer_sha256, NBP1901_STOCK_BMMINER_SHA256);
        assert_eq!(readiness.repair_jig_sha256, BM1398_REPAIR_JIG_SHA256);

        let profile = S19_PRO_NBP1901_BM1398_PROFILE;
        let identity = legacy::BM1398_NBP1901_IDENTITY;
        assert!(identity.protocol_reconstructed);
        assert!(!identity.deployed_identity_held);
        assert!(!identity.admit);
        assert!(!identity.implemented);
        assert!(!identity.mining_default_enabled);
        assert_eq!(identity.chip_id, profile.chip.chip_id);
        assert_eq!(
            identity.chain_asic_num as u16,
            profile.chain.expected_chip_count
        );
        assert_eq!(
            identity.asic_addr_interval,
            profile.chain.address_plan.address_interval()
        );
        assert_eq!(
            identity.chain_domain_num,
            profile.chain.voltage_domain_count
        );
        assert_eq!(
            identity.domain_asic_num,
            profile.chain.chips_per_voltage_domain
        );
        assert!(matches!(
            legacy::admit_bm1398_nbp1901(),
            Err(legacy::Bm1398Nbp1901StubError::MissingDeployedIdentityEvidence)
        ));

        let serialized = serde_json::to_value(readiness).unwrap();
        assert_eq!(serialized["software"], "reconstructed_host_tested");
        assert_eq!(
            serialized["physical_identity"],
            "missing_held_deployed_page"
        );
        assert_eq!(
            serialized["native_runtime"],
            "refused_missing_physical_identity"
        );
        assert_eq!(serialized["mining_default_enabled"], false);
    }

    #[test]
    fn diode_vdd_mux_value_masks_to_three_bits() {
        assert_eq!(bm1398_diode_vdd_mux_value(3), 0x0000_0003);
        assert_eq!(bm1398_diode_vdd_mux_value(0xFF), 0x7);
        assert_eq!(BM1398_DIODE_VDD_MUX_REG, 0x54);
    }

    /// Every LUT entry equals Rust's `reverse_bits`, proving the recovered 256 bytes.
    #[test]
    fn bit_swap_table_equals_reverse_bits() {
        for i in 0..=255u16 {
            let i = i as u8;
            assert_eq!(
                BM1398_BIT_SWAP_TABLE[i as usize],
                i.reverse_bits(),
                "LUT[{i:#04x}] mismatch"
            );
        }
        assert_eq!(BM1398_BIT_SWAP_TABLE[1], 0x80);
        assert_eq!(BM1398_BIT_SWAP_TABLE[0x80], 0x01);
        assert_eq!(BM1398_BIT_SWAP_TABLE[0xFF], 0xFF);
    }

    #[test]
    fn ticket_mask_encoding_matches_jig_vectors() {
        // All-accept round-trips (jig broadcasts TM=0xff -> 0xFFFF_FFFF).
        assert_eq!(bm1398_ticket_mask_value(0xFFFF_FFFF), 0xFFFF_FFFF);
        // Low bit reverses to the top of its byte.
        assert_eq!(bm1398_ticket_mask_value(0x0000_0001), 0x0000_0080);
        assert_eq!(BM1398_TICKET_MASK_REG, 0x14);
    }

    /// The recovered order: diode-mux first, chain-inactive, address sweep, then the
    /// two core writes, PLL, baud, ticket-mask.
    #[test]
    fn chain_init_step_order_is_jig_faithful() {
        use Bm1398ChainInitStep::*;
        assert!(matches!(
            BM1398_CHAIN_INIT_STEPS[0],
            RegisterWrite {
                register: BM1398_DIODE_VDD_MUX_REG
            }
        ));
        assert_eq!(BM1398_CHAIN_INIT_STEPS[1], ChainInactive);
        assert_eq!(BM1398_CHAIN_INIT_STEPS[2], SetChipAddress);
        // Diode-mux precedes chain-inactive (a safety-relevant ordering fact).
        let diode = BM1398_CHAIN_INIT_STEPS
            .iter()
            .position(|s| matches!(s, RegisterWrite { register: 0x54 }))
            .unwrap();
        let inactive = BM1398_CHAIN_INIT_STEPS
            .iter()
            .position(|s| *s == ChainInactive)
            .unwrap();
        assert!(diode < inactive);

        // Tail order ( review fix): both PLL0 writes (0x08) are adjacent at
        // indices 5,6 and PRECEDE baud (0x18) at 7; the sequence ends on ticket-mask
        // (0x14) at 8. This pins the exact misordering the review caught.
        assert_eq!(
            BM1398_CHAIN_INIT_STEPS[5],
            RegisterWrite {
                register: BM1398_CHIP_SPEC.pll_register
            }
        );
        assert_eq!(
            BM1398_CHAIN_INIT_STEPS[6],
            RegisterWrite {
                register: BM1398_CHIP_SPEC.pll_register
            }
        );
        assert_eq!(BM1398_CHAIN_INIT_STEPS[7], RegisterWrite { register: 0x18 });
        assert_eq!(
            BM1398_CHAIN_INIT_STEPS[8],
            RegisterWrite {
                register: BM1398_TICKET_MASK_REG
            }
        );
        // Both PLL writes precede baud.
        let baud = BM1398_CHAIN_INIT_STEPS
            .iter()
            .position(|s| *s == (RegisterWrite { register: 0x18 }))
            .unwrap();
        let pll_positions: Vec<usize> = BM1398_CHAIN_INIT_STEPS
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                **s == (RegisterWrite {
                    register: BM1398_CHIP_SPEC.pll_register,
                })
            })
            .map(|(i, _)| i)
            .collect();
        assert_eq!(pll_positions, vec![5, 6]);
        assert!(pll_positions.iter().all(|&p| p < baud));
    }

    /// The fixture pre-open-core voltage is documented ONLY as a forbidden value.
    #[test]
    fn fixture_pre_open_core_voltage_is_not_a_production_rail() {
        assert_eq!(BM1398_JIG_PRE_OPEN_CORE_FIXTURE_MILLIVOLTS, 15_000);
        // Well above the ~13.8 V nameplate — must never be a cold-boot target.
        assert!(BM1398_JIG_PRE_OPEN_CORE_FIXTURE_MILLIVOLTS > 14_000);
    }

    #[test]
    fn exact_vendor_pll_vectors_are_pinned() {
        let pll_525 = resolve_bm1398_pll(525).unwrap();
        assert_eq!(
            pll_525.dividers,
            FourDividerPll {
                refdiv: 2,
                fbdiv: 168,
                postdiv1: 4,
                postdiv2: 1,
            }
        );
        assert_eq!(pll_525.register_value, 0x40a8_0241);

        let pll_675 = resolve_bm1398_pll(675).unwrap();
        assert_eq!(
            pll_675.dividers,
            FourDividerPll {
                refdiv: 2,
                fbdiv: 162,
                postdiv1: 3,
                postdiv2: 1,
            }
        );
        assert_eq!(pll_675.register_value, 0x40a2_0231);
    }

    #[test]
    fn vendor_error_ceiling_is_strict_at_both_vco_boundaries() {
        assert!(resolve_bm1398_pll(1_990).is_none());
        assert!(resolve_bm1398_pll(1_991).is_some());
        assert!(resolve_bm1398_pll(3_134).is_some());
        assert!(resolve_bm1398_pll(3_135).is_none());
    }

    #[test]
    fn pll_encoder_preserves_the_repair_jig_12th_fbdiv_bit() {
        let word = bm1398_pll_register_value(FourDividerPll {
            refdiv: 1,
            fbdiv: 0x0800,
            postdiv1: 1,
            postdiv2: 1,
        });
        assert_eq!((word >> 16) & 0x0fff, 0x0800);
        assert_eq!(word, 0x4800_0111);
    }

    #[test]
    fn nbp1901_geometry_and_addressing_are_exact() {
        let chain = S19_PRO_NBP1901_CHAIN_SPEC;
        assert_eq!(
            chain.voltage_domain_count as u16 * chain.chips_per_voltage_domain as u16,
            chain.expected_chip_count
        );
        assert_eq!(chain.address_plan.first_address(), 0);
        assert_eq!(chain.address_plan.address_interval(), 2);
        assert_eq!(chain.address_plan.last_address(), 226);
        assert_eq!(chain.address_plan.hardware_address(113), Some(226));
        assert_eq!(chain.address_plan.dense_index(226), Some(113));
        assert_eq!(chain.address_plan.dense_index(225), None);
        assert_eq!(chain.address_plan.dense_index(228), None);
    }

    #[test]
    fn production_relay_sequence_is_distinct_and_complete() {
        let writes = S19_PRO_NBP1901_PRODUCTION_UART_RELAY_WRITES;
        assert_eq!(writes.len(), 12);
        assert_eq!(writes[0].chip_address, 214);
        assert_eq!(writes[0].value, 0x0017_0003);
        assert_eq!(writes[11].chip_address, 16);
        assert_eq!(writes[11].value, 0x007a_0003);
        for window in writes.windows(2) {
            assert_eq!(window[0].chip_address - window[1].chip_address, 18);
        }
        assert!(writes.iter().all(|write| write.register == 0x2c));
    }

    #[test]
    fn core_writes_are_staged_evidence_not_the_old_snapshot() {
        assert_eq!(BM1398_PROVEN_CORE_WRITES[0].value, 0x8000_8710);
        assert_eq!(BM1398_PROVEN_CORE_WRITES[1].value, 0x8000_8050);
        assert!(BM1398_PROVEN_CORE_WRITES
            .iter()
            .all(|write| write.value != 0x8000_8074));
    }

    #[test]
    fn fifo_modes_have_distinct_payload_sizes() {
        assert_eq!(Bm1398FpgaMidstateMode::Four.log2_count(), 2);
        assert_eq!(Bm1398FpgaMidstateMode::Four.payload_words(), 36);
        assert_eq!(Bm1398FpgaMidstateMode::Four.payload_bytes(), 144);
        assert_eq!(Bm1398FpgaMidstateMode::Eight.log2_count(), 3);
        assert_eq!(Bm1398FpgaMidstateMode::Eight.payload_words(), 68);
        assert_eq!(Bm1398FpgaMidstateMode::Eight.payload_bytes(), 272);
    }

    #[test]
    fn nonce_address_is_normalized_through_the_chain_plan() {
        let raw_address = 226u32;
        let nonce = raw_address << 17;
        assert_eq!(BM1398_FPGA_FIFO_SPEC.raw_chip_address(nonce), Some(226));
        assert_eq!(
            BM1398_FPGA_FIFO_SPEC.dense_chip_index(nonce, S19_PRO_NBP1901_ADDRESS_PLAN),
            Some(113)
        );

        let unassigned_nonce = 225u32 << 17;
        assert_eq!(
            BM1398_FPGA_FIFO_SPEC.dense_chip_index(unassigned_nonce, S19_PRO_NBP1901_ADDRESS_PLAN),
            None
        );
    }

    #[test]
    fn fifo_work_id_separates_raw_echo_logical_ring_and_slot_bits() {
        let fifo = BM1398_FPGA_FIFO_SPEC;
        assert_eq!(fifo.echoed_work_id_bits(), 16);
        assert_eq!(fifo.logical_work_id_bits(), 8);
        assert_eq!(
            fifo.encode_work_id(Bm1398FpgaMidstateMode::Four, 0x55, 3),
            Some(0x0157)
        );
        assert_eq!(
            fifo.decode_work_id(Bm1398FpgaMidstateMode::Four, 0x0157),
            Some((0x55, 3))
        );
        assert_eq!(
            fifo.decode_work_id(Bm1398FpgaMidstateMode::Eight, 0x0157),
            Some((0x2a, 7))
        );
        assert_eq!(
            fifo.decode_work_id(Bm1398FpgaMidstateMode::Four, 0x0400),
            None,
            "logical IDs beyond the 8-bit carrier ring must not mask-alias"
        );
    }

    #[test]
    fn malformed_internal_fifo_specs_fail_closed_without_shift_panics() {
        let invalid_shift = Bm1398FpgaFifoSpec {
            nonce_chip_address_shift: 32,
            ..BM1398_FPGA_FIFO_SPEC
        };
        assert_eq!(invalid_shift.raw_chip_address(u32::MAX), None);
        assert_eq!(
            invalid_shift.dense_chip_index(u32::MAX, S19_PRO_NBP1901_ADDRESS_PLAN),
            None
        );

        let invalid_width = Bm1398FpgaFifoSpec {
            echoed_work_id_bits: 16,
            logical_work_id_bits: 32,
            ..BM1398_FPGA_FIFO_SPEC
        };
        assert_eq!(
            invalid_width.encode_work_id(Bm1398FpgaMidstateMode::Eight, 1, 0),
            None
        );
        assert_eq!(
            invalid_width.decode_work_id(Bm1398FpgaMidstateMode::Eight, 1),
            None
        );

        let unsupported_mode = Bm1398FpgaFifoSpec {
            supported_modes: [Bm1398FpgaMidstateMode::Four, Bm1398FpgaMidstateMode::Four],
            ..BM1398_FPGA_FIFO_SPEC
        };
        assert_eq!(
            unsupported_mode.encode_work_id(Bm1398FpgaMidstateMode::Eight, 1, 0),
            None
        );
        assert_eq!(
            unsupported_mode.decode_work_id(Bm1398FpgaMidstateMode::Eight, 1),
            None
        );
    }
}
