//! BM1391 ASIC driver (Antminer S15 / T15) — release-scoped, evidence-backed
//! ChipDriver adapter.
//!
//! The BM1391 is Bitmain's **7 nm** SHA-256 die (Nov 2018). Identity and wire
//! facts below are bound to the two held exact stock releases
//! (`bm1391_carrier_profile`: S15 `1.92992.0.14`, T15 `1.92992.0.13`, both
//! December 2019, cgminer SHA-256-pinned per release) plus the Bitmain S17
//! factory jig, which carries the full unstripped BM1391 protocol
//! (`BM1391_set_config`, `set_BM1391_freq`, `BM1391_set_baud`, `BM1391_set_TM`,
//! `BM1391_chain_inactive`, `BM1391_set_address`, `single_BM1391{P,S}_open_core`).
//! Campaign evidence index:
//! evidence/r04/SOURCE_NOTE.md` (this driver's constant table).
//!
//! ## Carrier boundary (deliberate, evidence-based — mirrors BM1396/R06)
//!
//! The exact held binaries drive the STOCK flat FPGA fabric: work is thirteen
//! TW words through `+0x40`/`+0x44`, returns are two words read at `+0x10`/
//! `+0x14`, ASIC register commands publish a 12-byte BC frame through the
//! `+0xc0` command buffer, and jobs are SHA-padded coinbase + merkle branches
//! DMA'd into DDR job buffers (stock `cgminer` S15 `FUN_00046780` /
//! T15 `FUN_000467b4`; `bm1391_stock_return` / `bm1391_stock_work`). That
//! carrier is OWNED by the retained HAL owner
//! `dcentrald_hal::platform::stock_bm1391::Transport` (native-transport tests
//! v30; 112 selected HAL tests) and the production runtime
//! `dcentrald::bm1391_mining` (linked BM1391 suite v3). **No held artifact maps
//! BM1391 onto the Braiins-FIFO `FpgaChain` ABI** (C43/Braiins bitstreams are a
//! different fabric — `FPGA_GENERAL_I2C`/TW layout vs Braiins FIFO), so
//! `init_chain`, `set_frequency` and `send_work` REFUSE on that carrier while
//! naming the owning artifacts (`CARRIER_REFUSAL` / `FREQ_REFUSAL` /
//! `WORK_TX_REFUSAL`). The pure stock sequences are exposed here as single-
//! sourced plans so callers and tests can verify bytes without any I/O.
//!
//! ## Per-board facts stay separate (never one global geometry)
//!
//! S15 and T15 share one carrier family but the exact releases enforce
//! DIFFERENT per-present-chain register-0 response counts: S15 compares exactly
//! **72** (`FUN_00041248`, compare at `0x4171c`), T15 exactly **60**
//! (`FUN_00041250`, compare at `0x4172c`). The S15 maintenance guide's repeated
//! 60-chip statements conflict with its own six-per-domain line (which implies
//! 72) — no universal physical geometry exists, so the driver is
//! release-bound: S15 (address interval 3, 72 replies) and T15 (address
//! interval 4, 60 replies) never cross-apply (`admit_stock_response_count`).
//! The T15-only conditional PIC selector swap (chain 1↔2 at stock route state
//! `0x0100`) is likewise per-release (`pic_selector`).
//!
//! ## Voltage ownership (per-board APW8 callsites)
//!
//! Voltage is APW8-adjacent, driven by the stock FPGA general-I2C fabric
//! register `+0x30` (device `0x10`, register-prefix `0x02`, one DAC payload
//! byte; `bm1391_apw8_evidence::BM1391_APW8_SOFTWARE`), with PER-BOARD traced
//! callsites (`BM1391_APW8_FUNCTIONS`: S15 `set_iic_power_by_voltage` at file
//! offset `0x7257c`, T15 at `0x72544`). GPIO907 software levels are recorded
//! (`power_on`=0, `power_off`=1) but the physical load/polarity are unproved.
//! `ChipDriver::set_voltage` routes through the pure ownership SSOT
//! (`voltage_rail::chip_driver_set_voltage_admission`), which refuses BEFORE
//! any I/O — the real route is the retained
//! `VoltageRailAdapterKind::Bm1391RetainedOwner` (HAL `PicApplication`).
//!
//! ## BM1391 baud generation (the key family fact, jig-verified)
//! BM1391 is **Generation-1** (like BM1387/S9): the chain UART rate is a 5-bit
//! code in **MiscControl (reg 0x18) bits 12:8** off CLKI — there is **no PLL
//! baud reclock** (unlike Gen-2 BM1397/BM1398 PLL3/0x68, Gen-3 PLL1/0x60):
//! `MiscCtrl = (MiscCtrl & 0xffffe0ff) | (code << 8)`. On the exact releases
//! the same code is mirrored into the stock controller `+0xc0` low six bits
//! (`bm1391_apw8_evidence` sibling evidence: population transition S15
//! `0x439e0..0x43bd0` / T15 `0x43a00..0x43bf0`; codes cold `0x1a`, operational
//! `0`). See `BM13XX_BAUD_FAMILY_MAP.md`.
//!
//! ## Command/wire format (jig-verified, = BM1397 family, NOT BM1387)
//! Register write = `[0x51 (bcast) | 0x41 (single), 0x09, asic_addr, reg,
//! data_BE[4], CRC5]` (`BM1391_set_config`); register 0x14 payloads are
//! bit-reversed per byte (stock bit-swap; HAL `register_frame`).
//!
//! ## Promotion status
//! This `impl ChipDriver` stays registered **Scaffold-only** (`ChipRegistry::
//! production().detect(0x1391)` is `None`; drivers/mod.rs pins). It performs
//! no I/O itself: carrier mutation, voltage, reset, census and teardown belong
//! to the retained HAL/runtime owners. Refusals below name the exact owning
//! artifact or the missing evidence.
//!
//! References:
//!   - `dcentrald-common::bm1391_{carrier_profile,stock_startup,stock_work,
//!     stock_return,share_qualification,apw8_evidence,safety_contract}`
//!   - `dcentrald-hal/src/platform/stock_bm1391*.rs` (retained carrier)
//!   - `dcentrald/src/bm1391_mining*.rs` (production runtime)
//!   - S17 jig `single-board-test`
//!   - `BM13XX_BAUD_FAMILY_MAP.md`

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::Result;
use dcentrald_common::bm1391_carrier_profile::{
    self, Bm1391Gpio907StockIntent, Bm1391StockRelease,
};
use dcentrald_common::bm1391_stock_return::{
    decode_bm1391_stock_fpga_return, Bm1391StockFpgaReturn, Bm1391StockReturnDecodeError,
    BM1391_STOCK_FPGA_RETURN_RECORD_LEN,
};
use dcentrald_common::bm1391_stock_startup::{
    self, Bm1391StockRegisterWrite, Bm1391StockStartupError,
};
use dcentrald_hal::fpga_chain::FpgaChain;
use dcentrald_hal::platform::stock_bm1391::Model;

/// BM1391 chip ID. Read from the chip-address register (reg 0x00, bits 31:16);
/// both exact releases compare register-0 `value >> 16 == 0x1391`
/// (S15 `FUN_00041248` at `0x417b4..0x417b8`, T15 `FUN_00041250` at
/// `0x417c4..0x417c8`; `dcentrald-silicon-profiles/src/bm1391_stock_fw.rs`).
pub const CHIP_ID: u16 = 0x1391;

/// No model-independent BM1391 chain count exists in the held corpus.
///
/// The S15 maintenance guide is internally inconsistent: its hashrate formula
/// names 60 chips while its 12 voltage domains of six chips imply 72. The held
/// S15 and T15 stock releases enumerate 72 and 60 replies respectively, but
/// release-scoped software counts do not establish a universal physical chain
/// fallback for S11/S15/T15. The generic driver therefore has no default; use
/// [`Bm1391Driver::stock_expected_chips`] for a release-scoped count.
pub const DEFAULT_CHIPS_PER_CHAIN: Option<u8> = None;

/// SHA-256 cores per BM1391 chip.
///
/// Bitmain's S17 factory jig passes `256` to every BM1391
/// `calculate_core_number` path (`single_BM1391_calculate_timeout_and_baud`
/// and both BHB91601/91603 variants); the official S15 maintenance guide
/// independently states `frequency × chip core number 256 × chip number 60`
/// on page 11 (`bm1391_stock_fw::S15_CORES_PER_CHIP`). The core-count
/// corroboration remains useful even though the guide's chip-count statements
/// do not establish release-independent geometry.
const CORES_PER_CHIP: u32 = 256;

/// No runtime mutation is authorized through this trait surface.
///
/// The stock carrier, voltage, reset, and teardown owners live in
/// `dcentrald_hal::platform::stock_bm1391` and `dcentrald::bm1391_mining`;
/// this adapter performs no I/O.
pub const RUNTIME_MUTATION_AUTHORIZED: bool = false;

/// Exact stock-carrier return-record length: two 32-bit FPGA return words
/// (`+0x10`/`+0x14` on the flat fabric) assembled into one 8-byte record by
/// both held cgminer binaries (S15 `FUN_00046780`, T15 `FUN_000467b4`;
/// `bm1391_stock_return::BM1391_STOCK_FPGA_RETURN_RECORD_LEN`). This replaces
/// the retired 9-byte raw-ASIC-wire placeholder: the verified return layer on
/// the exact S15/T15 carrier is the FPGA-normalized 8-byte record.
pub const RESPONSE_BYTES: usize = BM1391_STOCK_FPGA_RETURN_RECORD_LEN;
pub const RESPONSE_BYTES_VERIFIED: bool = true;

/// Cold host/ASIC rate code `0x1a` — the cached stock MiscCtrl file default
/// `0x3a01` carries ASIC baud field `0x1a` and both releases' population
/// transitions preserve it as the pre-switch rate
/// (`evidence/r04/engine-dma-population-baud-v1.md`; HAL `StartupBaud::Cold`).
pub const STOCK_BAUD_CODE_COLD: u8 = 0x1a;

/// Operational rate code `0` — board reinitialization S15 `0x4a294` /
/// T15 `0x4a2dc` calls the complete population wrapper with rate `0` after
/// census/address setup (`engine-dma-population-baud-v1.md`; HAL
/// `StartupBaud::Operational`). No held BM1391 artifact states its wire Hz.
pub const STOCK_BAUD_CODE_OPERATIONAL: u8 = 0x0;

/// Why BM1391 cold start / frequency programming refuses this chain object.
const CARRIER_REFUSAL: &str = "BM1391 cold start (chain-inactive, addressing, \
     baud transition, PLL, core open) is proven only on the exact S15/T15 stock \
     flat FPGA carrier through the retained HAL owner \
     dcentrald_hal::platform::stock_bm1391::Transport (chain_inactive, \
     configure_addresses, set_population_asic_and_fpga_baud, program_pll, \
     initialize_cores_in_cold_engine) composed by dcentrald::bm1391_mining. No \
     held artifact maps BM1391 onto the Braiins-FIFO FpgaChain ABI (the C501 \
     stock fabric and Braiins C43 fabric are different bitstreams); refusing \
     instead of inventing a route (evidence/r04/SOURCE_NOTE.md)";

/// Why BM1391 `send_work` refuses the `MiningWork` midstate shape.
const WORK_TX_REFUSAL: &str = "BM1391 exact work TX is the stock-format job \
     publication: SHA-padded coinbase + 32-byte merkle branches written to DDR \
     job buffers 0x200000/0x210000 with the scalar spine of \
     dcentrald_common::bm1391_stock_work::plan_bm1391_stock_job_publication, \
     published through the retained HAL owner \
     dcentrald_hal::platform::stock_bm1391::Transport::publish_work (thirteen \
     TW words) and owned by dcentrald::bm1391_mining_work::WorkDispatcher. The \
     stock FPGA computes its own midstate from the coinbase, so ChipDriver::\
     MiningWork's precomputed-midstate FIFO shape has no held BM1391 mapping";

/// Why `set_voltage` never mutates through the legacy PIC16 surface.
const VOLTAGE_REFUSAL_OWNER: &str = "BM1391 APW8-adjacent voltage belongs to \
     VoltageRailAdapterKind::Bm1391RetainedOwner (dcentrald-hal \
     stock_bm1391::PicApplication over the stock FPGA general-I2C fabric \
     register +0x30); ChipDriver::set_voltage refuses via the pure ownership \
     SSOT before any I/O (voltage_rail::chip_driver_set_voltage_admission)";

/// BM1391 register addresses — JIG-VERIFIED from `BM1391_set_config` call sites;
/// the PLL pair and ticket mask are re-confirmed in the exact releases
/// (`bm1391_stock_startup` register constants; HAL `register_frame` reg 0x14).
pub mod regs {
    /// Chip address register (contains ChipID in bits 31:16).
    pub const CHIP_ADDRESS: u8 = 0x00;
    /// PLL0 parameter — hash clock PLL (jig `set_BM1391_freq` writes reg 0x08;
    /// exact releases: `bm1391_stock_startup::BM1391_STOCK_PLL_REGISTER`).
    pub const PLL0: u8 = 0x08;
    /// Ticket mask — hardware difficulty filter (jig `BM1391_set_TM` writes reg
    /// 0x14, BIT-REVERSED via `bit_swap_table`).
    pub const TICKET_MASK: u8 = 0x14;
    /// Misc control — 5-bit rate code at bits 12:8 (jig `BM1391_set_baud`;
    /// exact-release population transition preserves all non-`0x1f00` bits).
    pub const MISC_CONTROL: u8 = 0x18;
    /// Core register control (indirect core access; `BM1391_enable_core_clock`).
    pub const CORE_REG_CTRL: u8 = 0x3C;
    /// PLL0 output divider (jig `set_BM1391_freq` writes reg 0x70; exact
    /// releases: `bm1391_stock_startup::BM1391_STOCK_PLL_DIVIDER_REGISTER`).
    pub const PLL0_DIVIDER: u8 = 0x70;
}

/// Pack the 5-bit stock rate code into a MiscControl word, preserving every
/// other bit — the exact stock transform (population wrapper: "the ASIC value
/// preserves all prior MiscCtrl bits except `0x1f00`"; jig
/// `BM1391_set_baud: MiscCtrl = (MiscCtrl & 0xffffe0ff) | (baud_index << 8)`).
pub const fn misc_ctrl_baud_word(current: u32, code: u8) -> u32 {
    // Lead landing fix: `u32::from` is not const-stable on this toolchain; the
    // widening cast is identical for u8 -> u32.
    (current & !0x1f00) | (((code as u32) & 0x1f) << 8)
}

/// BM1391 driver — release-bound (S15 or T15); the profiles never merge.
pub struct Bm1391Driver {
    release: Model,
}

/// Bridge: carrier-profile release enum → startup-helper release enum. Both
/// module-local enums describe the same two held December-2019 releases
/// (`dcentrald-common`); this is a type bridge, not a second evidence path.
const fn startup_release(
    release: Bm1391StockRelease,
) -> dcentrald_common::bm1391_stock_startup::Bm1391StockRelease {
    match release {
        Bm1391StockRelease::S15December2019 => {
            dcentrald_common::bm1391_stock_startup::Bm1391StockRelease::S15_20191213
        }
        Bm1391StockRelease::T15December2019 => {
            dcentrald_common::bm1391_stock_startup::Bm1391StockRelease::T15_20191213
        }
    }
}

/// Bridge: HAL model → carrier-profile release enum (same two held releases).
const fn carrier_release(model: Model) -> Bm1391StockRelease {
    match model {
        Model::S15 => Bm1391StockRelease::S15December2019,
        Model::T15 => Bm1391StockRelease::T15December2019,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1391ResponseCountError {
    /// Observed per-present-chain register-0 count is not the exact release
    /// count. S15 and T15 counts never cross-apply (F02 row R-am1-t15:
    /// "distinct population cannot borrow S15").
    CountMismatch {
        expected: u32,
        observed: u32,
    },
}

impl Default for Bm1391Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm1391Driver {
    /// S15-default driver (canonical first model). Use [`Self::for_release`]
    /// for the exact T15 profile; counts, intervals and PIC selectors are
    /// strictly release-bound.
    pub fn new() -> Self {
        Self::for_release(Model::S15)
    }

    pub fn for_release(release: Model) -> Self {
        Self { release }
    }

    pub fn release(&self) -> Model {
        self.release
    }

    /// Exact per-release stock response count for one present chain:
    /// S15 **72**, T15 **60** (`bm1391_stock_fw` compare sites `0x4171c` /
    /// `0x4172c`; carrier profile `BM1391_{S15,T15}_STOCK_EXPECTED_CHIPS_PER_CHAIN`).
    pub fn stock_expected_chips(&self) -> u8 {
        self.release.expected_chips()
    }

    /// Model address stride from the exact all-chain setup writes: S15 `3`
    /// (at `0x439b4`), T15 `4` (at `0x439d4`). Address ladders cover
    /// `256 / interval` slots (85 / 64) — more slots than actual chips.
    pub fn address_interval(&self) -> u8 {
        self.release.address_interval()
    }

    /// Exact board target registered in `board_desc` (`am1-s15` / `am1-t15`).
    pub fn board_target(&self) -> &'static str {
        self.release.board_target()
    }

    /// Admit one observed per-present-chain register-0 population against the
    /// EXACT release count. This is release-scoped software-profile admission
    /// only — it never proves physical chip inventory or board identity.
    pub fn admit_stock_response_count(
        &self,
        observed: u32,
    ) -> std::result::Result<(), Bm1391ResponseCountError> {
        let expected = u32::from(self.stock_expected_chips());
        if observed == expected {
            Ok(())
        } else {
            Err(Bm1391ResponseCountError::CountMismatch { expected, observed })
        }
    }

    /// Exact per-release PIC selector for a chain (`bm1391_carrier_profile::
    /// bm1391_stock_pic_selector`): S15 compiles the swap predicate to constant
    /// false (`0x20|chain` always); T15 swaps chains 1/2 only when that chain's
    /// stock route state is exactly `0x0100`. This is the per-board resolution
    /// of the controller selector — one release's geometry never imposes on
    /// the other.
    pub const fn pic_selector(&self, chain: u8, stock_route_state: u16) -> u8 {
        bm1391_carrier_profile::bm1391_stock_pic_selector(
            carrier_release(self.release),
            chain,
            stock_route_state,
        )
    }

    /// Exact per-release APW8 `set_iic_power_by_voltage` receipt
    /// (`bm1391_apw8_evidence::BM1391_APW8_FUNCTIONS`): returns the model
    /// label, file offset, and size of the traced function. The S15 and T15
    /// callsites are distinct functions in distinct binaries.
    pub const fn apw8_voltage_callsite(&self) -> (&'static str, u32, u32) {
        match self.release {
            Model::S15 => ("S15", 0x7257c, 0x158),
            Model::T15 => ("T15", 0x72544, 0x158),
        }
    }

    /// Exact stock APW8 DAC law (`bm1391_apw8_evidence::BM1391_APW8_SOFTWARE`
    /// slope/intercept; same computation as the runtime ramp
    /// `dcentrald/src/bm1391_mining_profile.rs::dac`): saturating
    /// `DAC = intercept − volts × slope` clamped to the 0..=255 payload byte.
    /// Units-verified is FALSE in the evidence; this is a software preimage,
    /// never a rail readback.
    pub fn apw8_dac_code(volts: f64) -> u8 {
        let software = &dcentrald_common::bm1391_apw8_evidence::BM1391_APW8_SOFTWARE;
        (software.conversion_intercept - volts * software.conversion_slope).clamp(0.0, 255.0) as u8
    }

    /// Exact stock working-voltage envelope in millivolts, from the stock
    /// tuning-policy tokens 1603..=2028 hundredths-of-a-volt
    /// (`bm1391_stock_startup::BM1391_STOCK_TUNING_VOLTAGE_TOKEN_{MIN,MAX}`).
    /// These tokens are stock software bounds, NOT measured rail limits.
    pub const fn apw8_stock_envelope_mv() -> (u16, u16) {
        (
            dcentrald_common::bm1391_stock_startup::BM1391_STOCK_TUNING_VOLTAGE_TOKEN_MIN * 10,
            dcentrald_common::bm1391_stock_startup::BM1391_STOCK_TUNING_VOLTAGE_TOKEN_MAX * 10,
        )
    }

    /// Exact factory rootfs voltage token in millivolts (S15 `1650` → 16.5 V,
    /// T15 `1850` → 18.5 V; stock divides the token by the double constant
    /// 100.0 — `bm1391_stock_startup::factory_voltage_token` /
    /// `bm1391_stock_voltage_token_mv`). Presence is not electrical-safety
    /// proof.
    pub const fn factory_voltage_token_mv(&self) -> u32 {
        dcentrald_common::bm1391_stock_startup::bm1391_stock_voltage_token_mv(
            startup_release(carrier_release(self.release)).factory_voltage_token(),
        )
    }

    /// Exact four-write operational PLL sequence (divider reg 0x70, PLL reg
    /// 0x08, twice) from the single-source planner
    /// (`bm1391_stock_startup::bm1391_stock_operational_pll_plan`). Data-only;
    /// programming belongs to the retained HAL owner.
    pub const fn stock_pll_write_plan(
        raw_pll_word: u32,
        divider: u8,
    ) -> std::result::Result<[Bm1391StockRegisterWrite; 4], Bm1391StockStartupError> {
        bm1391_stock_startup::bm1391_stock_operational_pll_plan(raw_pll_word, divider)
    }

    /// Validate a per-ASIC EEPROM frequency-index vector against the exact
    /// release size (S15 72 / T15 60 entries, indices 0..=178)
    /// (`bm1391_stock_startup::validate_bm1391_stock_frequency_indices`).
    pub fn validate_frequency_indices(
        &self,
        indices: Option<&[u8]>,
    ) -> std::result::Result<(), Bm1391StockStartupError> {
        bm1391_stock_startup::validate_bm1391_stock_frequency_indices(
            startup_release(carrier_release(self.release)),
            indices,
        )
    }

    /// Exact stock GPIO907 software level (power on = 0, off = 1) from
    /// `bm1391_carrier_profile::bm1391_gpio907_stock_level`. Software intent
    /// only: physical load and polarity are unproved.
    pub const fn gpio907_stock_level(intent: Bm1391Gpio907StockIntent) -> u8 {
        bm1391_carrier_profile::bm1391_gpio907_stock_level(intent)
    }

    /// Why `init_chain` / `set_frequency` refuse the Braiins-FIFO carrier.
    pub fn carrier_refusal_reason() -> &'static str {
        CARRIER_REFUSAL
    }

    /// Why `send_work` refuses the `MiningWork` midstate shape.
    pub fn work_tx_refusal_reason() -> &'static str {
        WORK_TX_REFUSAL
    }

    /// Why `set_voltage` refuses the legacy PIC16 surface (names the owner).
    pub fn voltage_refusal_owner() -> &'static str {
        VOLTAGE_REFUSAL_OWNER
    }

    /// Decode one 8-byte stock FPGA return record from its two 32-bit words
    /// (the values read at fabric `+0x10`/`+0x14`, little-endian bytes — the
    /// same mapping the HAL receiver assembles). Single source:
    /// `dcentrald_common::bm1391_stock_return::decode_bm1391_stock_fpga_return`.
    pub fn decode_return_record(
        word0: u32,
        word1: u32,
    ) -> std::result::Result<Bm1391StockFpgaReturn, Bm1391StockReturnDecodeError> {
        let mut record = [0u8; BM1391_STOCK_FPGA_RETURN_RECORD_LEN];
        record[..4].copy_from_slice(&word0.to_le_bytes());
        record[4..].copy_from_slice(&word1.to_le_bytes());
        decode_bm1391_stock_fpga_return(&record)
    }
}

/// Host-decoded nonce observation in the exact two-word format consumed by
/// Bitmain's held S17 `single-board-test` BM1391 jig.
///
/// This is evidence tooling, not an S15/T15 carrier contract. In particular,
/// it grants no FIFO address, reset GPIO, voltage, or work-submission authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S17JigNonceObservation {
    pub nonce: u32,
    pub chip_index: u8,
    pub core_index: u8,
    pub work_id: u16,
}

/// Decode the held S17 jig's `single_BM1391_check_nonce` two-word observation.
///
/// The decompiled jig uses word 0 bit 31 to distinguish nonces from register
/// replies, requires `(word0 & 0xe0) == 0x80`, extracts `work_id` from the high
/// halfword masked with `0x7fff`, takes the raw ASIC address from word 1's high
/// byte, divides it by the jig's chain address interval, and takes the core
/// index from word 1's low byte. Bounds are supplied by the caller because the
/// observation itself does not carry chain geometry.
pub fn decode_s17_jig_nonce_observation(
    raw: &[u32; 2],
    address_interval: u8,
    expected_chip_count: u8,
) -> Result<S17JigNonceObservation> {
    if address_interval == 0 {
        return Err(crate::AsicError::InvalidParameter(
            "BM1391 S17-jig decode requires a non-zero address interval".into(),
        ));
    }
    if expected_chip_count == 0 {
        return Err(crate::AsicError::InvalidParameter(
            "BM1391 S17-jig decode requires a non-zero expected chip count".into(),
        ));
    }

    let flags = raw[0];
    if flags & 0x8000_0000 == 0 {
        return Err(crate::AsicError::InvalidParameter(
            "BM1391 S17-jig observation is a register reply, not a nonce".into(),
        ));
    }
    if flags & 0x0000_00e0 != 0x0000_0080 {
        return Err(crate::AsicError::InvalidParameter(format!(
            "BM1391 S17-jig nonce flags are not admissible: 0x{:02x}",
            flags & 0xff
        )));
    }

    let raw_address = (raw[1] >> 24) as u8;
    let chip_index = raw_address / address_interval;
    if chip_index >= expected_chip_count {
        return Err(crate::AsicError::InvalidParameter(format!(
            "BM1391 S17-jig ASIC index {chip_index} is outside expected chain length {expected_chip_count}"
        )));
    }

    Ok(S17JigNonceObservation {
        nonce: raw[1],
        chip_index,
        core_index: raw[1] as u8,
        work_id: ((raw[0] >> 16) & 0x7fff) as u16,
    })
}

impl ChipDriver for Bm1391Driver {
    fn chip_id(&self) -> u16 {
        CHIP_ID
    }

    fn chip_name(&self) -> &'static str {
        "BM1391"
    }

    fn cores_per_chip(&self) -> u32 {
        CORES_PER_CHIP
    }

    fn response_length(&self) -> usize {
        // 8-byte stock FPGA return record (two words at +0x10/+0x14);
        // see RESPONSE_BYTES.
        RESPONSE_BYTES
    }

    fn default_baud(&self) -> u32 {
        // Cold rate code 0x1a (cached stock MiscCtrl default 0x3a01 → field
        // 0x1a; population transitions pre-switch at this code). The classic
        // 115200 boot rate is the family reading of code 0x1a; no BM1391 wire
        // capture pins the Hz, so the number is a conservative family value,
        // recorded in evidence/r04/SOURCE_NOTE.md's unverified list.
        115_200
    }

    fn max_baud(&self) -> u32 {
        // BM1391 baud is a 5-bit MiscControl rate CODE (Gen-1 divider; no PLL
        // reclock). The exact releases evidence codes cold 0x1a, raw
        // operational 0, and 1 — no held BM1391 artifact states any code's
        // wire Hz or a maximum rate, so the trait keeps the conservative
        // Gen-1 ceiling it has always carried (drivers/mod.rs registry pin).
        // Never program a rate from this number on the stock carrier: rates
        // change only through HAL StartupBaud code transitions.
        3_125_000
    }

    fn init_chain(&self, chain: &mut FpgaChain, _chip_count: u8, _freq_mhz: u16) -> Result<()> {
        // Named-owner refusal (see CARRIER_REFUSAL). The real sequence lives
        // in dcentrald::bm1391_mining::startup: quiet fans → PIC off →
        // heartbeats → GPIO source high → reset cycle → census → address
        // assignment → StartupObservation + operational baud transition →
        // cold engine + timeout ticks → per-chain PLL → thermal → core open →
        // DAC ramp → raw known-header qualification. None of it maps onto the
        // Braiins-FIFO FpgaChain ABI.
        Err(crate::AsicError::InitFailed {
            chain_id: chain.chain_id,
            detail: CARRIER_REFUSAL.to_string(),
        })
    }

    fn set_frequency(&self, chain: &mut FpgaChain, _chip_addr: u8, _freq_mhz: u16) -> Result<()> {
        // Named-owner refusal. The exact per-release frequency data is the
        // stock (configured MHz, clock divider, raw PLL MHz) profile table at
        // S15 0x9e530 / T15 0x9e450 (33 triples; engine-dma-runtime-policy
        // vectors) programmed per chain by HAL Transport::program_pll with a
        // PllSetting; the pure write plan is single-sourced in
        // Bm1391Driver::stock_pll_write_plan. No FpgaChain route exists.
        Err(crate::AsicError::InitFailed {
            chain_id: chain.chain_id,
            detail: CARRIER_REFUSAL.to_string(),
        })
    }

    fn set_voltage(&self, pic: &mut PicController, voltage_mv: u16) -> Result<()> {
        // Route through the pure ownership SSOT (same strangler as BM1396):
        // AsicProtocolIdentity::Bm1391 ownership is NOT ChipDriverPic, so this
        // refuses BEFORE any I/O. The real route is the retained
        // Bm1391RetainedOwner (HAL PicApplication::set_apw8_voltage, per-board
        // callsites from Bm1391Driver::apw8_voltage_callsite, DAC law
        // Bm1391Driver::apw8_dac_code, stock envelope
        // Bm1391Driver::apw8_stock_envelope_mv).
        let addr = pic.address();
        crate::voltage_rail_adapters::chip_driver_set_voltage_via_pic16_rail(
            dcentrald_common::board_desc::AsicProtocolIdentity::Bm1391,
            pic,
            voltage_mv,
        )
        .map_err(|e| crate::voltage_rail_adapters::voltage_rail_error_as_asic(e, addr))
    }

    fn send_work(&self, chain: &mut FpgaChain, _work: &MiningWork) -> Result<u16> {
        // Named-owner refusal (see WORK_TX_REFUSAL).
        Err(crate::AsicError::InitFailed {
            chain_id: chain.chain_id,
            detail: WORK_TX_REFUSAL.to_string(),
        })
    }

    fn decode_nonce(&self, raw: &[u32; 2]) -> Result<NonceResult> {
        // Exact stock return-record decode (see decode_return_record). The
        // BM1391 nonce branch of both held cgminer binaries selects records by
        // word0 bit 31 and binds them only when the stock valid bit (byte0
        // bit 7) is set; raw bit 6 is NOT tested in that branch (do not import
        // BM1396 CRC-error semantics — see bm1391_stock_return). The record
        // carries chain slot (bits 3:0), a 15-bit work id, and the nonce —
        // NO per-chip field, so chip_index stays u8::MAX (unknown) exactly as
        // NonceResult documents; work attribution happens host-side through
        // the 15-bit work id into the outstanding-work snapshot.
        match Self::decode_return_record(raw[0], raw[1])
            .map_err(|e| crate::AsicError::InvalidParameter(format!("BM1391 return: {e:?}")))?
        {
            Bm1391StockFpgaReturn::Register(_) => Err(crate::AsicError::InvalidParameter(
                "BM1391 return record is a register reply, not a nonce (word0 bit 31 clear)".into(),
            )),
            Bm1391StockFpgaReturn::Nonce(nonce) => {
                if !nonce.stock_valid {
                    return Err(crate::AsicError::InvalidParameter(
                        "BM1391 nonce record fails the stock valid bit (byte0 bit 7 clear); \
                         stock would not bind it"
                            .into(),
                    ));
                }
                Ok(NonceResult {
                    nonce: nonce.nonce,
                    chip_index: u8::MAX,
                    work_id: nonce.work_id,
                    solution_id: 0,
                    midstate_idx: 0,
                })
            }
        }
    }

    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32 {
        // Generic Braiins-FIFO divisor form (div = fpga_clock/(16*baud) − 1).
        // This is NOT the stock BM1391 control: on the exact carrier the rate
        // is the 5-bit code packed by misc_ctrl_baud_word and the +0xc0 low
        // bits, and carrier-bound operations refuse anyway. Kept so the trait
        // metadata stays total; never write it into the stock fabric.
        let div = fpga_clock_hz / (16 * target_baud.max(1));
        div.saturating_sub(1)
    }

    fn ctrl_reg_value(&self) -> u32 {
        // Stock fabric +0xc0 command-start template: bit 31 (command active)
        // | 0x0080_0000, before the chain selector is ORed in
        // (`(previous & 0xfff0_ffff) | 0x8080_0000 | (chain << 16)`, HAL
        // publish_command_locked; original S15 7c5e8 / T15 7c5b0). Never zero
        // (campaign rule). NOT a Braiins CTRL_REG word.
        0x8080_0000
    }

    fn job_interval_ms(&self, _chip_count: u8, _freq_mhz: u16) -> u32 {
        // Scheduling hint only (dispatch pacing), not a stock-derived
        // constant: the exact stock receiver cadence is owned by the runtime
        // polling loops (bm1391_mining_work::WorkDispatcher). Unchanged from
        // the prior scaffold value.
        1000
    }

    fn ticket_mask(&self, difficulty: u32) -> u32 {
        // G25 pure SSOT: BM1391_set_TM bit-swap (BitReversed for non-256
        // difficulties); the exact releases initialize broadcast reg 0x14 to
        // 0x3f and the raw qualification routine restores it (dcentrald
        // bm1391_mining::qualify_raw, original B82EC is 0x3f in both releases).
        dcentrald_common::ticket_mask_from_difficulty(
            dcentrald_common::TicketMaskEncoding::BitReversed,
            difficulty.max(1),
        )
    }

    fn pll_params(&self, freq_mhz: u16) -> PllConfig {
        // S17-jig table/solver preview (single source resolve_bm1391_pll).
        // The EXACT releases program per-chain PLLs from the stock profile
        // table (S15 0x9e530 / T15 0x9e450; 33 configured-MHz triples) via
        // Bm1391Driver::stock_pll_write_plan on the retained HAL owner. This
        // trait surface stays a pure metadata lookup.
        let sol = dcentrald_common::resolve_bm1391_pll(freq_mhz);
        PllConfig {
            fb_div: sol.fb_div,
            ref_div: sol.ref_div,
            post_div1: sol.post_div1,
            post_div2: sol.post_div2,
            reg_value: sol.pll0_register,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bm1391_identity_and_release_profiles_stay_separate() {
        let s15 = Bm1391Driver::new();
        let t15 = Bm1391Driver::for_release(Model::T15);
        assert_eq!(s15.chip_id(), 0x1391);
        assert_eq!(s15.chip_name(), "BM1391");
        assert_eq!(s15.board_target(), "am1-s15");
        assert_eq!(t15.board_target(), "am1-t15");
        // Exact release-scoped response counts: S15 72, T15 60. Never merged.
        assert_eq!(s15.stock_expected_chips(), 72);
        assert_eq!(t15.stock_expected_chips(), 60);
        assert_eq!(
            s15.stock_expected_chips(),
            bm1391_carrier_profile::BM1391_S15_STOCK_EXPECTED_CHIPS_PER_CHAIN
        );
        assert_eq!(
            t15.stock_expected_chips(),
            bm1391_carrier_profile::BM1391_T15_STOCK_EXPECTED_CHIPS_PER_CHAIN
        );
        // Address intervals from the exact all-chain setup writes.
        assert_eq!(s15.address_interval(), 3);
        assert_eq!(t15.address_interval(), 4);
        // Universal geometry stays refused.
        assert_eq!(DEFAULT_CHIPS_PER_CHAIN, None);
        assert!(!RUNTIME_MUTATION_AUTHORIZED);
        assert_eq!(s15.cores_per_chip(), 256);
    }

    #[test]
    fn stock_response_count_admission_never_cross_applies() {
        let s15 = Bm1391Driver::new();
        let t15 = Bm1391Driver::for_release(Model::T15);
        assert_eq!(s15.admit_stock_response_count(72), Ok(()));
        assert_eq!(t15.admit_stock_response_count(60), Ok(()));
        // Wrong-board counts must not cross-apply (F02 R-am1-t15 lane gap).
        assert_eq!(
            s15.admit_stock_response_count(60),
            Err(Bm1391ResponseCountError::CountMismatch {
                expected: 72,
                observed: 60
            })
        );
        assert_eq!(
            t15.admit_stock_response_count(72),
            Err(Bm1391ResponseCountError::CountMismatch {
                expected: 60,
                observed: 72
            })
        );
        // Partial-init populations never pass.
        assert!(matches!(
            s15.admit_stock_response_count(71),
            Err(Bm1391ResponseCountError::CountMismatch { .. })
        ));
        assert!(matches!(
            t15.admit_stock_response_count(59),
            Err(Bm1391ResponseCountError::CountMismatch { .. })
        ));
    }

    #[test]
    fn per_board_pic_selector_and_apw8_callsites_are_release_exact() {
        let s15 = Bm1391Driver::new();
        let t15 = Bm1391Driver::for_release(Model::T15);
        // S15: swap predicate compiled to constant false.
        assert_eq!(s15.pic_selector(1, 0x0100), 0x21);
        assert_eq!(s15.pic_selector(2, 0x0100), 0x22);
        // T15: conditional chain 1/2 swap at stock route state 0x0100.
        assert_eq!(t15.pic_selector(1, 0), 0x21);
        assert_eq!(t15.pic_selector(1, 0x0100), 0x22);
        assert_eq!(t15.pic_selector(2, 0x0100), 0x21);
        // Per-board APW8 callsites (BM1391_APW8_FUNCTIONS receipts).
        assert_eq!(s15.apw8_voltage_callsite(), ("S15", 0x7257c, 0x158));
        assert_eq!(t15.apw8_voltage_callsite(), ("T15", 0x72544, 0x158));
        // Factory tokens: S15 1650, T15 1850 (hundredths of a volt → mV).
        assert_eq!(s15.factory_voltage_token_mv(), 16_500);
        assert_eq!(t15.factory_voltage_token_mv(), 18_500);
        // Stock tuning envelope 1603..=2028 cV → 16030..20280 mV.
        assert_eq!(Bm1391Driver::apw8_stock_envelope_mv(), (16_030, 20_280));
    }

    #[test]
    fn apw8_dac_law_matches_stock_conversion_and_packable_command() {
        // SSOT slope/intercept (BM1391_APW8_SOFTWARE); 20.0 V → 17 in the
        // exact runtime ramp computation.
        let software = dcentrald_common::bm1391_apw8_evidence::BM1391_APW8_SOFTWARE;
        assert_eq!(software.conversion_slope, 59.931_506_85);
        assert_eq!(software.conversion_intercept, 1215.894_44);
        assert!(!software.conversion_units_verified);
        assert_eq!(Bm1391Driver::apw8_dac_code(20.0), 17);
        assert_eq!(Bm1391Driver::apw8_dac_code(0.0), 255, "saturates high");
        // Saturation below 0 V and at the top of the f64 domain.
        assert_eq!(Bm1391Driver::apw8_dac_code(-100.0), 255);
        assert_eq!(Bm1391Driver::apw8_dac_code(100.0), 0);
        // The exact FPGA general-I2C base word is reproducible from the
        // single-source packer: device 0x10, field 1, prefix write of
        // register 0x02, no payload byte.
        let prefix = bm1391_carrier_profile::pack_bm1391_general_i2c_command(
            bm1391_carrier_profile::Bm1391GeneralI2cCommandFields {
                device_selector: software.i2c_device_address,
                field_27_26: 1,
                read: software.read_direction,
                write_data: Some(software.register_address),
                payload: 0,
            },
        )
        .unwrap();
        assert_eq!(prefix, software.packed_command_base_without_payload);
        assert_eq!(software.packed_command_base_without_payload, 0x0520_0200);
    }

    #[test]
    fn stock_rate_codes_and_misc_ctrl_transform_are_exact() {
        assert_eq!(STOCK_BAUD_CODE_COLD, 0x1a);
        assert_eq!(STOCK_BAUD_CODE_OPERATIONAL, 0);
        // Preserves every non-0x1f00 bit (population wrapper transform):
        // 0x3a01 has baud bits 0x1a00, so code 0 must clear them to 0x2001.
        assert_eq!(misc_ctrl_baud_word(0x3a01, 0), 0x2001);
        assert_eq!(misc_ctrl_baud_word(0x0000_0000, 0x1a), 0x0000_1a00);
        assert_eq!(misc_ctrl_baud_word(0xffff_ffff, 0x1a), 0xffff_faff);
        // Code is masked to five bits.
        assert_eq!(misc_ctrl_baud_word(0, 0x3a), misc_ctrl_baud_word(0, 0x1a));
    }

    #[test]
    fn stock_pll_plan_and_frequency_index_validation_are_single_sourced() {
        // Solver-fallback plan: divider 0x70 = 0x0f0f_0f0e, PLL 0x08 =
        // 0x4078_0111, written twice each.
        let plan =
            Bm1391Driver::stock_pll_write_plan(0x0078_0111, 0x0f).expect("fallback plan");
        assert_eq!(
            plan,
            [
                Bm1391StockRegisterWrite {
                    register: 0x70,
                    value: 0x0f0f_0f0e
                },
                Bm1391StockRegisterWrite {
                    register: 0x08,
                    value: 0x4078_0111
                },
                Bm1391StockRegisterWrite {
                    register: 0x70,
                    value: 0x0f0f_0f0e
                },
                Bm1391StockRegisterWrite {
                    register: 0x08,
                    value: 0x4078_0111
                },
            ]
        );
        assert_eq!(
            Bm1391Driver::stock_pll_write_plan(0, 0),
            Err(Bm1391StockStartupError::ZeroPllDivider)
        );
        // Release-sized frequency index vectors: 72 for S15, 60 for T15.
        let s15 = Bm1391Driver::new();
        let t15 = Bm1391Driver::for_release(Model::T15);
        assert_eq!(s15.validate_frequency_indices(Some(&[178_u8; 72])), Ok(()));
        assert_eq!(t15.validate_frequency_indices(Some(&[0_u8; 60])), Ok(()));
        assert!(matches!(
            s15.validate_frequency_indices(Some(&[0_u8; 60])),
            Err(Bm1391StockStartupError::WrongFrequencyIndexCount { expected: 72, observed: 60 })
        ));
        assert!(matches!(
            t15.validate_frequency_indices(Some(&[179_u8; 60])),
            Err(Bm1391StockStartupError::FrequencyIndexOutOfRange { .. })
        ));
        assert_eq!(
            s15.validate_frequency_indices(None),
            Err(Bm1391StockStartupError::MissingFrequencyIndices)
        );
    }

    #[test]
    fn jig_verified_register_map_and_return_record_shape() {
        assert_eq!(regs::PLL0, 0x08);
        assert_eq!(regs::PLL0_DIVIDER, 0x70);
        assert_eq!(regs::TICKET_MASK, 0x14);
        assert_eq!(regs::MISC_CONTROL, 0x18);
        assert_eq!(
            dcentrald_common::BM1391_S17_JIG_PLL_FALLBACK_200M,
            0xC078_0111
        );
        // The return record is the 8-byte FPGA-normalized layer.
        assert_eq!(RESPONSE_BYTES, 8);
        assert!(RESPONSE_BYTES_VERIFIED);
        assert_eq!(RESPONSE_BYTES, BM1391_STOCK_FPGA_RETURN_RECORD_LEN);
        assert_eq!(Bm1391Driver::new().response_length(), 8);
        // Metadata surfaces.
        assert_eq!(Bm1391Driver::new().default_baud(), 115_200);
        assert_eq!(Bm1391Driver::new().max_baud(), 3_125_000);
        assert_eq!(Bm1391Driver::new().ctrl_reg_value(), 0x8080_0000);
        assert_eq!(Bm1391Driver::new().job_interval_ms(72, 500), 1000);
        // GPIO907 stock software intent only.
        assert_eq!(Bm1391Driver::gpio907_stock_level(Bm1391Gpio907StockIntent::PowerOn), 0);
        assert_eq!(Bm1391Driver::gpio907_stock_level(Bm1391Gpio907StockIntent::PowerOff), 1);
        assert!(
            !bm1391_carrier_profile::BM1391_GPIO907_PHYSICAL_LOAD_PROVEN,
            "GPIO907 physical load is unproved"
        );
    }

    #[test]
    fn stock_nonce_decode_maps_the_exact_fields() {
        // Captured-style record: word0 bit 31 + valid bit, chain slot 2,
        // 15-bit work id 0x1234; word1 is the nonce. Bit 6 is NOT tested in
        // the stock nonce branch (no BM1396 CRC-error refusal here).
        let word0: u32 =
            (1 << 31) | (0x1234 << 16) | (1 << 7) | (1 << 6) | 2;
        let word1: u32 = 0x89ab_cdef;
        let result = Bm1391Driver::new()
            .decode_nonce(&[word0, word1])
            .expect("stock-valid nonce");
        assert_eq!(result.nonce, 0x89ab_cdef);
        assert_eq!(result.work_id, 0x1234);
        // The BM1391 stock nonce record carries no chip field.
        assert_eq!(result.chip_index, u8::MAX);
        assert_eq!(result.solution_id, 0);
        assert_eq!(result.midstate_idx, 0);
    }

    #[test]
    fn decode_refuses_register_replies_and_non_stock_valid_nonces() {
        // Register reply (bit 31 clear): not a nonce.
        let register_word: u32 = (2 << 29) | (0x1d << 24) | (0x72 << 16) | (0x40 << 8) | 3;
        let err = Bm1391Driver::new()
            .decode_nonce(&[register_word, 0x1391_0000])
            .expect_err("register reply refused");
        assert!(err.to_string().contains("register reply"), "{err}");
        // Nonce-shaped but valid bit clear: stock would not bind it.
        let invalid: u32 = (1 << 31) | (0x1234 << 16) | 2;
        let err = Bm1391Driver::new()
            .decode_nonce(&[invalid, 1])
            .expect_err("stock-invalid nonce refused");
        assert!(err.to_string().contains("valid bit"), "{err}");
    }

    #[test]
    fn s17_jig_and_stock_decoders_apply_independent_flag_rules() {
        // Synthetic words exercise the exact held-jig bit extraction. They are
        // not presented as a captured S15/T15 nonce.
        let raw = [0x9234_0080, 0x3000_00a5];
        let decoded = decode_s17_jig_nonce_observation(&raw, 0x10, 4).unwrap();
        assert_eq!(
            decoded,
            S17JigNonceObservation {
                nonce: 0x3000_00a5,
                chip_index: 3,
                core_index: 0xa5,
                work_id: 0x1234,
            }
        );
        // The exact-release stock decoder decodes the same words by its OWN
        // bit rules (bit 31 + valid bit) — jig acceptance never unlocked it,
        // and the two codecs stay independent.
        let stock = Bm1391Driver::new().decode_nonce(&raw).expect("stock rules");
        assert_eq!(stock.nonce, 0x3000_00a5);
        assert_eq!(stock.work_id, 0x1234);
        assert_eq!(stock.chip_index, u8::MAX, "stock record carries no chip");
        // A word that fails BOTH codecs (no valid bit, bad jig flags) is
        // refused by the exact-release decoder too.
        assert!(Bm1391Driver::new().decode_nonce(&[0x9234_0040, 0]).is_err());
    }

    #[test]
    fn s17_jig_nonce_observation_rejects_non_nonce_flags_and_bad_geometry() {
        assert!(decode_s17_jig_nonce_observation(&[0x1234_0080, 0], 1, 1).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_00c0, 0], 1, 1).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_0080, 0], 0, 1).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_0080, 0], 1, 0).is_err());
        assert!(decode_s17_jig_nonce_observation(&[0x9234_0080, 0x4000_0000], 0x10, 4).is_err());
    }

    #[test]
    fn refusals_name_their_owners() {
        let carrier = Bm1391Driver::carrier_refusal_reason();
        assert!(carrier.contains("stock_bm1391::Transport"), "{carrier}");
        assert!(carrier.contains("FpgaChain"), "{carrier}");
        let work = Bm1391Driver::work_tx_refusal_reason();
        assert!(work.contains("publish_work"), "{work}");
        assert!(work.contains("MiningWork"), "{work}");
        assert!(work.contains("plan_bm1391_stock_job_publication"), "{work}");
        let voltage = Bm1391Driver::voltage_refusal_owner();
        assert!(voltage.contains("Bm1391RetainedOwner"), "{voltage}");
        assert!(voltage.contains("+0x30"), "{voltage}");
    }

    #[test]
    fn voltage_ownership_ssot_refuses_before_io() {
        // The exact same SSOT the trait method routes through: Bm1391 is not
        // a ChipDriverPic chip, so set_voltage refuses without touching the
        // (unconstructed) controller.
        let admission = dcentrald_common::voltage_rail::chip_driver_set_voltage_admission(
            dcentrald_common::board_desc::AsicProtocolIdentity::Bm1391,
        );
        assert!(admission.is_err(), "Bm1391 set_voltage must refuse via SSOT");
    }
}
