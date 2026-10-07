//! BM1396 exact-protocol chip driver for S17e / T17e (am2 Zynq, stock-FPGA
//! carrier), derived from held evidence only.
//!
//! Identity/wire proof: exact signed production `bmminer` binaries enforce
//! register-zero high word `0x1396` and the unified BM139x CRC5 command
//! frames (`CONFIRMED_MULTI_FIRMWARE`; not a live DCENT bench result).
//! Constants live in `dcentrald-common::bm1396_contract` and are cited to
//! `file@offset` there; this driver only binds them to the `ChipDriver`
//! surface. Campaign evidence index:
//! execution/evidence/r06/SOURCE_NOTE.md` (this driver's constant table).
//!
//! Carrier boundary (deliberate, evidence-based): the exact held binaries
//! drive the STOCK FPGA fabric — register-mapped BC command `0xc0`, return
//! words `0x10`/`0x14` (`S17e/cgminer.dec/get_return_nonce@44D18.c`),
//! job-buffer DMA at `0x20_0000`/`0x21_0000`. The proven DCENT cold start,
//! operational baud (S17e 6 Mbaud / T17e 3 Mbaud), factory calibration and
//! final PLL are owned by the retained HAL owner
//! `dcentrald_hal::platform::stock_bm1396::Transport` (R06 HAL53..HAL159;
//! `native-cold-core-implementation-v1.md` and successors). No held artifact
//! maps BM1396 onto the Braiins-FIFO `FpgaChain` ABI, so `init_chain`,
//! `set_frequency` and `send_work` REFUSE on that carrier instead of
//! inventing a route (see `CARRIER_REFUSAL` / `WORK_TX_REFUSAL`).
//!
//! Work attribution: return records are 8 bytes (two words); nonce validity
//! is word0 bit 31 + byte0 bit7, CRC-error is byte0 bit6, work id is word0
//! bits [30:16] masked to 15 bits (`HIWORD(buf[0]) & 0x7FFF`), nonce is
//! word1, chain is word0 [3:0]
//! (`get_nonce_and_register@2AA04.c`; codec `bm1396_work::
//! bm1396_decode_nonce_record`, model-bound 135/1 versus 78/3 geometry).
//!
//! Promotion status: this `impl ChipDriver` is NOT registered in
//! `ChipRegistry` — `ChipRegistry::production().detect(0x1396)` stays `None`
//! and 0x1396 is never silently mapped onto BM1397 (PR-056 pin in
//! `drivers/mod.rs`). Registration is a Lead-reviewed decision after the R06
//! proof lands. Campaign rules honored: never write 0 to a FPGA control
//! register (`ctrl_reg_value` returns the stock-fabric MAIN_CONTROL RUN bit);
//! BM1396 is not BM1387 (CMD headers 0x51/0x52/0x53/0x40/0x41/0x42, not
//! 0x58/0x54/0x55); chip counts stay separate per model (135 vs 78).

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::Result;
use dcentrald_common::{
    admit_bm1396_present_chain_enumeration, bm1396_decode_nonce_record, resolve_bm1396_pll,
    ticket_mask_from_difficulty, AsicProtocolIdentity, Bm1396EnumerationAdmission,
    Bm1396EnumerationError, Bm1396Model, Bm1396NonceDecodeError, Bm1396NonceRecord,
    TicketMaskEncoding, TransportOp, BM1396_FPGA_MAIN_CONTROL_RUN_BIT,
    BM1396_PLL_FAILURE_REGISTER, BM1396_RETURN_RECORD_LEN, BM1396_STARTUP_BAUD,
    BM1396_WIRE_CHIP_ID,
};
use dcentrald_hal::fpga_chain::FpgaChain;

/// Why BM1396 cold start / frequency programming refuses this chain object.
const CARRIER_REFUSAL: &str = "BM1396 cold start and PLL programming are proven \
     only on the stock-FPGA carrier through the retained HAL owner \
     dcentrald_hal::platform::stock_bm1396::Transport (R06 HAL53..HAL159: cold \
     registers, operational baud S17e 6M / T17e 3M, factory calibration, final \
     PLL). No held artifact maps BM1396 onto the Braiins-FIFO FpgaChain ABI \
     (evidence/r06/SOURCE_NOTE.md); refusing instead of inventing a route";

/// Why BM1396 work submission refuses the `MiningWork` midstate shape.
const WORK_TX_REFUSAL: &str = "BM1396 exact work TX is the stock-format job \
     packet (0x52 header, 0x58-byte fixed body + coinbase + merkle branches, \
     dcentrald_common::bm1396_work::Bm1396JobPacket) published through the HAL \
     job-buffer DMA spine (bm1396_plan_ordered_job_dispatch) by the retained \
     work owner; ChipDriver::MiningWork carries precomputed midstates that \
     BM1396 computes internally and no held artifact maps the Braiins midstate \
     work-TX FIFO format onto BM1396";

pub struct Bm1396Driver {
    model: Bm1396Model,
}

// Keep the wire-frame helpers on the same host-testable contract used by
// BoardDesc and admission code. These helpers do not perform I/O.
pub use dcentrald_common::{
    bm1396_baud_plan, bm1396_read_register_frame, bm1396_reset_address_frame,
    bm1396_set_address_frame, bm1396_validate_voltage_response,
    bm1396_voltage_dac_in_vendor_envelope, bm1396_voltage_request_frame,
    bm1396_write_register_frame,
};

impl Default for Bm1396Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm1396Driver {
    /// S17e-default driver (canonical first model). Use [`Self::for_model`]
    /// for exact T17e attribution; nonce decoding is strictly model-bound.
    pub fn new() -> Self {
        Self::for_model(Bm1396Model::S17e)
    }

    pub fn for_model(model: Bm1396Model) -> Self {
        Self { model }
    }

    pub fn model(&self) -> Bm1396Model {
        self.model
    }

    /// Exact per-present-chain population: S17e 135, T17e 78
    /// (`bm1396_contract.rs:19/:27`; S17e count compare `0x82ad4`, T17e
    /// `0x8397c`). The profiles are never merged or guessed.
    pub fn chips_per_chain(&self) -> u16 {
        self.model.expected_chips_per_present_chain()
    }

    /// Model address stride: S17e 1 (`0x80ea0`), T17e 3 (`0x81d48`).
    pub fn address_interval(&self) -> u8 {
        self.model.address_interval()
    }

    /// Why `init_chain` / `set_frequency` refuse the Braiins-FIFO carrier
    /// (names the owning HAL artifacts). Exposed so tests and callers can
    /// pin/report the refusal without constructing a chain.
    pub fn carrier_refusal_reason() -> &'static str {
        CARRIER_REFUSAL
    }

    /// Why `send_work` refuses the `MiningWork` midstate shape (names the
    /// owning HAL work artifacts).
    pub fn work_tx_refusal_reason() -> &'static str {
        WORK_TX_REFUSAL
    }

    /// Validate one present-chain enumeration against the exact signed model
    /// contract (chip id 0x1396 and the model's exact 135/78 population).
    pub fn admit_present_chain_enumeration(
        &self,
        observed_chip_id: u16,
        observed_chip_count: u16,
    ) -> std::result::Result<Bm1396EnumerationAdmission, Bm1396EnumerationError> {
        admit_bm1396_present_chain_enumeration(self.model, observed_chip_id, observed_chip_count)
    }

    /// Decode one 8-byte return record (two 32-bit return words, LE bytes)
    /// under this driver's model. Same word→record mapping as the HAL
    /// receiver assembler (`stock_bm1396_receiver.rs`).
    pub fn decode_return_record(
        &self,
        word0: u32,
        word1: u32,
    ) -> std::result::Result<Bm1396NonceRecord, Bm1396NonceDecodeError> {
        let mut record = [0u8; BM1396_RETURN_RECORD_LEN];
        record[..4].copy_from_slice(&word0.to_le_bytes());
        record[4..].copy_from_slice(&word1.to_le_bytes());
        bm1396_decode_nonce_record(self.model, &record)
    }

    /// Exact on-wire PLL register word for a solved target: the pure solver
    /// value with bit 30 forced (mode bits `0x4000_0000` per the PLL ramp
    /// producer; `native-pll-ramp-source-v1.md`). Extracted from the pure
    /// double-write plan so the transform stays single-sourced.
    pub fn resolved_pll_wire_value(target_mhz: u16) -> Option<u32> {
        let solution = resolve_bm1396_pll(f32::from(target_mhz), 0)?;
        let ops = dcentrald_common::plan_bm1396_pll_program_ops(solution, 0)?;
        match ops.as_slice() {
            [TransportOp::SendWriteRegBroadcastBm1397Plus { value, .. }, ..] => Some(*value),
            _ => None,
        }
    }

    /// Whether the exact signed-firmware pure PLL solver is admitted.
    /// (Carrier and electrical admission remain independently closed.)
    pub fn production_pure_pll_admitted() -> bool {
        dcentrald_common::bm1396_production_pure_pll_admitted()
    }

    /// Thin wrapper over the exact signed S17e/T17e pure PLL solver.
    pub fn resolve_pll(
        target_mhz: f32,
        old_register_value: u32,
    ) -> Option<dcentrald_common::Bm1396PllSolution> {
        dcentrald_common::resolve_bm1396_pll(target_mhz, old_register_value)
    }

    /// Exact pure primary-PLL double-write plan. Carrier admission stays
    /// closed, so this helper cannot energize hardware by itself.
    pub fn plan_frequency_program_ops(
        target_mhz: u16,
    ) -> Option<Vec<dcentrald_common::TransportOp>> {
        dcentrald_common::plan_bm1396_frequency_program_ops(target_mhz)
    }
}

impl ChipDriver for Bm1396Driver {
    fn chip_id(&self) -> u16 {
        // Register-zero high word required by both exact signed binaries
        // (bm1396_contract.rs:11; enumeration compares S17e@0x82a70,
        // T17e@0x83918).
        BM1396_WIRE_CHIP_ID
    }

    fn chip_name(&self) -> &'static str {
        "BM1396"
    }

    fn cores_per_chip(&self) -> u32 {
        // DELIBERATE REFUSAL — missing artifact: per-chip core topology is
        // UNPROVED. The exact signed binaries settle wire identity, CRC5 and
        // model chain counts, not core count; the silicon catalog records
        // `cores: 0` for the same reason (dcentrald-silicon-profiles/
        // src/asics.rs, AsicChip::Bm1396: "Per-chip core count remains
        // unproved"). No CORE_NUM byte, open-core sweep count, or held
        // maintenance-guide statement exists for BM1396. Return the catalog
        // value (0) so no hashrate prediction can silently inherit another
        // die's geometry (e.g. BM1397's 672).
        // Lead landing fix 2026-09-11: return the catalog value directly —
        // dcentrald-silicon-profiles is a dev-dependency only, and a metadata
        // literal must not force it into the production dependency graph.
        // (Catalog: dcentrald-silicon-profiles/src/asics.rs, AsicChip::Bm1396,
        // cores == 0.)
        0
    }

    fn response_length(&self) -> usize {
        // 8-byte return record = return words at fabric offsets 0x10/0x14
        // (get_return_nonce@44D18.c reads axi_fpga_addr[4]/[5];
        // bm1396_work.rs BM1396_RETURN_RECORD_LEN; HAL receiver assembles
        // exactly these two words per record).
        BM1396_RETURN_RECORD_LEN
    }

    fn default_baud(&self) -> u32 {
        // Exact signed startup baud (bm1396_contract.rs BM1396_STARTUP_BAUD;
        // operational switch vectors start from the fixed 115200 default).
        BM1396_STARTUP_BAUD
    }

    fn max_baud(&self) -> u32 {
        // Highest model-fixed operational baud proven in the exact binaries:
        // S17e requests 6 Mbaud, T17e 3 Mbaud (HAL stock_bm1396_baud.rs,
        // 52 original callers; native-operational-baud-vectors-v1: S17e
        // baud=6000000 selector 0x03 divisor 7). bm1396_baud_plan also
        // carries 12/25 Mbaud selectors, but no held operational caller uses
        // them, so the driver ceiling stays at the highest proven rate.
        6_000_000
    }

    fn init_chain(&self, chain: &mut FpgaChain, _chip_count: u8, _freq_mhz: u16) -> Result<()> {
        Err(crate::AsicError::InitFailed {
            chain_id: chain.chain_id,
            detail: CARRIER_REFUSAL.to_string(),
        })
    }

    fn set_frequency(&self, chain: &mut FpgaChain, _chip_addr: u8, _freq_mhz: u16) -> Result<()> {
        Err(crate::AsicError::InitFailed {
            chain_id: chain.chain_id,
            detail: CARRIER_REFUSAL.to_string(),
        })
    }

    fn set_voltage(&self, pic: &mut PicController, voltage_mv: u16) -> Result<()> {
        // P1-2 / ADR-0010: BM1396 voltage ownership is
        // HashboardFramedEndpointEvidenceOnly (voltage_rail.rs:176) — the
        // shared admission below refuses BEFORE any I/O. The real route is
        // the framed I2C 0x11 endpoint (55 aa 06 83 frames, 1800..=2100 cV,
        // DAC = (91849 - 43*cV)/120), owned by the VoltageRail adapter
        // family (Bm1396I2c11EvidenceOnly), not the PIC16 rail.
        let addr = pic.address();
        crate::voltage_rail_adapters::chip_driver_set_voltage_via_pic16_rail(
            AsicProtocolIdentity::Bm1396,
            pic,
            voltage_mv,
        )
        .map_err(|e| crate::voltage_rail_adapters::voltage_rail_error_as_asic(e, addr))
    }

    fn send_work(&self, chain: &mut FpgaChain, _work: &MiningWork) -> Result<u16> {
        Err(crate::AsicError::InitFailed {
            chain_id: chain.chain_id,
            detail: WORK_TX_REFUSAL.to_string(),
        })
    }

    fn decode_nonce(&self, raw: &[u32; 2]) -> Result<NonceResult> {
        // Exact return-record decode (see module docs). chip_index is the
        // dense per-model ordinal (wire address / interval, bounds-checked
        // against 135/78); work_id is the 15-bit outstanding-table index.
        // BM1396 return records carry no midstate-slot or solution field
        // (job snapshots live in the FPGA outstanding table / host binding),
        // so both stay 0 rather than inventing fields.
        let record = self.decode_return_record(raw[0], raw[1]).map_err(|e| {
            crate::AsicError::InvalidParameter(format!("BM1396 return record: {e:?}"))
        })?;
        Ok(NonceResult {
            nonce: record.nonce,
            chip_index: u8::try_from(record.chip_ordinal).unwrap_or(u8::MAX),
            work_id: record.work_id,
            solution_id: 0,
            midstate_idx: 0,
        })
    }

    fn baud_reg_value(&self, target_baud: u32, _fpga_clock_hz: u32) -> u32 {
        // The stock fabric baud register (offset 0x3c) takes per-byte-lane
        // SELECTORS, not divisors (bm1396_baud_plan: 115200→0x1a, 1.5M→0x01,
        // 3M→0x00, 6M→0x03, 12M→0x04, 25M→0x05, repeated across all four
        // lanes under preserve mask 0xc0c0_c0c0), so fpga_clock_hz is not an
        // input. Unsupported values reproduce the exact stock fallback
        // (selector 0x1a, i.e. 115200) — the binaries map every unrecognized
        // configured baud there even after computing a different ASIC
        // divisor. Operational callers MUST pre-validate with
        // dcentrald_common::bm1396_baud_plan (which refuses) because this
        // desynchronizing fallback is silently wrong on a typo.
        match bm1396_baud_plan(target_baud, 0, 0) {
            Ok(plan) => plan.fpga_register_value,
            Err(unsupported) => {
                tracing::warn!(
                    baud = unsupported.baud,
                    "BM1396: unsupported baud has no exact signed-firmware \
                     selector; returning the stock 0x1a fallback. Pre-validate \
                     with dcentrald_common::bm1396_baud_plan."
                );
                0x1a1a_1a1a
            }
        }
    }

    fn ctrl_reg_value(&self) -> u32 {
        // STOCK fabric MAIN_CONTROL (offset 0x100) RUN bit — NOT the
        // Braiins CTRL_REG layout (am1 bit4 BM139X / am2 ctrl_am2 words do
        // not exist on this fabric; do not write this into fpga_chain
        // REG_CTRL). The cold path requires RUN observed CLEAR before init,
        // and the retained work owner sets RUN when publishing jobs
        // (bm1396_contract.rs BM1396_FPGA_MAIN_CONTROL_RUN_BIT;
        // native-cold-core-implementation-v1.md). Never zero: the campaign
        // rule forbids writing 0 to a FPGA control register.
        BM1396_FPGA_MAIN_CONTROL_RUN_BIT
    }

    fn job_interval_ms(&self, _chip_count: u8, _freq_mhz: u16) -> u32 {
        // The exact binaries poll/receive on a 1 ms cadence:
        // get_nonce_and_register@2AA04.c runs `cgsleep_ms(1)` per loop, and
        // the R06 receivers drain/observe on the same 1 ms cadence
        // (BM1396_FPGA_WORK_READY_DELAY_CALL_VALUE = 1000 us;
        // native-cold-core-implementation-v1.md — 1 ms drain replaces the
        // monolithic 300 ms wait).
        1
    }

    fn ticket_mask(&self, difficulty: u32) -> u32 {
        // Bit-reversed vendor encoding (same bit_swap LUT family as the S17
        // jig BM1397 set_TM). Golden: the exact cold spine broadcasts
        // register 0x14 = 0xfe, i.e. difficulty 128 under this encoding
        // (HAL stock_bm1396_cold.rs, 18 original cold spines;
        // native-cold-core-implementation-v1.md). 0x1396 is not yet in
        // try_ticket_mask_encoding_for_chip_id (integration patch filed);
        // the encoding is pinned directly here.
        ticket_mask_from_difficulty(TicketMaskEncoding::BitReversed, difficulty)
    }

    fn pll_params(&self, freq_mhz: u16) -> PllConfig {
        // Exact signed solver (pll_model.rs resolve_bm1396_pll; register
        // encoding fbdiv<<16 | refdiv<<8 | 16*pd1 | pd2 per
        // get_pllparam_divider@225D8.c, VCO 2000..3200). reg_value is the
        // exact ON-WIRE program word (bit 30 forced; the ramp producer
        // forces mode bits 0x4000_0000 — native-pll-ramp-source-v1.md).
        // Unattainable targets mirror the vendor -1 outcome with the failure
        // word 0x0078_0111: callers MUST treat it as refuse-to-program (the
        // Option-shaped safe path is Bm1396Driver::plan_frequency_program_ops).
        match (
            resolve_bm1396_pll(f32::from(freq_mhz), 0),
            Self::resolved_pll_wire_value(freq_mhz),
        ) {
            (Some(solution), Some(wire_value)) => PllConfig {
                fb_div: solution.dividers().fb_div,
                ref_div: solution.dividers().ref_div,
                post_div1: solution.dividers().post_div1,
                post_div2: solution.dividers().post_div2,
                reg_value: wire_value,
            },
            _ => PllConfig {
                fb_div: 0,
                ref_div: 0,
                post_div1: 0,
                post_div2: 0,
                reg_value: BM1396_PLL_FAILURE_REGISTER,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_signed_bm1396_read_frames_pin_headers_order_and_crc5() {
        assert_eq!(
            bm1396_read_register_frame(true, 0x00, 0x00),
            [0x52, 0x05, 0x00, 0x00, 0x0a]
        );
        assert_eq!(
            bm1396_read_register_frame(false, 0x2a, 0x18),
            [0x42, 0x05, 0x2a, 0x18, 0x1c]
        );
    }

    #[test]
    fn exact_signed_bm1396_write_frames_pin_big_endian_value_and_crc5() {
        assert_eq!(
            bm1396_write_register_frame(true, 0x00, 0x18, 0x1234_5678),
            [0x51, 0x09, 0x00, 0x18, 0x12, 0x34, 0x56, 0x78, 0x0a]
        );
        assert_eq!(
            bm1396_write_register_frame(false, 0x2a, 0x08, 0x4068_0221),
            [0x41, 0x09, 0x2a, 0x08, 0x40, 0x68, 0x02, 0x21, 0x03]
        );
    }

    #[test]
    fn exact_signed_address_reset_and_assignment_frames_are_pinned() {
        assert_eq!(bm1396_reset_address_frame(), [0x53, 0x05, 0x00, 0x00, 0x03]);
        assert_eq!(bm1396_set_address_frame(134), [0x40, 0x05, 0x86, 0x00, 0x12]);
        assert_eq!(bm1396_set_address_frame(231), [0x40, 0x05, 0xe7, 0x00, 0x0b]);
        assert_eq!(bm1396_set_address_frame(252), [0x40, 0x05, 0xfc, 0x00, 0x02]);
    }

    #[test]
    fn driver_is_model_bound_and_never_silently_registered() {
        // The ChipDriver impl now EXISTS (R06), but the registration pin
        // stays: 0x1396 must never resolve through ChipRegistry until the
        // Lead-owned promotion lands (drivers/mod.rs PR-056 pin unchanged).
        let registry_source = include_str!("mod.rs");
        assert!(
            !registry_source.contains("register(Box::new(bm1396::Bm1396Driver"),
            "wire framing alone must not authorize BM1396 energization"
        );
        let this_source = include_str!("bm1396.rs");
        assert!(
            this_source.contains(concat!("impl Chip", "Driver for Bm1396Driver")),
            "R06: the evidence-cited ChipDriver impl must stay present"
        );
        // Both model profiles stay separate and exact (F02 tuple row
        // R-am2-t17e: BM1396, BHB16701, 78/present-chain, interval 3).
        assert_eq!(Bm1396Driver::new().chips_per_chain(), 135);
        assert_eq!(Bm1396Driver::new().address_interval(), 1);
        assert_eq!(
            Bm1396Driver::for_model(Bm1396Model::T17e).chips_per_chain(),
            78
        );
        assert_eq!(
            Bm1396Driver::for_model(Bm1396Model::T17e).address_interval(),
            3
        );
    }

    /// sim-hal-gated: the carrier refusals must hold on a live chain object
    /// of the Braiins-FIFO shape (never a silent BM1387-style init).
    #[cfg(all(test, feature = "sim-hal"))]
    #[test]
    fn carrier_bound_methods_refuse_the_braiins_fifo_chain() {
        use crate::drivers::MiningWork;
        use dcentrald_hal::platform::sim::SimModel;
        let mut chain = FpgaChain::open_sim_for_model(0, SimModel::S19Pro).unwrap();
        let driver = Bm1396Driver::new();
        let err = driver.init_chain(&mut chain, 135, 600).unwrap_err();
        assert!(err.to_string().contains("stock_bm1396::Transport"));
        let work = MiningWork {
            work_id: 0,
            fpga_midstate_cnt: 2,
            version: 0x2000_0000,
            nbits: 0x1702_3226,
            ntime: 0x5f00_6f4d,
            merkle_tail: [0; 4],
            midstates: vec![[0; 32]],
            merkle_root: [0; 32],
            prev_block_hash: [0; 32],
        };
        assert!(driver.send_work(&mut chain, &work).is_err());
        assert!(driver.set_frequency(&mut chain, 0xff, 600).is_err());
    }
}
