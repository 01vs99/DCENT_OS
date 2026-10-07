//! BM1393 (S9 SE / S9k) evidence-backed protocol driver.
//!
//! Every constant below is derived from held binaries, cited `file@offset`
//! against
//! (or the named capture). The pure frame/codec helpers are NOT duplicated
//! here — this driver wraps the single-source `dcentrald_common::s9se_*`
//! modules and the native executor facts (`dcentrald_common::bm1393_native`).
//!
//! ## Carrier truth (read before calling any `FpgaChain` method)
//!
//! The evidenced BM1393 carrier is the **stock C43 fabric** at `0x43C00000`
//! (VIL frames via `BC_COMMAND_BUFFER 0xC4` + `BC_WRITE_COMMAND 0xC0`,
//! 13-word work bursts via `TW_WRITE 0x40`, two-word return records via
//! `RETURN_NONCE0/1`). It is driven by
//! `dcentrald_hal::platform::c43_bm1393::transport::C43Transport` and
//! `dcentrald_common::bm1393_native::Bm1393Runtime` — that is the runnable
//! C43 lane. The [`ChipDriver`] trait carries `&mut FpgaChain`, which models
//! the **Braiins s9io FIFO fabric** (a different bitstream/ABI). No held
//! evidence puts BM1393 on the s9io fabric, so the `FpgaChain`-taking trait
//! methods refuse and name the exact missing artifact; everything
//! carrier-independent (identity, response width, PLL plan, ticket mask,
//! nonce decode, baud divisors) is real.
//!
//! Evidence base:
//! - Held S9k `cgminer.dec` (1,223 files; anchors cited inline below).
//! - Issue #2 live capture `0xC4 = 42 05 78 1c` (27-bit CRC5, addr 0x78).
//! - Campaign
//!   (stock-tw-machine-code-vectors.json, s9se-tw-machine-code-vectors.json).
//! - F02 tuple rows `R-am1-s9se` / `R-am1-s9k` (3x60 BM1393, 208 cores/chip).

use crate::drivers::{ChipDriver, MiningWork, NonceResult, PllConfig};
use crate::pic::PicController;
use crate::{AsicError, Result};
use dcentrald_common::s9se_enum::S9SE_ADDR_INTERVAL;
use dcentrald_common::s9se_nonce::{classify_return_record, classify_s9se_nonce, S9SeFifoRecord};
use dcentrald_common::s9se_pll::{
    decode_pll_word, get_index_from_high_pll, FREQ_HIGH_PLL_1393, FREQ_PLL_1393,
};
use dcentrald_hal::fpga_chain::FpgaChain;

pub const CHIP_ID: u16 = crate::bm1393::CHIP_ID;
/// 4 slot groups x 52 cores; `open_core_bm1393@21C12.c:42-53` walks
/// `core_id = 0..=51` x `slot = 0..=3` with `core_index = 52 * slot + core_id`
/// (one CORE_CMD enable frame per (slot, core) plus one dummy TW record per
/// core position).
pub const CORES_PER_CHIP: u32 = crate::bm1393::CORES_PER_CHIP as u32;
/// Normalized stock-FPGA return record: exactly **two 32-bit words**.
/// `get_return_nonce@46076.c` reads `buf[0] = axi[4]`, `buf[1] = axi[5]`;
/// `get_nonce_and_register@222DA.c:60-64` consumes records in that shape.
/// This is the width of the FPGA-normalized C43 record — NOT a raw ASIC UART
/// frame width (the stock fabric never hands drivers raw UART frames; see the
/// fabric warning in ).
pub const RESPONSE_BYTES: usize = 8;
pub const RESPONSE_BYTES_VERIFIED: bool = true;

/// Stock default UART baud **divisor** 26: `gBM1393_MISC_CONTROL_reg = 0x3A01`
/// (`set_default_uart_baud`; baud field `(0x3A01 >> 8) & 0x1F`, module
/// `dcentrald_common::s9se_regs::DEFAULT_BAUDDIV`).
pub const DEFAULT_BAUD_DIVISOR: u8 = dcentrald_common::s9se_regs::DEFAULT_BAUDDIV;
/// Stock working UART baud **divisor** 1: `set_working_uart_baud@14902.c`
/// is exactly `set_baud(1u, 1)`; `set_baud@14674.c` also latches the same
/// divisor into `BC_WRITE_COMMAND[5:0]` (`bauddiv & 0x3F | ret & 0xFFFFFFC0`).
pub const WORKING_BAUD_DIVISOR: u8 = dcentrald_common::s9se_timeout::WORKING_BAUDDIV;
/// Ticket-mask register 0x14 (`set_asic_ticket_mask@1492E.c`: `buf[3] = 20`),
/// payload is bswap + per-byte bit-reverse (`bit_swap_table`); stock default
/// mask `0x3F` (S9k `.data ticket_mask`; `dcentrald_common::s9se_timeout`).
pub const TICKET_MASK_REG: u8 = dcentrald_common::s9se_regs::REG_TICKET_MASK;
pub const DEFAULT_TICKET_MASK: u32 = dcentrald_common::s9se_timeout::DEFAULT_TICKET_MASK;

pub struct Bm1393Driver;

impl Default for Bm1393Driver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bm1393Driver {
    pub const fn new() -> Self {
        Self
    }

    /// Exact CRC5 wrapper for offline frame replay (poly 0x05, init 0x1F;
    /// `CRC5@1AE70.c`). Bit counts: 27 (short non-VIL), 32 (VIL short),
    /// 64 (VIL set-config) — every stock builder (`set_config_BM1393@13D92.c`,
    /// `chain_inactive@132F0.c`, `set_address@13508.c`) uses one of these.
    pub fn crc5(data: &[u8], bits: u32) -> u8 {
        crate::bm1393::crc5_bits(data, bits)
    }

    /// Operational PLL plan for a target frequency: `(vil_pll_word, divider)`.
    ///
    /// Rows are the held tables, not a synthesis: `FREQ_HIGH_PLL_1393` is the
    /// 33-row `freq_high_pll_1393` region of both production S9 SE ELFs and
    /// `FREQ_PLL_1393` is the 179-entry `freq_pll_1393` `.data` table of the
    /// unstripped S9k `cgminer` (`get_plldata_from_index`, `index > 178`
    /// fails; `dcentrald_common::s9se_pll`). Out-of-table targets use the
    /// stock bracketing walk (`get_index_from_high_pll`), never interpolation.
    /// The word programs the PLL VCO (register 0x08) and the divider register
    /// 0x70 divides it to the core clock — e.g. 500 MHz = 3000 MHz VCO / 6.
    /// The runtime applies these as the four-write divider@0x70 / word@0x08
    /// spine (`change_high_pll_test@22DEC.c` —
    /// `dcentrald_common::s9se_pll::pack_operational_pll_frames`), bounded to
    /// exact table rows by `Bm1393Runtime::new`.
    pub fn pll_plan(freq_mhz: u16) -> (u32, u8) {
        let index = get_index_from_high_pll(freq_mhz);
        let (_, divider, pll_mhz) = FREQ_HIGH_PLL_1393[usize::from(index)];
        let word = FREQ_PLL_1393
            .iter()
            .find(|row| row.0 == pll_mhz)
            .map(|row| row.1)
            .unwrap_or(dcentrald_common::s9se_pll::PLL_FALLBACK_WORD);
        (word, divider)
    }
}

/// Named-artifact refusal for the `FpgaChain`-carried trait methods.
///
/// BM1393 evidence exists only on the stock C43 fabric (raw-TW / BC buffer /
/// two-word return FIFO). No held evidence — ELF, bitstream, DTB or capture —
/// expresses BM1393 behind the Braiins s9io FIFO fabric that `FpgaChain`
/// models, so these methods cannot be implemented without inventing a
/// transport. The runnable executor is
/// `dcentrald_common::bm1393_native::Bm1393Runtime` over
/// `dcentrald_hal::platform::c43_bm1393::transport::C43Transport`.
/// Public so replay tests can pin the exact refusal contract without a
/// hardware handle.
pub fn refuse_no_s9io_carrier<T>(operation: &str) -> Result<T> {
    Err(AsicError::InvalidParameter(format!(
        "BM1393 {operation}: no s9io/Braiins-FIFO carrier exists for BM1393 in held evidence; \
         the evidenced carrier is the stock C43 fabric via dcentrald_common::bm1393_native::\
         Bm1393Runtime + dcentrald_hal::platform::c43_bm1393 (missing artifact: a BM1393 \
         s9io bitstream/DTB/ELF set)"
    )))
}

impl ChipDriver for Bm1393Driver {
    fn chip_id(&self) -> u16 {
        CHIP_ID
    }
    fn chip_name(&self) -> &'static str {
        "BM1393"
    }
    fn cores_per_chip(&self) -> u32 {
        CORES_PER_CHIP
    }
    fn response_length(&self) -> usize {
        RESPONSE_BYTES
    }
    fn default_baud(&self) -> u32 {
        // Divisor-anchored: stock programs divisor 26 for enumeration
        // (DEFAULT_BAUD_DIVISOR; `gBM1393_MISC_CONTROL_reg = 0x3A01`). The Hz
        // label is the crate's RE2 §4.1 family default; stock code itself
        // never converts divisors to Hz — the C43 lane programs divisors
        // directly (`C43Transport::set_baud`).
        crate::bm1393::BM1393_BAUD_DEFAULT
    }
    fn max_baud(&self) -> u32 {
        // Working operating point: divisor 1 (`set_working_uart_baud@14902.c`
        // = `set_baud(1, 1)`, WORKING_BAUD_DIVISOR). Hz label derived with the
        // family 25 MHz / (8 x (divisor + 1)) law, which reproduces BOTH stock
        // points (div 26 -> ~115,200; div 1 -> 1,562,500). Advisory only; the
        // wire truth is the divisor, never a synthesized Hz.
        1_562_500
    }

    fn init_chain(&self, _: &mut FpgaChain, _: u8, _: u16) -> Result<()> {
        // The evidenced init is `set_addr_one_chain@13896.c` (3x chain_inactive
        // @30 ms; 256/interval set_address + set_core_number pairs @2 ms/50 ms)
        // plus the `bitmain_soc_init` tail — all issued on the C43 BC-buffer
        // path and implemented by `Bm1393Runtime::start_inner` (EEPROM-PIC
        // custody, 5 heartbeats, PLL park spine, pre-open 13, working baud 1,
        // sensor MISC after baud, ticket mask 0x3f, clock delay, open-core 52,
        // stock timeout). Refusal names the missing s9io artifact.
        refuse_no_s9io_carrier("init_chain")
    }

    fn set_frequency(&self, _: &mut FpgaChain, _: u8, _: u16) -> Result<()> {
        // Frames are real ([`Self::pll_plan`] + `pack_operational_pll_frames`;
        // `set_unused_pll@22C3C.c` park: dividers 0x74/0x78/0x7C =
        // 0x0F0F0F0F, PLLs 0x60/0x64/0x68 = 0x8010F0F7); the s9io carrier is
        // not.
        refuse_no_s9io_carrier("set_frequency")
    }

    fn set_voltage(&self, _: &mut PicController, _: u16) -> Result<()> {
        // The evidenced S9 SE/S9k rail route is the framed dsPIC33EP16GS202
        // over the C43 shared IIC (`Bm1393PicCommand::Voltage` via
        // `C43Transport::pic`, 550 ms reply window per send_pic_cmd@70292),
        // bounded to 8500..=9500 mV against the CRC-bound factory EEPROM by
        // `Bm1393FactoryProfile::rail_code`. `PicController` here is the
        // AM1-S9 PIC16 dialect — a different controller. Missing artifact
        // (F02 `R-am1-s9se`): live S9 SE dsPIC IIC adapter ABI confirmation
        // against a physical board.
        Err(AsicError::InvalidParameter(
            "BM1393 set_voltage: evidenced route is the C43 framed dsPIC \
             (Bm1393PicCommand::Voltage + Bm1393FactoryProfile::rail_code), not the AM1 PIC16; \
             missing artifact: live S9 SE dsPIC IIC adapter ABI confirmation"
                .into(),
        ))
    }

    fn send_open_core_work(&self, _: &mut FpgaChain, _: u8) -> Result<u32> {
        // BM1393 REQUIRES open-core (208 cores, `open_core_bm1393@21C12.c`);
        // silently returning the trait default Ok(0) would skip a mandatory
        // step. Implemented only on the C43 fabric (`Bm1393Runtime::open_cores`:
        // per position, 4 bank enable frames 0x51/0x09/reg 0x3C/core_id/0x84/
        // 0xAA + one zero-payload 13-word dummy TW with word0
        // (chain<<16)|0x1000080, buffer-space gated per
        // `get_buffer_space@471F4.c`).
        refuse_no_s9io_carrier("send_open_core_work")
    }

    fn send_work(&self, _: &mut FpgaChain, _: &MiningWork) -> Result<u16> {
        // Encoder is real and machine-code-verified:
        // `dcentrald_common::bm1393_native::encode_bm1393_work` builds the
        // 13-word burst (word0 = 0x01800000 | chain<<16, word1 = 15-bit
        // work_id, words 2..5 = header tail BE, words 5..13 = midstate BE),
        // replayed bit-exact against both original S9k (d09c482f…) and S9 SE
        // encoders in `bm1393_native_tests.rs`. Transport is
        // `set_TW_write_command_vil@4717C.c` (word0 -> axi[16] 0x40, words
        // 1..=12 -> axi[17] 0x44) = `C43Transport::work`. The s9io FIFO
        // carrier is not evidenced.
        refuse_no_s9io_carrier("send_work")
    }

    fn decode_nonce(&self, raw: &[u32; 2]) -> Result<NonceResult> {
        // Real decode of the normalized two-word C43 return record.
        // Record grammar: `get_nonce_and_register@222DA.c:63-141` —
        //   bit31 clear  -> register (crc error = bit 0x40, crc5 = HIBYTE&0x1F,
        //                   chip = BYTE2, reg = BYTE1, chain = low nibble);
        //   bit31 + bit7 -> nonce: work_id = HIWORD & 0x7FFF, nonce3 = buf[1],
        //                   chain = low nibble.
        // Chip/core attribution: `nonce_calc@2214E.c` — chip =
        // HIBYTE(nonce3) / addrInterval (4), core = low byte; valid only when
        // chain <= 15, chip <= 59, core <= 207 and nonce3 != 0. The same
        // classify gate guards the production C43 ledger
        // (`dcentrald/src/c43_bm1393_work.rs::Ledger::validate`); the owning
        // chain is keyed there before decode, so it is not in NonceResult.
        let Some(S9SeFifoRecord::Nonce {
            chain,
            work_id,
            nonce3,
        }) = classify_return_record(raw[0], raw[1])
        else {
            return Err(AsicError::InvalidParameter(
                "BM1393 decode_nonce: record is not a nonce record (register record or \
                 unclassifiable FIFO pair; nonce records require bit31+bit7 set)"
                    .into(),
            ));
        };
        let place = classify_s9se_nonce(chain, nonce3, S9SE_ADDR_INTERVAL).map_err(|error| {
            AsicError::InvalidParameter(format!(
                "BM1393 nonce attribution refused per nonce_calc@2214E: {error:?} \
                 (chain={chain}, nonce3={nonce3:#010x})"
            ))
        })?;
        // BM1393 is single-midstate in this lane: the 15-bit work_id maps 1:1
        // to the submitted job (`encode_bm1393_work` word1), so both solution
        // slots stay 0. Core attribution remains available through
        // `classify_s9se_nonce` for telemetry.
        Ok(NonceResult {
            nonce: nonce3,
            chip_index: place.chip,
            work_id,
            solution_id: 0,
            midstate_idx: 0,
        })
    }

    fn baud_reg_value(&self, target_baud: u32, fpga_clock_hz: u32) -> u32 {
        // C43 programs a 6-bit divisor into BC_WRITE_COMMAND[5:0]
        // (`set_baud@14674.c`: `set_BC_write_command(bauddiv & 0x3F |
        // ret & 0xFFFFFFC0)`), with the MISC register carrying the same
        // divisor in bits [12:8] (`set_baud_one_chain@14284.c`:
        // `& 0xFFFFE0FF | (bauddiv << 8) & 0x1F00`).
        //
        // Stock pins exactly two operating points — divisor 26 and divisor 1 —
        // and never converts Hz to divisor. Inverting the family
        // 25 MHz/(8 x (divisor + 1)) law reproduces both:
        //   25_000_000 / (8 x 115_200) - 1 = 26 (DEFAULT_BAUD_DIVISOR)
        //   25_000_000 / (8 x 1_562_500) - 1 = 1  (WORKING_BAUD_DIVISOR)
        // so this helper answers with that law, clamped to the 6-bit field.
        // The production lane never routes through it: divisors are programmed
        // directly (`C43Transport::set_baud(1 | 26)`).
        let divisor = (fpga_clock_hz / (8 * target_baud.max(1))).saturating_sub(1);
        divisor.min(0x3F)
    }

    fn ctrl_reg_value(&self) -> u32 {
        // C43 hash-accelerator control is DHASH_ACC_CONTROL (axi[64], 0x100),
        // NOT the s9io CTRL_REG. Raw-TW/freq-scan mode contribution is 0x8100
        // with preserve mask 0xFFFF_70DF — `open_core_bm1393@21C12.c:38`:
        // `(opt_multi_version << 8) & 0xF00 | dhash & 0xFFFF70DF | 0x8000`
        // (V1 reviewer nit 2026-09-11: the preserve mask is 0xFFFF70DF, i.e.
        // 0xFFFF_70DF — the earlier comment's 0xFFFF7FDF spelling transposed
        // the nibbles; the applied value below was always correct)
        // (clears bit 5, sets bits 15 and 8 for opt_multi_version = 1), the
        // same word `C43Transport::configure` applies as
        // `previous & 0xffff_70df | 0x8100`. This value must ONLY be applied
        // with that read-modify-write through the C43 transport lane; a bare
        // write to a different fabric's CTRL_REG is a fabric-ABI violation
        // (and the s9io CTRL_REG must never be written 0 — see
        // ).
        crate::bm1393::DHASH_MODE_RAW_TW & 0xFFFF
    }

    fn job_interval_ms(&self, _: u8, _: u16) -> u32 {
        // Work is FIFO-space driven (per-chain bit in `BUFFER_SPACE`, axi[3],
        // `get_buffer_space@471F4.c`; `open_core_bm1393@21C12.c:58-86` spins
        // on it before each TW burst), so the interval is a fallback poll
        // cadence only. The C43 executor polls returns/dispatch every 5 ms
        // (`c43_bm1393_mining.rs::mining_loop`); stock's return pump spins at
        // 1 ms (`get_nonce_and_register@222DA.c:35`).
        5
    }

    fn ticket_mask(&self, difficulty: u32) -> u32 {
        // `set_asic_ticket_mask@1492E.c`: broadcast 0x51 0x09 frame, reg 20
        // (0x14), payload = bswap(mask) then per-byte `bit_swap_table`
        // reversal — the BitReversed encoding. Stock default mask 0x3F
        // (`.data ticket_mask`); the C43 runtime restores 0x3f after codec
        // discovery. Keep the shared pure SSOT encode.
        dcentrald_common::ticket_mask_from_difficulty(
            dcentrald_common::TicketMaskEncoding::BitReversed,
            difficulty.max(1),
        )
    }

    fn pll_params(&self, freq_mhz: u16) -> PllConfig {
        // Real held-table lookup (see [`Self::pll_plan`]). `reg_value` is the
        // VIL PLL word programmed at register 0x08; the field decode follows
        // `decode_pll_word` (fbdiv[23:16], refdiv[15:8], postdiv1[7:4],
        // postdiv2[3:0]). NOTE: BM1393 programming is the four-write
        // divider@0x70 / word@0x08 spine (`change_high_pll_test@22DEC.c`),
        // where the divider comes from the SAME FREQ_HIGH_PLL_1393 row —
        // `pll_plan` returns it. It is not a single-register 0x0C write.
        let (word, _divider) = Self::pll_plan(freq_mhz);
        let decoded = decode_pll_word(word);
        PllConfig {
            fb_div: u16::from(decoded.fbdiv),
            ref_div: decoded.refdiv,
            post_div1: decoded.postdiv1,
            post_div2: decoded.postdiv2,
            reg_value: word,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_metadata_is_evidence_backed() {
        let driver = Bm1393Driver::new();
        assert_eq!(driver.chip_id(), 0x1393);
        assert_eq!(driver.chip_name(), "BM1393");
        assert_eq!(driver.cores_per_chip(), 208);
        // open_core_bm1393@21C12.c: 4 slots x 52 cores.
        assert_eq!(CORES_PER_CHIP, 4 * 52);
        // get_return_nonce@46076.c: two-word FIFO record.
        assert_eq!(driver.response_length(), 8);
        assert!(RESPONSE_BYTES_VERIFIED);
        // set_working_uart_baud@14902.c / 0x3A01 MISC default.
        assert_eq!(DEFAULT_BAUD_DIVISOR, 26);
        assert_eq!(WORKING_BAUD_DIVISOR, 1);
        assert_eq!(TICKET_MASK_REG, 0x14);
        assert_eq!(DEFAULT_TICKET_MASK, 0x3F);
    }

    #[test]
    fn crc5_reproduces_the_issue2_capture_and_stock_bit_counts() {
        // Issue #2 live BC word0: 42 05 78 1c (27-bit CRC5).
        assert_eq!(Bm1393Driver::crc5(&[0x42, 0x05, 0x78], 27), 0x1c);
        // chain_inactive@132F0.c: CRC5 over 32 bits of [0x53, 0x05, 0, 0].
        let inactive = dcentrald_common::s9se_vil::pack_chain_inactive_vil();
        assert_eq!(inactive[4], Bm1393Driver::crc5(&inactive[..4], 32));
        // set_config_BM1393@13D92.c: CRC5 over 64 bits.
        let frame = dcentrald_common::s9se_vil::pack_set_config_single(0, 0x18, 0x3A01);
        assert_eq!(frame[8], Bm1393Driver::crc5(&frame[..8], 64));
    }

    #[test]
    fn nonce_decode_matches_get_nonce_and_register_grammar() {
        let driver = Bm1393Driver::new();
        // Nonce record: bit31 set, bit7 set, chain in low nibble,
        // work_id = HIWORD & 0x7FFF, nonce3 = word1. Same record shape the
        // native runtime replays (bm1393_native_tests.rs:
        // [0xff45_0082, 0x7800_1207] for chain 2 / work_id 0x7f45).
        // Chip attribution per nonce_calc@2214E: HIBYTE(0x78001207) = 0x78,
        // 0x78 / 4 = chip 30; core = 0x07.
        let decoded = driver
            .decode_nonce(&[0xff45_0082, 0x7800_1207])
            .expect("well-formed nonce record");
        assert_eq!(decoded.nonce, 0x7800_1207);
        assert_eq!(decoded.work_id, 0x7f45);
        assert_eq!(decoded.chip_index, 30);
        assert_eq!(decoded.solution_id, 0);
        assert_eq!(decoded.midstate_idx, 0);
    }

    #[test]
    fn nonce_decode_refuses_register_records_and_bad_attribution() {
        let driver = Bm1393Driver::new();
        // bit31 clear -> register record (get_nonce_and_register@222DA.c:63).
        assert!(driver.decode_nonce(&[0x0512_3402, 0x1111_2222]).is_err());
        // bit31 set, bit7 clear -> unclassifiable pair.
        assert!(driver.decode_nonce(&[0x8000_0000, 1]).is_err());
        // nonce3 high byte 0xF0 / 4 = chip 60 -> outside the 60-chip population.
        assert!(driver.decode_nonce(&[0xff45_0082, 0xF000_0001]).is_err());
        // Zero nonce is refused (nonce_calc@2214E: buf != 0).
        assert!(driver.decode_nonce(&[0xff45_0082, 0x0]).is_err());
        // Core byte 208+ is outside the 208-core chip (high byte 0x01 keeps
        // chip attribution valid so the core check is what fires).
        assert!(driver.decode_nonce(&[0xff45_0082, 0x1000_0000 | 208]).is_err());
    }

    #[test]
    fn pll_params_come_from_the_held_tables_with_row_divider() {
        let driver = Bm1393Driver::new();
        // 500 MHz is an exact FREQ_HIGH_PLL_1393 row: (500, 6, 3000) — VCO
        // word 0x780111 (the FREQ_PLL_1393 row for 3000) with divider 6.
        let pll = driver.pll_params(500);
        let (word, divider) = Bm1393Driver::pll_plan(500);
        assert_eq!(divider, 6);
        assert_eq!(word, 0x7801_11);
        assert_eq!(pll.reg_value, word);
        let decoded = dcentrald_common::s9se_pll::decode_pll_word(word);
        assert_eq!(pll.fb_div, u16::from(decoded.fbdiv));
        assert_eq!(pll.ref_div, decoded.refdiv);
        assert_eq!(pll.post_div1, decoded.postdiv1);
        assert_eq!(pll.post_div2, decoded.postdiv2);
        // 25 MHz x fbdiv / (refdiv x postdiv1 x postdiv2 x divider) = core.
        let rebuilt = dcentrald_common::s9se_pll::pll_output_mhz(word, divider).unwrap();
        assert!((rebuilt - 500.0).abs() < 0.5, "rebuilt={rebuilt}");
        // Out-of-table targets still resolve through the stock bracket walk
        // (get_index_from_high_pll), never panic.
        let _ = Bm1393Driver::pll_plan(493);
        let _ = Bm1393Driver::pll_plan(10_000);
        assert_eq!(
            Bm1393Driver::pll_plan(500).0,
            driver.pll_params(500).reg_value
        );
    }

    #[test]
    fn baud_law_reproduces_both_stock_operating_points() {
        let driver = Bm1393Driver::new();
        const ZYNQ_UART_CLOCK_HZ: u32 = 25_000_000;
        // divisor 26 default, divisor 1 working — set_baud@14674.c field.
        assert_eq!(
            driver.baud_reg_value(115_200, ZYNQ_UART_CLOCK_HZ),
            u32::from(DEFAULT_BAUD_DIVISOR)
        );
        assert_eq!(
            driver.baud_reg_value(1_562_500, ZYNQ_UART_CLOCK_HZ),
            u32::from(WORKING_BAUD_DIVISOR)
        );
        // Clamped to the 6-bit BC_WRITE_COMMAND field.
        assert!(driver.baud_reg_value(1, ZYNQ_UART_CLOCK_HZ) <= 0x3F);
    }

    #[test]
    fn carrier_bound_methods_refuse_with_named_artifacts() {
        // Pin the exact refusal contract shared by init_chain / set_frequency /
        // send_open_core_work / send_work: the missing s9io artifact and the
        // evidenced C43 executor are both named (fail-closed stays honest).
        let error = refuse_no_s9io_carrier::<()>("init_chain").unwrap_err();
        let message = error.to_string();
        assert!(message.contains("no s9io/Braiins-FIFO carrier"));
        assert!(message.contains("missing artifact"));
        assert!(message.contains("Bm1393Runtime"));
    }

    #[test]
    fn ticket_mask_is_bitreversed_per_stock_table() {
        let driver = Bm1393Driver::new();
        // 0x3f encodes to per-byte-reversed payload bytes in the frame
        // (set_asic_ticket_mask@1492E.c bit_swap_table path; pinned by
        // s9se_regs::tests). Here: encode stays the shared SSOT and the
        // register byte is 0x14.
        let mask = driver.ticket_mask(64);
        assert_eq!(
            mask,
            dcentrald_common::ticket_mask_from_difficulty(
                dcentrald_common::TicketMaskEncoding::BitReversed,
                64,
            )
        );
        // pack_ticket_mask_broadcast consumes the PLAIN mask word and performs
        // the per-byte reversal itself (s9se_regs.rs:90-93); feeding it the
        // already-encoded driver value double-reverses back to 0x3F. The wire
        // truth from set_asic_ticket_mask@1492E.c is the stock 0x3F word
        // framed as payload bytes 00 00 00 FC with register 0x14.
        let frame = dcentrald_common::s9se_regs::pack_ticket_mask_broadcast(63);
        assert_eq!(frame[3], TICKET_MASK_REG);
        assert_eq!(&frame[4..8], &[0x00, 0x00, 0x00, 0xFC]);
    }
}
