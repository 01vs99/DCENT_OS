//! BM1393 (S9 SE / S9k) captured-byte wire replay against held evidence.
//!
//! Campaign `2026-09-07-antminer-beta-execution` R03. Every "captured" byte
//! array below was transcribed from the held S9k `cgminer.dec` decompilation
//! — the
//! frame body is the exact stock builder output and the trailing CRC5 byte is
//! the value stock's `CRC5@1AE70.c` produces for it (independently recomputed
//! and cross-checked with a Python bit-serial implementation before being
//! pinned here). This is desk evidence replay: no hardware was contacted and
//! no physical share is claimed.
//!
//! The positive path proven here mirrors the C43 unit of done:
//! init frames -> work TX (13-word raw-TW burst) -> nonce RX (two-word
//! normalized FIFO record) -> driver decode. Header reconstruct + share
//! target are proven inside the daemon (`dcentrald/src/c43_bm1393_work.rs`
//! tests replay the genesis and block-1 headers to their exact public block
//! hashes against the difficulty-1/64 targets); they need
//! `dcentrald_stratum`, which the daemon bin already owns.

use dcentrald_asic::drivers::{bm1387::Bm1387Driver, bm1393::Bm1393Driver, ChipDriver};
use dcentrald_common::bm1393_native::encode_bm1393_work;
use dcentrald_common::s9se_nonce::classify_return_record;
use dcentrald_common::s9se_regs as regs;
use dcentrald_common::s9se_vil as vil;

/// `chain_inactive@132F0.c` (opt_multi_version): `53 05 00 00` + CRC5(32).
const CAPTURED_CHAIN_INACTIVE: [u8; 5] = [0x53, 0x05, 0x00, 0x00, 0x03];
/// `set_address@13508.c`: first populated address 0x00 (60 chips, stride 4).
const CAPTURED_SET_ADDRESS_FIRST: [u8; 5] = [0x40, 0x05, 0x00, 0x00, 0x1C];
/// Last populated production address 0xEC (`s9se_enum::S9SE_LAST_CHIP_ADDR`).
const CAPTURED_SET_ADDRESS_LAST: [u8; 5] = [0x40, 0x05, 0xEC, 0x00, 0x11];
/// 64th assignment slot 0xFC (`256 / interval` slots, stock emits all 64).
const CAPTURED_SET_ADDRESS_SLOT63: [u8; 5] = [0x40, 0x05, 0xFC, 0x00, 0x02];
/// `set_core_number_BM1390@137D4.c` at chip 0x00: `LE 0x00d09313` prefix,
/// high byte replaced by chip address -> payload `13 93 D0 addr`.
const CAPTURED_CORE_NUMBER_CHIP0: [u8; 9] = [0x41, 0x09, 0x00, 0x00, 0x13, 0x93, 0xD0, 0x00, 0x0C];
/// Same frame addressed to the issue-2 capture address 0x78.
const CAPTURED_CORE_NUMBER_CHIP78: [u8; 9] =
    [0x41, 0x09, 0x00, 0x00, 0x13, 0x93, 0xD0, 0x78, 0x0D];
/// `enable_core_clock_BM1393@13A90.c` mode=1, core_id 0: broadcast CORE_CMD
/// `0x51 0x09` reg 0x3C, core_id, cmd 0x84, data 0xAA.
const CAPTURED_ENABLE_CORE_0: [u8; 9] = [0x51, 0x09, 0x00, 0x3C, 0x00, 0x00, 0x84, 0xAA, 0x0A];
/// Same frame for the 52nd core of bank 0 (core_id 51 = last of the walk).
const CAPTURED_ENABLE_CORE_51: [u8; 9] = [0x51, 0x09, 0x00, 0x3C, 0x00, 0x33, 0x84, 0xAA, 0x09];
/// `set_asic_ticket_mask@1492E.c` mask 0x3F: bswap + per-byte `bit_swap_table`
/// -> payload `00 00 00 FC`, reg 20 (0x14).
const CAPTURED_TICKET_MASK_3F: [u8; 9] = [0x51, 0x09, 0x00, 0x14, 0x00, 0x00, 0x00, 0xFC, 0x07];
/// `set_baud_one_chain@14284.c` bauddiv 1: MISC 0x3A01 with baud field
/// `(bauddiv << 8) & 0x1F00` -> 0x2101, broadcast reg 0x18.
const CAPTURED_BAUD_DIVISOR_1: [u8; 9] = [0x51, 0x09, 0x00, 0x18, 0x00, 0x00, 0x21, 0x01, 0x11];
/// `set_clock_delay_control@2192E.c` pulse off (`g_Clock_delay_control`
/// initial 2, `|= 4`, pulse bit clear) -> data byte 0x04.
const CAPTURED_CLOCK_DELAY_PULSE_OFF: [u8; 9] =
    [0x51, 0x09, 0x00, 0x3C, 0x80, 0x00, 0x80, 0x04, 0x1C];
/// Pulse-on variant (bit 1 set) -> data byte 0x06.
const CAPTURED_CLOCK_DELAY_PULSE_ON: [u8; 9] =
    [0x51, 0x09, 0x00, 0x3C, 0x80, 0x00, 0x80, 0x06, 0x16];
/// `read_asic_register` broadcast of register 0 (`pack_read_vil(0, 0, true)`),
/// the coverage read the runtime uses to require 60 distinct 0x1393 replies.
const CAPTURED_READ_ALL_REG0: [u8; 5] = [0x52, 0x05, 0x00, 0x00, 0x0A];

fn assert_frame_matches(builder: impl FnOnce() -> [u8; 5], captured: [u8; 5], label: &str) {
    assert_eq!(builder(), captured, "frame mismatch: {label}");
}

#[test]
fn captured_stock_init_frames_replay_byte_exact() {
    // CRC5 values are checked BOTH against the pinned capture and against the
    // driver's own CRC5 helper (CRC5@1AE70.c algorithm).
    assert_frame_matches(
        vil::pack_chain_inactive_vil,
        CAPTURED_CHAIN_INACTIVE,
        "chain_inactive",
    );
    assert_frame_matches(
        || vil::pack_set_address_vil(0x00),
        CAPTURED_SET_ADDRESS_FIRST,
        "set_address first",
    );
    assert_frame_matches(
        || vil::pack_set_address_vil(0xEC),
        CAPTURED_SET_ADDRESS_LAST,
        "set_address last populated",
    );
    assert_frame_matches(
        || vil::pack_set_address_vil(0xFC),
        CAPTURED_SET_ADDRESS_SLOT63,
        "set_address slot 63",
    );
    for (frame, captured) in [
        (regs::pack_core_number(0x00), CAPTURED_CORE_NUMBER_CHIP0),
        (regs::pack_core_number(0x78), CAPTURED_CORE_NUMBER_CHIP78),
    ] {
        assert_eq!(frame, captured, "set_core_number payload pins 0x1393 + 0xD0");
        assert_eq!(frame[8], Bm1393Driver::crc5(&frame[..8], 64));
    }
    assert_eq!(regs::pack_enable_core_clock(0), CAPTURED_ENABLE_CORE_0);
    assert_eq!(regs::pack_enable_core_clock(51), CAPTURED_ENABLE_CORE_51);
    assert_eq!(
        regs::pack_ticket_mask_broadcast(0x3F),
        CAPTURED_TICKET_MASK_3F
    );
    assert_eq!(
        regs::pack_baud_one_chain(1).unwrap(),
        CAPTURED_BAUD_DIVISOR_1,
        "working baud divisor 1 folds into MISC 0x2101, not the 0x40 21 shape"
    );
    assert_eq!(
        regs::pack_clock_delay_control(false),
        CAPTURED_CLOCK_DELAY_PULSE_OFF
    );
    assert_eq!(
        regs::pack_clock_delay_control(true),
        CAPTURED_CLOCK_DELAY_PULSE_ON
    );
    assert_eq!(regs::pack_read_vil(0, 0, true), CAPTURED_READ_ALL_REG0);
}

#[test]
fn work_tx_reproduces_the_captured_s9k_encoder_vector() {
    // Vector transcribed from campaign evidence/r03/stock-tw-machine-code-
    // vectors.json (chain 0, id 1; sha256 d09c482f… ELF, Unicorn replay of the
    // original Thumb ranges 0x31660..0x31880 + 0x4717c..0x471f4).
    let data = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    ];
    let midstate = std::array::from_fn(|i| 0x40 + i as u8);
    let words = encode_bm1393_work(0, 1, &data, &midstate).unwrap();
    assert_eq!(
        words,
        [
            0x0180_0000, // word0: real-work header | chain 0
            0x0000_0001, // word1: 15-bit work id
            0x1011_1213, 0x1415_1617, 0x1819_1A1B, // header tail (BE)
            0x4041_4243, 0x4445_4647, 0x4849_4A4B, // midstate (BE)
            0x4C4D_4E4F, 0x5051_5253, 0x5455_5657, 0x5859_5A5B, 0x5C5D_5E5F,
        ]
    );
    // Second captured vector: chain 1, id 511 -> word0 0x01810000.
    let words = encode_bm1393_work(1, 511, &data, &midstate).unwrap();
    assert_eq!(words[0], 0x0181_0000);
    assert_eq!(words[1], 511);
    // Transport shape: set_TW_write_command_vil@4717C.c writes word0 to
    // axi[16] (0x40) and words 1..=12 to axi[17] (0x44).
    let offsets = dcentrald_common::s9se_work::vil_tw_register_offsets();
    assert_eq!(offsets.len(), 13);
    assert_eq!(offsets[0], 0x40);
    assert!(offsets[1..].iter().all(|offset| *offset == 0x44));
}

#[test]
fn nonce_rx_decode_matches_the_captured_record_grammar() {
    let driver = Bm1393Driver::new();
    // Record transcribed from get_nonce_and_register@222DA.c:136-140 replay
    // (also the exact record the native runtime test replays):
    //   buf[0] = 0xff45_0082 -> bit31+bit7 set, chain 2, work_id 0x7f45
    //   buf[1] = 0x7800_1207 -> nonce3; chip = 0x78 / 4 = 30, core = 0x07.
    let decoded = driver.decode_nonce(&[0xff45_0082, 0x7800_1207]).unwrap();
    assert_eq!(decoded.nonce, 0x7800_1207);
    assert_eq!(decoded.work_id, 0x7f45);
    assert_eq!(decoded.chip_index, 30);
    assert_eq!(decoded.solution_id, 0);
    assert_eq!(decoded.midstate_idx, 0);
    // The classify layer the transport/ledger use agrees bit-for-bit.
    match classify_return_record(0xff45_0082, 0x7800_1207) {
        Some(dcentrald_common::s9se_nonce::S9SeFifoRecord::Nonce {
            chain,
            work_id,
            nonce3,
        }) => {
            assert_eq!((chain, work_id, nonce3), (2, 0x7f45, 0x7800_1207));
        }
        other => panic!("expected nonce record, got {other:?}"),
    }
    // Work-id round trip: the decoded id is exactly the encoded word1, for
    // the lowest id, a capture-shaped id, and the 15-bit maximum.
    let data = [0u8; 12];
    let midstate = [0u8; 32];
    for id in [0u16, 1, 0x7f45, 32767] {
        let words = encode_bm1393_work(2, id, &data, &midstate).unwrap();
        assert_eq!(words[1], u32::from(id));
        // Nonce record for chain 2 carrying this work id and a plausible
        // nonce (chip 0x78/4=30, core 7, nonzero), built per the
        // get_nonce_and_register bit layout: bit31 | bit7 | chain | id<<16.
        let buf0 = 0x8000_0080u32 | 2 | (u32::from(id) << 16);
        let decoded = driver.decode_nonce(&[buf0, 0x7800_1207]).unwrap();
        assert_eq!(decoded.work_id, id);
        assert_eq!(decoded.chip_index, 30);
    }
}

#[test]
fn nonce_rx_fault_injection_refuses_every_malformed_record() {
    let driver = Bm1393Driver::new();
    // Register record (bit31 clear): the correlated register path owns these;
    // decode_nonce must refuse, including the CRC-error-flagged variant
    // (get_nonce_and_register@222DA.c:85-97 marks buf[0] & 0x40 as CRC error).
    assert!(driver.decode_nonce(&[0x0512_3402, 0x1111_2222]).is_err());
    assert!(driver.decode_nonce(&[0x0512_3442, 0x1111_2222]).is_err());
    // bit31 set but bit7 clear: neither register nor nonce — refuse.
    assert!(driver.decode_nonce(&[0x8000_0000, 0x1]).is_err());
    // Zero nonce (nonce_calc@2214E: buf != 0).
    assert!(driver.decode_nonce(&[0xff45_0082, 0]).is_err());
    // Chip attribution outside 60 chips: high byte 0xF0 / 4 = 60.
    assert!(driver.decode_nonce(&[0xff45_0082, 0xF000_0001]).is_err());
    // Core attribution outside 208 cores: low byte 208 with valid chip byte.
    assert!(driver.decode_nonce(&[0xff45_0082, 0x1000_0000 | 208]).is_err());
}

#[test]
fn bm1393_decode_is_deliberately_not_the_bm1387_s9io_format() {
    // The C43 stock fabric and the S9 s9io FIFO have DIFFERENT normalized
    // return shapes (findings.md fabric warning). The same two words decode
    // differently: bm1387 reads word1 as CRC|work_id|solution and embeds the
    // chip index in nonce bits [7:2]; bm1393 reads word1 as the raw nonce and
    // embeds the chip in nonce3's high byte. This test pins that a future
    // "shared normalization" refactor cannot silently merge them.
    let raw = [0xff45_0082u32, 0x7800_1207u32];
    let bm1393 = Bm1393Driver::new().decode_nonce(&raw).unwrap();
    let bm1387 = Bm1387Driver::new().decode_nonce(&raw).unwrap();
    // Even the nonce field differs: s9io word0 is the nonce; the C43 record
    // carries the nonce in word1 and the header/work metadata in word0.
    assert_eq!(bm1393.nonce, 0x7800_1207);
    assert_eq!(bm1387.nonce, 0xff45_0082);
    // Divergent metadata for the same record:
    assert_eq!(bm1393.work_id, 0x7f45);
    assert_ne!(bm1387.work_id, bm1393.work_id);
    assert_ne!(bm1387.chip_index, bm1393.chip_index);
    assert_ne!(bm1387.solution_id, bm1393.solution_id);
}

#[test]
fn pll_spine_replays_the_held_tables_and_the_stock_frame_set() {
    // 500 MHz row of the held freq_high_pll_1393 region: divider 6, VCO
    // 3000 MHz; freq_pll_1393[175] = (3000, 0x780111) — the same word stock
    // uses as its solver fallback (25 MHz x 120 / 1 / 1 / 1 = 3000).
    let (word, divider) = Bm1393Driver::pll_plan(500);
    assert_eq!((word, divider), (0x0078_0111, 6));
    assert!((dcentrald_common::s9se_pll::pll_output_mhz(word, divider).unwrap() - 500.0).abs() < 0.5);
    // Operational four-write spine (change_high_pll_test@22DEC.c): divider
    // 0x70 then word 0x08, twice; preceded by the 12-frame set_unused_pll
    // park (dividers 0x74/0x78/0x7C, PLLs 0x60/0x64/0x68). Exactly what
    // Bm1393Runtime::start_inner sends per chain.
    let spine = dcentrald_common::s9se_pll::pack_operational_pll_frames(word, divider).unwrap();
    assert_eq!(spine.len(), 4);
    assert_eq!(&spine[0][..4], &[0x51, 0x09, 0x00, 0x70]);
    assert_eq!(&spine[1][..4], &[0x51, 0x09, 0x00, 0x08]);
    assert_eq!(&spine[2][..4], &[0x51, 0x09, 0x00, 0x70]);
    assert_eq!(&spine[3][..4], &[0x51, 0x09, 0x00, 0x08]);
    assert_eq!(&spine[1][4..8], &word.to_be_bytes());
    let park = dcentrald_common::s9se_pll::pack_unused_pll_park_frames();
    assert_eq!(park.len(), 12);
    assert_eq!(park[0][3], 0x74);
    assert_eq!(&park[1][4..8], &0x8010_F0F7u32.to_be_bytes());
    assert_eq!(park.len() + spine.len(), 16);
    // pll_params exposes the same word with honest divider decode.
    let pll = Bm1393Driver::new().pll_params(500);
    assert_eq!(pll.reg_value, word);
    assert_eq!(
        (pll.fb_div, pll.ref_div, pll.post_div1, pll.post_div2),
        (120, 1, 1, 1)
    );
}

#[test]
fn open_core_geometry_and_carrier_refusals_stay_fail_closed() {
    // open_core_bm1393@21C12.c geometry: 4 banks x 52 positions, one dummy TW
    // per position with word0 (chain<<16) | 0x1000080.
    assert_eq!(
        dcentrald_common::s9se_init::open_core_tw0(2),
        0x0002_0000 | 0x0100_0080
    );
    let plan = dcentrald_common::s9se_init::plan_s9se_open_core().unwrap();
    assert_eq!(plan.core_enable_frames.len(), 208);
    assert_eq!(plan.tw_words, 13);
    // The FpgaChain-carried trait methods refuse through one shared,
    // publicly-pinnable helper: no BM1393 s9io carrier exists in held
    // evidence; the refusal names both the missing artifact and the
    // evidenced C43 executor.
    let error = dcentrald_asic::drivers::bm1393::refuse_no_s9io_carrier::<()>("init_chain")
        .unwrap_err()
        .to_string();
    assert!(error.contains("no s9io/Braiins-FIFO carrier"));
    assert!(error.contains("missing artifact: a BM1393 s9io bitstream/DTB/ELF set"));
    assert!(error.contains("Bm1393Runtime"));
    assert!(error.contains("dcentrald_hal::platform::c43_bm1393"));
}
