//! S19k Braiins Track-1 **userspace** job fill — desk 11d/11e/11f + Wire CLEAR_BRAIINS_TTY.
//!
//! Pure pack + **the Track-1 mining-on work-TX seam**. No open, no ioctl, no
//! GPIO write. Live 2026-08-12 miss was the FPGA/ESP-Miner length **field**
//! `0x56` + 82-byte full header. CLOSED stock/AML on-wire is:
//!
//! ```text
//! 55 AA 21 36 <job_id=work_id<<log> 01 <sno=0> <data2[12]> <data[64]> <crc16_itu_t_be>
//! ```
//!
//! Fill `+0x55=1` ⇒ log 0 ⇒ the on-wire byte **is** the registry `work_id`.
//! Stock uart_trans 11f still uses [`job_id_from_slot`] (`slot<<3`).
//!
//! `data[64]` = bbversion‖prev_hash‖merkle[0:28] then byte-rev (desk 11f).
//! `data2[12]` = merkle[28:32]‖ntime‖nbit then byte-rev.
//! One frame per work (desk 11e). MS8 is on-chip version roll, not 8 UART frames.
//!
//! Ghidra 2026-08-13 (`FUN_0091ba88` + `FUN_0091beb4`): Braiins userspace
//! prefix is `55 AA 21 36` (DAT_012ec448). Payload is ESP-style 82 B
//! (nonce/nbits/ntime/merkle32/prev32/version), **not** desk-11f 36+28.
//! Stock `pack_uart_trans_job` stays 11f for Track-2 uart_trans.

use crate::s19k_uart_trans_job::{
    admit_uart_frames_per_work, crc16_itu_t, fill_job_data_header_chunk_byte_rev, job_id_from_slot,
    pack_uart_trans_job, JOB_BODY_LEN, JOB_CMD_TYPE, JOB_CRC_LEN, JOB_DATA2_LEN,
    JOB_DATA_BBVERSION_LEN, JOB_DATA_MERKLE_PREFIX_LEN, JOB_DATA_PREV_HASH_LEN, JOB_LEN_FIELD,
    JOB_PREAMBLE_0, JOB_PREAMBLE_1, JOB_RSVD2, JOB_WIRE_TOTAL,
};

/// `SerialChainBackend::send_work` payload: body **without** preamble/CRC.
/// `21 36 … data[64]` = [`JOB_CRC_LEN`] = 0x54.
pub const MINING_ON_SEND_WORK_BODY_LEN: usize = JOB_CRC_LEN;

/// FPGA / ESP-Miner length **field** that DCENT serial dispatch sent live 2026-08-12.
/// REFUSE as S19k AML/Braiins on-wire length field.
pub const FPGA_ESP_JOB_LEN_FIELD: u8 = 0x56;
/// ESP-Miner / `serial_mining.rs` BM1362-style full-header payload (not 11f).
pub const FPGA_ESP_JOB_PAYLOAD_LEN: usize = 82;

/// Live 2026-08-12 prefix (wrong). Logged as `55 AA 21 56 …`.
pub const LIVE_20260812_FPGA_PREFIX: [u8; 4] = [0x55, 0xAA, 0x21, 0x56];
/// Desk 11d CLOSED prefix.
pub const CLOSED_11D_PREFIX: [u8; 4] = [0x55, 0xAA, 0x21, 0x36];
/// `bosminer.unpacked` file offset / VA of `55 AA 21 36`.
///  treated this as UART-field rodata next to `register`. Ghidra 2026-08-13:
/// `FUN_0091ba88` stores `DAT_012ec448` at src+0x50; `FUN_0091beb4` emits it as
/// dest[0:4]. Same bytes, now a packer prefix — not a collision.
pub const BOSMINER_55AA2136_COLLISION_OFF: u64 = 0x00EE_C448;
/// ELF VA (`image_base 0x400000` + file off).
pub const BOSMINER_PREFIX_CONST_VA: u64 = 0x012E_C448;
pub const BOSMINER_FILL_FN_VA: u64 = 0x0091_BA88;
pub const BOSMINER_PACK_FN_VA: u64 = 0x0091_BEB4;
pub const BOSMINER_PACK_ALLOC: usize = 0x56;
pub const BOSMINER_PACK_CRC_OFF: usize = 2;
pub const BOSMINER_PACK_CRC_LEN: usize = 0x54;
/// `FUN_0091beb4` dest (includes `55 AA`). Body queued by mining-on is dest[2..].
pub const BOSMINER_PACK_DEST_PREFIX_OFF: usize = 0;
pub const BOSMINER_PACK_DEST_TYPE_OFF: usize = 2;
pub const BOSMINER_PACK_DEST_LEN_OFF: usize = 3;
pub const BOSMINER_PACK_DEST_JOB_ID_OFF: usize = 4;
pub const BOSMINER_PACK_DEST_MIDSTATES_OFF: usize = 5;
pub const BOSMINER_PACK_DEST_NONCE_OFF: usize = 6;
pub const BOSMINER_PACK_DEST_NBITS_OFF: usize = 10;
pub const BOSMINER_PACK_DEST_NTIME_OFF: usize = 14;
pub const BOSMINER_PACK_DEST_MERKLE_OFF: usize = 0x12;
pub const BOSMINER_PACK_DEST_PREV_OFF: usize = 0x32;
pub const BOSMINER_PACK_DEST_VERSION_OFF: usize = 0x52;
/// Painted first-LOAD words. Success path has 0 rustc Locations.
pub const BOSMINER_PACK_FN_SUB_INSN: u32 = 0xD101_03FF;
pub const BOSMINER_PACK_FN_MOVZ56_VA: u64 = 0x0091_BEC8;
pub const BOSMINER_PACK_FN_MOVZ56_INSN: u32 = 0x5280_0AC0;
pub const BOSMINER_PACK_FN_ADD54_VA: u64 = 0x0091_BEE4;
pub const BOSMINER_PACK_FN_ADD54_INSN: u32 = 0x9101_52A8;
pub const BOSMINER_PACK_FN_ADD50_VA: u64 = 0x0091_BF00;
pub const BOSMINER_PACK_FN_ADD50_INSN: u32 = 0x9101_42A8;
pub const BOSMINER_PACK_FN_STRQ0_VA: u64 = 0x0091_BF14;
pub const BOSMINER_PACK_FN_STRQ0_INSN: u32 = 0x3D80_0000;
pub const BOSMINER_PACK_FN_STUR52_VA: u64 = 0x0091_BF50;
pub const BOSMINER_PACK_FN_STUR52_INSN: u32 = 0xB805_2009;
pub const BOSMINER_PACK_FN_CRC_INIT_BL_VA: u64 = 0x0091_BF54;
pub const BOSMINER_PACK_FN_CRC_INIT_BL_INSN: u32 = 0x9400_73FF;
pub const BOSMINER_PACK_FN_ADD2_VA: u64 = 0x0091_BF58;
pub const BOSMINER_PACK_FN_ADD2_INSN: u32 = 0x9100_0A81;
pub const BOSMINER_PACK_FN_MOVZ54_VA: u64 = 0x0091_BF5C;
pub const BOSMINER_PACK_FN_MOVZ54_INSN: u32 = 0x5280_0A82;
pub const BOSMINER_PACK_FN_CRC_UPD_BL_VA: u64 = 0x0091_BF60;
pub const BOSMINER_PACK_FN_CRC_UPD_BL_INSN: u32 = 0x9400_73FE;
pub const BOSMINER_PACK_FN_CRC_FIN_BL_VA: u64 = 0x0091_BF64;
pub const BOSMINER_PACK_FN_CRC_FIN_BL_INSN: u32 = 0x9400_7408;
pub const BOSMINER_PACK_FN_RET_VA: u64 = 0x0091_BFB0;
pub const BOSMINER_PACK_FN_RET_INSN: u32 = 0xD65F_03C0;
/// Alloc-fail Location after RET. `packing.rs:40:23` — not the packer name.
pub const BOSMINER_PACK_FN_FAIL_LOC_VA: u64 = 0x019C_A130;
pub const BOSMINER_PACK_FN_FAIL_LOC_LINE: u16 = 40;
pub const BOSMINER_PACK_FN_FAIL_LOC_COL: u16 = 23;
pub const BOSMINER_PACK_FN_SUCCESS_RUSTC_LOCS: usize = 0;
///  Ghidra `FUN_0091ba88` 86-byte fill struct.
pub const BOSMINER_FILL_PREFIX_OFF: usize = 0x50;
pub const BOSMINER_FILL_JOB_ID_OFF: usize = 0x54;
pub const BOSMINER_FILL_MIDSTATES_OFF: usize = 0x55;
pub const BOSMINER_FILL_NONCE_OFF: usize = 0x40;
pub const BOSMINER_FILL_MIDSTATES: u8 = 1;
/// `FUN_00c41e5c` — `work.rs` version-index helper. Index 0 is midstate 0.
pub const BOSMINER_VERSION_ROLL_FN_VA: u64 = 0x00C4_1E5C;
/// Pack caller `FUN_0091bfe8` BL at `0x0091c04c`.
pub const BOSMINER_PACK_CALLER_VA: u64 = 0x0091_BFE8;
/// `FUN_0091ba88` `ldr w21, [x8, #0x38]` @ `0x0091bcb8` then
/// `stp w21, w0, [x19, #0x48]` — w0 is `FUN_00c41e5c` version.
/// Same work.rs unit as `ntime_offset < ROLL_NTIME_SECONDS` (`FUN_00c41c48`).
/// Packed into the ESP `ntime` word, **not** nbits.
pub const BOSMINER_WORK_VERSION_OFF: usize = 0x34;
pub const BOSMINER_WORK_NTIME_OFF: usize = 0x38;
pub const BOSMINER_WORK_NTIME_LDR_VA: u64 = 0x0091_BCB8;
pub const BOSMINER_NTIME_ROLL_FN_VA: u64 = 0x00C4_1C48;
/// fill+0x44 ← **Job dyn** vtable `+0x90` (`ldr x8,[x22,#0x90]; blr x8` @ `0x0091bc5c`).
/// Packed as ESP `nbits`. rustc `BUG: job has incorrect nbits` is work.rs:307.
///  called this "engine vtable"; : x22 is `*(work+0x20)`, the
/// Job fat-pointer vtable, **not** pack-caller `FUN_0091bfe8` param_3.
pub const BOSMINER_FILL_NBITS_OFF: usize = 0x44;
pub const BOSMINER_FILL_NTIME_OFF: usize = 0x48;
pub const BOSMINER_ENGINE_NBITS_VTABLE_OFF: usize = 0x90;
pub const BOSMINER_ENGINE_NBITS_BLR_VA: u64 = 0x0091_BC5C;
pub const BOSMINER_INCORRECT_NBITS_STR_VA: u64 = 0x013A_D458;
/// `open/bosminer/bosminer/src/work.rs` rustc Location line for the nbits BUG.
pub const BOSMINER_NBITS_BUG_WORK_RS_LINE: u16 = 307;
/// Fill `x22 = *(work+0x20)` — rust dyn Job vtable (align at vtable+0x10).
pub const BOSMINER_WORK_JOB_VTABLE_OFF: usize = 0x20;
/// `FUN_00c7b380` / `FUN_00d139dc`: `ldr w0,[x0,#0x78]; ret` (LE `0xB9407800`).
pub const BOSMINER_JOB_NBITS_GETTER_VA: u64 = 0x00C7_B380;
pub const BOSMINER_JOB_NBITS_GETTER2_VA: u64 = 0x00D1_39DC;
pub const BOSMINER_JOB_NBITS_GETTER_INSN: u32 = 0xB940_7800;
pub const BOSMINER_JOB_NBITS_GETTER_FILE_OFF: u64 = 0x0087_B380;
pub const BOSMINER_JOB_NBITS_GETTER2_FILE_OFF: u64 = 0x0091_39DC;
/// First-LOAD file offsets of the two rust vtables (`size=0x80`, `align=8`).
/// ELF PHDR maps Ghidra VA `0x01a121d8` → file `0x16021d8`.
pub const BOSMINER_STRATUM_V2_JOB_VTABLE_VA: u64 = 0x01A1_21D8;
pub const BOSMINER_STRATUM_V2_JOB_VTABLE2_VA: u64 = 0x01A1_DC10;
pub const BOSMINER_STRATUM_V2_JOB_VTABLE_FILE_OFF: u64 = 0x0160_21D8;
pub const BOSMINER_STRATUM_V2_JOB_VTABLE2_FILE_OFF: u64 = 0x0160_DC10;
/// Exclusive ELF pointer hits for the two nbits getters (both rust vtables).
pub const BOSMINER_JOB_NBITS_VTABLE_HITS: usize = 2;
/// `FUN_00d1372c` Job object: prevhash +8, merkle +0x28, nbits u32 +0x78.
pub const BOSMINER_JOB_SIZE: usize = 0x80;
pub const BOSMINER_JOB_PREVHASH_OFF: usize = 0x08;
pub const BOSMINER_JOB_MERKLE_OFF: usize = 0x28;
pub const BOSMINER_JOB_NBITS_OFF: usize = 0x78;
pub const BOSMINER_JOB_PREVHASH_GETTER_VA: u64 = 0x00C7_B368;
pub const BOSMINER_JOB_MERKLE_GETTER_VA: u64 = 0x00C7_B370;
pub const BOSMINER_JOB_BUILD_FN_VA: u64 = 0x00D1_372C;
pub const BOSMINER_STRATUM_V2_RS: &str = "open/bosminer/bosminer/src/client/stratum_v2.rs";
/// Pack caller `FUN_0091bfe8` is invoked from `FUN_008f1d44`
/// (`bosminer-backend/src/worker.rs:482`). rust sret: `x8`=Result,
/// `x0`=work, `x1`=engine. `engine+0x70` is the midstate logarithm;
/// `engine+0x90` is a **direct** fn pointer (not the Job vtable) that
/// returns the UART `job_id` byte.
pub const BOSMINER_WORKER_RS: &str = "/build/source/open/bosminer/bosminer-backend/src/worker.rs";
pub const BOSMINER_PACK_CALLER_WORKER_RS_LINE: u16 = 482;
pub const BOSMINER_ENGINE_MIDSTATE_LOG_OFF: usize = 0x70;
pub const BOSMINER_ENGINE_JOB_ID_FN_OFF: usize = 0x90;
/// `FUN_0092f200` panics `invalid midstate count logarithm` if log >= 4.
pub const BOSMINER_MIDSTATE_LOG_MAX: u32 = 3;
pub const BOSMINER_MIDSTATE_LOG_FN_VA: u64 = 0x0092_F200;
/// FPGA `ext_work_id.rs` — **not** the AML ttyS job_id path.
pub const BOSMINER_EXT_WORK_ID_RS: &str = "open/bosminer/bosminer-antminer/src/io/ext_work_id.rs";
pub const BOSMINER_EXT_WORK_ID_ASSERT_LINE: u16 = 81;
pub const BOSMINER_FPGA_WORK_ID_COUNT_BASE: u32 = 0x1_0000;
pub const BOSMINER_EXT_WORK_ID_FN_VA: u64 = 0x0092_E784;
/// Serial registry (`bosminer-hal/src/registry.rs`).
/// Line 119 = insert when `+0x18==0`. Line 148 = `work_id < registry_size`.
pub const BOSMINER_REGISTRY_RS: &str = "open/bosminer/bosminer-hal/src/registry.rs";
pub const BOSMINER_REGISTRY_EMPTY_LINE: u16 = 119;
pub const BOSMINER_REGISTRY_ASSERT_LINE: u16 = 148;
pub const BOSMINER_REGISTRY_ASSERT_FN_VA: u64 = 0x00BF_6C2C;
pub const BOSMINER_REGISTRY_INSERT_FN_VA: u64 = 0x00BE_7084;
pub const BOSMINER_WORK_BUILD_FN_VA: u64 = 0x00BF_5414;
/// `FUN_00bf5414` `stp x8,x22,[x27,#0x38]` @ `0x00bf6454` — x22 is insert return.
pub const BOSMINER_WORK_ID_STP_VA: u64 = 0x00BF_6454;
/// `stp x8, x22, [x27, #0x38]` LE word at [`BOSMINER_WORK_ID_STP_VA`].
pub const BOSMINER_WORK_ID_STP_INSN: u32 = 0xA903_DB68;
pub const BOSMINER_WORK_ID_OFF: usize = 0x40;
pub const BOSMINER_REGISTRY_SLOT_STRIDE: usize = 0x78;
/// No single compile-time constant. UART size is `0x100 >> log` (am3.rs factories).
pub const BOSMINER_REGISTRY_SIZE_KNOWN: bool = false;
/// Five `bosminer-am2-s17` AM3-hashboard Worker factories pass this into
/// `Registry::new` (`0x100 >> *(engine+0x70)`). `FUN_008aea30` uses
/// `0x10000` instead (FPGA). Refuse that as UART.
pub const BOSMINER_UART_REGISTRY_SIZE_BASE: u32 = 0x100;
pub const BOSMINER_AM3_RS: &str = "open/bosminer/bosminer-am2-s17/src/hardware/am3.rs";
/// Control-board module. Not the UART registry factory (that is [`BOSMINER_AM3_RS`]).
pub const BOSMINER_AML_CTRL_RS: &str =
    "open/bosminer/bosminer-am2-s17/src/hardware/antminer/controlboard/aml.rs";
pub const BOSMINER_AM3_FACTORY_0X100_SHR_HITS: usize = 5;
/// `MOVZ W10,#0x100` then `LSRV X6,X10,X8` at each factory.
pub const BOSMINER_AM3_FACTORY_MOVZ_INSN: u32 = 0x5280_200A;
pub const BOSMINER_AM3_FACTORY_LSRV_INSN: u32 = 0x9AC8_2546;
pub const BOSMINER_AM3_FACTORY_MOVZ_VAS: [u64; 5] = [
    0x0087_67E8,
    0x0087_6D70,
    0x0087_72F8,
    0x0087_7880,
    0x0087_7E08,
];
/// Worker::new monomorphizations those factories `BL` (same count arg).
pub const BOSMINER_AM3_WORKER_CTOR_VAS: [u64; 5] = [
    0x0090_0810,
    0x0090_3534,
    0x0090_171C,
    0x0090_2628,
    0x0090_4434,
];
/// rustc line of `BUG: Combination architecture-control board not supported`.
pub const BOSMINER_AM3_COMBO_BUG_LINE: u16 = 57;
pub const BOSMINER_REGISTRY_NEW_FN_VA: u64 = 0x00BE_6244;
pub const BOSMINER_REGISTRY_WRAP_FN_VA: u64 = 0x00BF_7798;
pub const BOSMINER_AM3_WORKER_FACTORY_VA: u64 = 0x0087_6CA8;
pub const BOSMINER_FPGA_REGISTRY_FACTORY_VA: u64 = 0x008A_EA30;
pub const BOSMINER_FPGA_0X10000_MOVZ_VA: u64 = 0x008A_EE2C;
pub const BOSMINER_FPGA_0X10000_MOVZ_INSN: u32 = 0x52A0_0029;
pub const BOSMINER_FPGA_0X10000_LSRV_INSN: u32 = 0x1AC8_2527;
/// `FUN_00903534+0x20` `mov x26,x6` — x6 is the factory count.
pub const BOSMINER_WORKER_NEW_SAVES_X6_INSN: u32 = 0xAA06_03FA;
/// `FUN_008d6cf0` chip→factory table. BM1366 uses the same AM3 factory.
pub const BOSMINER_AM3_CHIP_DISPATCH_FN_VA: u64 = 0x008D_6CF0;
pub const BOSMINER_AM3_CHIP_DISPATCH_1366_MOVZ_VA: u64 = 0x008D_6D14;
pub const BOSMINER_AM3_CHIP_DISPATCH_1366_MOVZ_INSN: u32 = 0x5282_6CCA;
pub const BOSMINER_AM3_CHIP_DISPATCH_1362_MOVZ_INSN: u32 = 0x5282_6C48;
pub const BOSMINER_BM1366_CHIP_ID: u16 = 0x1366;
pub const BOSMINER_AM3_CHIP_DISPATCH_IDS: [u16; 4] = [0x1362, 0x1366, 0x1368, 0x1370];
pub const BOSMINER_BM1366_RS: &str = "open/bosminer/bosminer-am2-s17/src/hashchain/bm1366.rs";
pub const BOSMINER_BM136X_RS: &str = "open/bosminer/bosminer-am2-s17/src/hashchain/bm136x.rs";
pub const BOSMINER_HASHCHAIN_RS: &str = "open/bosminer/bosminer-am2-s17/src/hashchain.rs";
/// rustc `hashchain.rs:298` log: setting ticket mask / discovered chips.
pub const BOSMINER_HASHCHAIN_TICKET_LINE: u16 = 298;
/// Factory clones `X1` (`FUN_00875f54`). Copies `[0x11]`/`[0x12]` = +0x88/+0x90.
pub const BOSMINER_FACTORY_CLONE_FN_VA: u64 = 0x0087_5F54;
/// UART work-response parse (`FUN_0091c0a0`). `BUG: Not a work response`.
pub const BOSMINER_WORK_RESP_PARSE_FN_VA: u64 = 0x0091_C0A0;
/// `u64 >> 0x28` is frame byte 5 of the 8-byte payload = job_id (ESP body[5]).
pub const BOSMINER_WORK_RESP_JOB_SHIFT: u32 = 0x28;
/// engine+0x88: chip/core attribution callback called after bswap32 of
/// payload[0:4]. BM1366 resolves this slot to `FUN_009256ac`.
pub const BOSMINER_ENGINE_NONCE_FN_OFF: usize = 0x88;
/// Pack-caller `LSL X1,X9,X10` @ `0x91c00c` — second arg is `1<<log`.
pub const BOSMINER_PACK_CALLER_LSL_COUNT_VA: u64 = 0x0091_C00C;
pub const BOSMINER_PACK_CALLER_LSL_COUNT_INSN: u32 = 0x9ACA_2121;
/// `FUN_0091c0a0` `REV W0,W24` then `blr [engine,#0x88]`.
pub const BOSMINER_WORK_RESP_REV_VA: u64 = 0x0091_C0E0;
pub const BOSMINER_WORK_RESP_REV_INSN: u32 = 0x5AC0_0B00;
/// `LDR X8,[X1,#0x88]` immediately before REV.
pub const BOSMINER_WORK_RESP_LDR88_VA: u64 = 0x0091_C0DC;
pub const BOSMINER_WORK_RESP_LDR88_INSN: u32 = 0xF940_4428;
/// `BLR X8` after REV.
pub const BOSMINER_WORK_RESP_BLR_VA: u64 = 0x0091_C0E4;
pub const BOSMINER_WORK_RESP_BLR_INSN: u32 = 0xD63F_0100;
/// After BLR: `LDRB [X21,#0x80]; CMP #1; B.NE 0x91c1b0` (panic, not alt transform).
pub const BOSMINER_WORK_RESP_PLUS80_LDRB_VA: u64 = 0x0091_C0E8;
pub const BOSMINER_WORK_RESP_PLUS80_LDRB_INSN: u32 = 0x3942_02A8;
pub const BOSMINER_WORK_RESP_PLUS80_CMP1_VA: u64 = 0x0091_C0EC;
pub const BOSMINER_WORK_RESP_PLUS80_CMP1_INSN: u32 = 0x7100_051F;
pub const BOSMINER_WORK_RESP_PLUS80_BNE_VA: u64 = 0x0091_C0F0;
pub const BOSMINER_WORK_RESP_PLUS80_BNE_INSN: u32 = 0x5400_0601;
pub const BOSMINER_WORK_RESP_PLUS80_BNE_TARGET: u64 = 0x0091_C1B0;
/// : `engine+0x80` is the `bm1398_6x.rs` **work-type** tag.
/// Fill / version-rolling requires `== 1`. `!= 1` is
/// `BUG: Midstates work type in version-rolling mode` at line 344.
/// Not AM3 Future `LDRB [X0,#0x80]` and not `pic0x88.rs`.
pub const BOSMINER_ENGINE_WORK_TYPE_OFF: usize = 0x80;
pub const BOSMINER_WORK_TYPE_VERSION_ROLLING: u8 = 1;
pub const BOSMINER_BM1398_6X_RS: &str = "open/bosminer/bosminer-antminer/src/bm1398_6x.rs";
pub const BOSMINER_WORK_RESP_PLUS80_PANIC_MSG: &str =
    "BUG: Midstates work type in version-rolling mode";
pub const BOSMINER_WORK_RESP_PLUS80_PANIC_MSG_VA: u64 = 0x0132_548F;
pub const BOSMINER_WORK_RESP_PLUS80_PANIC_MSG_LEN: u32 = 0x30;
pub const BOSMINER_WORK_RESP_PLUS80_ADRP_VA: u64 = 0x0091_C1B0;
pub const BOSMINER_WORK_RESP_PLUS80_ADRP_INSN: u32 = 0xB000_5040;
pub const BOSMINER_WORK_RESP_PLUS80_ADD_VA: u64 = 0x0091_C1B4;
pub const BOSMINER_WORK_RESP_PLUS80_ADD_INSN: u32 = 0x9112_3C00;
pub const BOSMINER_WORK_RESP_PLUS80_MOVZ_LEN_VA: u64 = 0x0091_C1C0;
pub const BOSMINER_WORK_RESP_PLUS80_MOVZ_LEN_INSN: u32 = 0x5280_0601;
/// Second-LOAD rust `Location` (`file_off = VA - 0x410000`).
pub const BOSMINER_WORK_RESP_PLUS80_LOC_VA: u64 = 0x019C_A220;
pub const BOSMINER_WORK_RESP_PLUS80_LOC_FILE_OFF: u64 = 0x015B_A220;
pub const BOSMINER_WORK_RESP_PLUS80_SRC_VA: u64 = 0x0132_5433;
pub const BOSMINER_WORK_RESP_PLUS80_SRC_LEN: u32 = 48;
pub const BOSMINER_WORK_RESP_PLUS80_LINE: u16 = 344;
pub const BOSMINER_WORK_RESP_PLUS80_COL: u16 = 21;
pub const BOSMINER_WORK_RESP_NOT_WORK_MSG: &str = "BUG: Not a work response";
pub const BOSMINER_WORK_RESP_NOT_WORK_MSG_VA: u64 = 0x0132_5477;
pub const BOSMINER_WORK_RESP_NOT_WORK_MSG_LEN: u32 = 0x18;
pub const BOSMINER_WORK_RESP_NOT_WORK_LINE: u16 = 319;
pub const BOSMINER_WORK_RESP_NOT_WORK_COL: u16 = 9;
pub const BOSMINER_WORK_RESP_NOT_WORK_LOC_VA: u64 = 0x019C_A208;
/// PIC driver filename — not the engine+0x88 attribution callback pointer.
pub const BOSMINER_PIC0X88_RS: &str =
    "open/bosminer/bosminer-am2-s17/src/hardware/hashboard/power/antminer/pic0x88.rs";
/// `MOV X22,X0` — first half of the BLR attribution tuple: encoded chip
/// address, later passed to `FUN_00bf3264`.
pub const BOSMINER_WORK_RESP_SAVE_X0_VA: u64 = 0x0091_C0F4;
pub const BOSMINER_WORK_RESP_SAVE_X0_INSN: u32 = 0xAA00_03F6;
/// `MOV X1,X22` before `BL` into the encoded-address divider (`0xbf3264`).
pub const BOSMINER_WORK_RESP_MOV_X1_NONCE_VA: u64 = 0x0091_C120;
pub const BOSMINER_WORK_RESP_MOV_X1_NONCE_INSN: u32 = 0xAA16_03E1;
/// Original LE-loaded payload low32 is stored separately at WorkResponse+0x30.
pub const BOSMINER_WORK_RESP_STORE_RAW_NONCE_VA: u64 = 0x0091_C140;
pub const BOSMINER_WORK_RESP_STORE_RAW_NONCE_INSN: u32 = 0xB900_3278;
/// rustc `fn(u32)->u32 { x }` is a lone `RET`. First LOAD has this many
/// RET-only sites / DATA u64 pointers to them — not a unique +0x88 name.
pub const BOSMINER_RET_ONLY_SITES: usize = 269;
pub const BOSMINER_RET_ONLY_DATA_PTRS: usize = 220;
/// : factory `FUN_00876ca8` has **0** file bytes `u64==0x876ca8`
/// (aligned or unaligned). Dispatch materializes it via ADRP+ADD only.
pub const BOSMINER_FACTORY_DATA_PTR_HITS: usize = 0;
/// ADRP (page in first LOAD) + ADD + non-SP `STR [Xn,#0x88]` of a
/// `RET`/`REV W0,W0;RET` body: **0**.
pub const BOSMINER_ADRP_TEXT_NONSP_STR88_RET_HITS: usize = 0;
/// Outer get+factory: `MOV X1,X24` @ `0x87e1c8` (`X24` ← `SP+0x60` ← `SP+0x78`).
pub const BOSMINER_FACTORY_X1_FROM_X24_VA: u64 = 0x0087_E1C8;
pub const BOSMINER_FACTORY_X1_FROM_X24_INSN: u32 = 0xAA18_03E1;
/// `STR X26,[X23,#0x290]` — HashChain engine slot is entry `X4`, not a static.
pub const BOSMINER_HC290_STR_VA: u64 = 0x0087_8C98;
pub const BOSMINER_HC290_STR_INSN: u32 = 0xF901_4AFA;
/// bm1366.rs `STR X0,[X19,#0x88]` after `BL FUN_008d9984` — Result, not .text.
pub const BOSMINER_BM1366_STR88_RESULT_VA: u64 = 0x008D_C95C;
pub const BOSMINER_BM1366_STR88_RESULT_INSN: u32 = 0xF900_4660;
/// : stripped ELF `.comment` rustc; no `.rustc` / identity symbol.
pub const BOSMINER_RUSTC_VERSION: &str = "rustc version 1.87.0 (17067e9ac 2025-05-09)";
pub const BOSMINER_COMMENT_FILE_OFF: u64 = 0x016D_A050;
pub const BOSMINER_ELF_SHNUM: u16 = 18;
pub const BOSMINER_RUSTC_SECTION_PRESENT: bool = false;
pub const BOSMINER_IDENTITY_STR_HITS: usize = 0;
/// Chip-id dispatch that materializes the BM1366 factory (`MOVZ W10,#0x1366`).
pub const BOSMINER_BM1366_DISPATCH_FN_VA: u64 = 0x008D_6CF0;
pub const BOSMINER_BM1366_DISPATCH_MOVZ_VA: u64 = 0x008D_6D14;
pub const BOSMINER_BM1366_DISPATCH_MOVZ_INSN: u32 = 0x5282_6CCA;
pub const BOSMINER_BM1366_DISPATCH_ADD_VA: u64 = 0x008D_6D10;
pub const BOSMINER_BM1366_DISPATCH_ADD_INSN: u32 = 0x9132_A108;
/// `ADRP 0x876000 + #0xCA8` — BM1366 HashChain factory.
pub const BOSMINER_BM1366_FACTORY_FN_VA: u64 = 0x0087_6CA8;
pub const BOSMINER_BM1366_FACTORY_PROLOGUE_INSN: u32 = 0xA9BA_7BFD;
/// `FUN_00875f54` copies source+136 → dest+136 (covers Worker+0x88 qword).
pub const BOSMINER_CLONE_LDUR_Q88_VA: u64 = 0x0087_5FAC;
pub const BOSMINER_CLONE_LDUR_Q88_INSN: u32 = 0x3CC8_8285;
pub const BOSMINER_CLONE_STUR_Q88_VA: u64 = 0x0087_61D4;
pub const BOSMINER_CLONE_STUR_Q88_INSN: u32 = 0x3C88_8265;
/// : clone dest/src identity and the five factory `BL` sites.
pub const BOSMINER_CLONE_DEST_MOV_VA: u64 = 0x0087_5F74;
pub const BOSMINER_CLONE_DEST_MOV_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_CLONE_SRC_MOV_VA: u64 = 0x0087_5F80;
pub const BOSMINER_CLONE_SRC_MOV_INSN: u32 = 0xAA01_03F4;
pub const BOSMINER_FACTORY_CLONE_BL_HITS: usize = 5;
pub const BOSMINER_FACTORY_CLONE_BL_STRIDE: u64 = 0x588;
pub const BOSMINER_FACTORY_X1_SAVE_TO_CLONE_BL: u64 = 0x20;
pub const BOSMINER_FACTORY_X1_SAVE_INSN_CLONE: u32 = 0xAA01_03F8;
pub const BOSMINER_FACTORY_CLONE_BL_VA: [u64; 5] = [
    0x0087_679C,
    0x0087_6D24,
    0x0087_72AC,
    0x0087_7834,
    0x0087_7DBC,
];
pub const BOSMINER_FACTORY_CLONE_BL_INSN: [u32; 5] = [
    0x97FF_FDEE,
    0x97FF_FC8C,
    0x97FF_FB2A,
    0x97FF_F9C8,
    0x97FF_F866,
];
/// : prep `FUN_0083b3a0` is a second `LDUR Q5,#136` from `X1` (`X20`).
/// Dest is stack `X11=SP+0x230`, **not** factory dest `X19`. Do not reuse
/// [`BOSMINER_PREP_SRC_MOV_INSN`] (that is get-caller `MOV X1,X19`).
pub const BOSMINER_PREP_Q88_LDUR_VA: u64 = 0x0083_B400;
pub const BOSMINER_PREP_Q88_LDUR_INSN: u32 = 0x3CC8_8285;
pub const BOSMINER_PREP_Q88_STUR_VA: u64 = 0x0083_B630;
pub const BOSMINER_PREP_Q88_STUR_INSN: u32 = 0x3C88_8165;
pub const BOSMINER_PREP_X20_MOV_VA: u64 = 0x0083_B3D4;
pub const BOSMINER_PREP_Q88_DEST_ADD_VA: u64 = 0x0083_B578;
pub const BOSMINER_PREP_Q88_DEST_ADD_INSN: u32 = 0x9108_C3EB;
pub const BOSMINER_PREP_Q88_STACK_BASE: u16 = 0x230;
/// `FUN_00835220` `MOV X19,X2` then prep `MOV X1,X19` — prep source is get `X2`.
pub const BOSMINER_GET_X19_FROM_X2_VA: u64 = 0x0083_5240;
pub const BOSMINER_GET_X19_FROM_X2_INSN: u32 = 0xAA02_03F3;
pub const BOSMINER_GET_PREP_X1_VA: u64 = 0x0083_52DC;
pub const BOSMINER_GET_PREP_X1_INSN: u32 = 0xAA13_03E1;
/// Production caller `FUN_0087e02c`: `X2 = SP+0x2e0` (prep source), `X1 = X24` (factory).
pub const BOSMINER_PROD_CALL_X2_ADD_VA: u64 = 0x0087_E1C0;
pub const BOSMINER_PROD_CALL_X2_ADD_INSN: u32 = 0x910B_83E2;
pub const BOSMINER_PROD_CALL_X1_MOV_VA: u64 = 0x0087_E1C8;
pub const BOSMINER_PROD_CALL_X1_MOV_INSN: u32 = 0xAA18_03E1;
pub const BOSMINER_PROD_CONSTRUCT_X0_ADD_VA: u64 = 0x0087_E190;
pub const BOSMINER_PROD_CONSTRUCT_X0_ADD_INSN: u32 = 0x910B_83E0;
pub const BOSMINER_PREP_TEMPLATE_STACK_OFF: u16 = 0x2E0;
/// : `FUN_0087fb4c` wraps clone — dest `X0`, src `X1`, `BL FUN_00875f54`.
/// Production builds prep source by cloning context `X22` onto `SP+0x2e0`.
pub const BOSMINER_WRAP_CLONE_DEST_MOV_VA: u64 = 0x0087_FB70;
pub const BOSMINER_WRAP_CLONE_DEST_MOV_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_WRAP_CLONE_SRC_MOV_VA: u64 = 0x0087_FB78;
pub const BOSMINER_WRAP_CLONE_SRC_MOV_INSN: u32 = 0xAA01_03F4;
pub const BOSMINER_WRAP_CLONE_BL_VA: u64 = 0x0087_FB80;
pub const BOSMINER_WRAP_CLONE_BL_INSN: u32 = 0x97FF_D8F5;
pub const BOSMINER_PROD_WRAP_SRC_MOV_VA: u64 = 0x0087_E194;
pub const BOSMINER_PROD_WRAP_SRC_MOV_INSN: u32 = 0xAA16_03E1;
pub const BOSMINER_PROD_WRAP_BL_VA: u64 = 0x0087_E198;
pub const BOSMINER_PROD_WRAP_BL_INSN: u32 = 0x9400_066D;
pub const BOSMINER_PROD_CTX_MOV_VA: u64 = 0x0087_E044;
/// : `FUN_0087e02c` is vtable method 0 of a `0x2a0` / align-16 type.
pub const BOSMINER_PROD_FN_VA: u64 = 0x0087_E02C;
pub const BOSMINER_E02C_VTABLE_HITS: usize = 2;
pub const BOSMINER_E02C_VTABLE_FILE_OFF: [u64; 2] = [0x015A_B778, 0x015B_1920];
pub const BOSMINER_E02C_VTABLE_VA: [u64; 2] = [0x019B_B778, 0x019C_1920];
pub const BOSMINER_E02C_TYPE_SIZE: usize = 0x2A0;
pub const BOSMINER_E02C_TYPE_ALIGN: usize = 0x10;
pub const BOSMINER_E02C_SIZE_BEFORE_SLOT: u64 = 0x10;
pub const BOSMINER_FIXTURE_RS: &str =
    "open/bosminer/bosminer-am2-s17/src/hardware/braiinsminer/fixture.rs";
pub const BOSMINER_HARDWARE_RS: &str = "open/bosminer/bosminer-am2-s17/src/hardware.rs";
pub const BOSMINER_FIXTURE_RS_LEN: usize = 0x43;
pub const BOSMINER_HARDWARE_RS_LEN: usize = 0x2E;
pub const BOSMINER_E02C_FIXTURE_LINE: u16 = 258;
pub const BOSMINER_E02C_FIXTURE_COL: u16 = 22;
pub const BOSMINER_E02C_HARDWARE_LINE: u16 = 352;
pub const BOSMINER_E02C_HARDWARE_COL: u16 = 18;
pub const BOSMINER_FIXTURE_RS_VA: u64 = 0x0131_B9BC;
pub const BOSMINER_HARDWARE_RS_VA: u64 = 0x0131_F03A;
/// : method 0 loads `*(X22+0x290)+0x88`, not `X22+0x88`.
pub const BOSMINER_CTX_290_LDR_VA: u64 = 0x0087_E11C;
pub const BOSMINER_CTX_290_LDR_INSN: u32 = 0xF941_4AC9;
pub const BOSMINER_CTX_290_THEN_88_VA: u64 = 0x0087_E128;
pub const BOSMINER_CTX_290_THEN_88_INSN: u32 = 0xF940_4529;
pub const BOSMINER_SP88_LDR_VA: u64 = 0x0087_E070;
pub const BOSMINER_SP88_LDR_INSN: u32 = 0xF940_47E1;
pub const BOSMINER_CTX_X22_PLUS88_HITS: usize = 0;
/// : method 0 `X0 = *(X22+0x290)` is `FUN_008787a8` HashMap-get self.
pub const BOSMINER_PROD_MAP_LDR_VA: u64 = 0x0087_E080;
pub const BOSMINER_PROD_MAP_LDR_INSN: u32 = 0xF941_4AC0;
pub const BOSMINER_PROD_GET_BL_VA: u64 = 0x0087_E088;
pub const BOSMINER_PROD_GET_BL_INSN: u32 = 0x97FF_E9C8;
pub const BOSMINER_HASHMAP_GET_ADD_C0_VA: u64 = 0x0087_87B8;
pub const BOSMINER_HASHMAP_GET_ADD_C0_INSN: u32 = 0x9103_0000;
pub const BOSMINER_HASHMAP_GET_A8_LDR_VA: u64 = 0x0087_87C8;
pub const BOSMINER_HASHMAP_GET_A8_LDR_INSN: u32 = 0xF940_5688;
pub const BOSMINER_HASHMAP_GET_KEY_ADD_VA: u64 = 0x0087_87CC;
pub const BOSMINER_HASHMAP_GET_KEY_ADD_INSN: u32 = 0x9106_7033;
pub const BOSMINER_HASHMAP_INNER_OFF: usize = 0xC0;
pub const BOSMINER_HASHMAP_A8_OFF: usize = 0xA8;
pub const BOSMINER_HC290_STR298_VA: u64 = 0x0087_8C9C;
pub const BOSMINER_HC290_STR298_INSN: u32 = 0xF901_4EF9;
/// : AM3 window `0x860000..0x890000` non-SP `STR #0x88` census.
pub const BOSMINER_AM3_STR88_HITS: usize = 10;
pub const BOSMINER_AM3_STR88_VA: [u64; 10] = [
    0x0086_83B8,
    0x0086_8A24,
    0x0086_8F08,
    0x0086_C42C,
    0x0086_CADC,
    0x0086_DDE8,
    0x0087_64BC,
    0x0088_B638,
    0x0088_D984,
    0x0088_E0B8,
];
pub const BOSMINER_AM3_STR88_INSN: [u32; 10] = [
    0xF900_4669,
    0xF900_4660,
    0xF900_4660,
    0xF900_4668,
    0xF900_4668,
    0xF900_467F,
    0xF900_4668,
    0xF900_4660,
    0xF900_4668,
    0xF900_4668,
];
/// Result-after-helper: `STR X0,[X19,#0x88]` after `BL` packed-tag `LDRB #0x70`.
pub const BOSMINER_AM3_STR88_RESULT_HITS: usize = 3;
pub const BOSMINER_AM3_STR88_RESULT_VA: [u64; 3] = [0x0086_8A24, 0x0086_8F08, 0x0088_B638];
pub const BOSMINER_AM3_STR88_RESULT_INSN: u32 = 0xF900_4660;
pub const BOSMINER_AM3_STR88_RESULT_BL_BEFORE: u64 = 0x0C;
pub const BOSMINER_AM3_TAG70_HELPER_VA: [u64; 2] = [0x0086_5EF0, 0x0088_7D10];
pub const BOSMINER_AM3_TAG70_HELPER_LDRB_OFF: u64 = 0x14;
pub const BOSMINER_AM3_TAG70_HELPER_LDRB_INSN: u32 = 0x3941_C008;
/// Interior `X10+0x18` stored at dest+0x88 (not `.text`).
pub const BOSMINER_AM3_STR88_ADD18_HITS: usize = 2;
pub const BOSMINER_AM3_STR88_ADD18_VA: [u64; 2] = [0x0086_C42C, 0x0088_D984];
pub const BOSMINER_AM3_STR88_ADD18_BEFORE: u64 = 0x0C;
pub const BOSMINER_AM3_STR88_ADD18_INSN: u32 = 0x9100_6148;
pub const BOSMINER_AM3_STR88_MOVZ4_BEFORE: u64 = 0x28;
pub const BOSMINER_AM3_STR88_MOVZ4_INSN: u32 = 0x5280_0088;
/// Second SLICE10 clone (`ADD X8,#0x10`) in the AM3 window.
pub const BOSMINER_AM3_STR88_SLICE10_CLONE_VA: u64 = 0x0088_E0B8;
pub const BOSMINER_AM3_STR88_SLICE10_ADD_BEFORE: u64 = 0x0C;
pub const BOSMINER_AM3_STR88_ZERO_VA: u64 = 0x0086_DDE8;
pub const BOSMINER_AM3_STR88_ZERO_INSN: u32 = 0xF900_467F;
pub const BOSMINER_AM3_STR88_FIELD_VA: u64 = 0x0086_83B8;
pub const BOSMINER_AM3_STR88_FIELD_INSN: u32 = 0xF900_4669;
/// 0 of the 10 dests `STR [X19,#0xA8]` (HashMap-get ctrl).
pub const BOSMINER_AM3_STR88_DEST_A8_HITS: usize = 0;
/// : first-LOAD non-SP `STR #0x88` whose dest also has `+0xA8` **and** `+0xC0`.
pub const BOSMINER_HASHMAP_STR88_HITS: usize = 11;
pub const BOSMINER_HASHMAP_STR88_WINDOW: u64 = 0x300;
pub const BOSMINER_HASHMAP_STR88_VA: [u64; 11] = [
    0x005D_E708,
    0x0062_6AAC,
    0x0065_4C10,
    0x0065_5098,
    0x008D_1340,
    0x008D_1BF8,
    0x008D_24B0,
    0x009F_3F00,
    0x00B8_24C8,
    0x0115_C698,
    0x0115_C788,
];
pub const BOSMINER_HASHMAP_STR88_INSN: [u32; 11] = [
    0xF900_4660,
    0xF900_4660,
    0xF900_4678,
    0xF900_4668,
    0xF900_4674,
    0xF900_4674,
    0xF900_4674,
    0xF900_4668,
    0xF900_4669,
    0xF900_46A8,
    0xF900_46A8,
];
/// Three HashMap-shaped inits: `ADD #0xA8` / `ADD #0xC0` then `STR X20,[X19,#0x88]`.
pub const BOSMINER_HASHMAP_STR88_FAMILY_HITS: usize = 3;
pub const BOSMINER_HASHMAP_STR88_FAMILY_STRIDE: u64 = 0x8B8;
pub const BOSMINER_HASHMAP_STR88_FAMILY_VA: [u64; 3] = [0x008D_1340, 0x008D_1BF8, 0x008D_24B0];
pub const BOSMINER_HASHMAP_STR88_FAMILY_INSN: u32 = 0xF900_4674;
pub const BOSMINER_HASHMAP_STR88_ADD_A8_BEFORE: u64 = 0x1C0;
pub const BOSMINER_HASHMAP_STR88_ADD_C0_BEFORE: u64 = 0x1B0;
pub const BOSMINER_HASHMAP_STR88_ADD_A8_INSN: u32 = 0x9102_A260;
pub const BOSMINER_HASHMAP_STR88_ADD_C0_INSN: u32 = 0x9103_0260;
/// : family `X20` is Result-Ok low qword, not dest+0x88/+0x90.
pub const BOSMINER_HASHMAP_STR88_HELPER_VA: u64 = 0x0086_1090;
pub const BOSMINER_HASHMAP_STR88_BL_BEFORE: u64 = 0x50;
pub const BOSMINER_HASHMAP_STR88_LDRB8_BEFORE: u64 = 0x4C;
pub const BOSMINER_HASHMAP_STR88_TBZ_BEFORE: u64 = 0x48;
pub const BOSMINER_HASHMAP_STR88_LDP_BEFORE: u64 = 0x34;
pub const BOSMINER_HASHMAP_STR88_SRET_ADD_BEFORE: u64 = 0x58;
pub const BOSMINER_HASHMAP_STR88_SELF_B8_BEFORE: u64 = 0x5C;
pub const BOSMINER_HASHMAP_STR88_ADD88_BEFORE: u64 = 0xCC;
pub const BOSMINER_HASHMAP_STR88_ADD90_BEFORE: u64 = 0x7C;
pub const BOSMINER_HASHMAP_STR88_BL_INSN: [u32; 3] = [0x97FE_3F68, 0x97FE_3D3A, 0x97FE_3B0C];
pub const BOSMINER_HASHMAP_STR88_LDRW_SP110_INSN: u32 = 0xB941_13E8;
pub const BOSMINER_HASHMAP_STR88_TBZ_INSN: u32 = 0x3600_00A8;
pub const BOSMINER_HASHMAP_STR88_LDP_INSN: u32 = 0xA951_DFF4;
pub const BOSMINER_HASHMAP_STR88_SRET_ADD_INSN: u32 = 0x9104_43E8;
pub const BOSMINER_HASHMAP_STR88_SELF_B8_INSN: u32 = 0xF940_5E60;
pub const BOSMINER_HASHMAP_STR88_ADD88_INSN: u32 = 0x9102_2274;
pub const BOSMINER_HASHMAP_STR88_ADD90_INSN: u32 = 0x9102_4274;
pub const BOSMINER_HASHMAP_STR88_SRET_SP: u16 = 0x110;
pub const BOSMINER_HASHMAP_STR88_OK_SP: u16 = 0x118;
pub const BOSMINER_HASHMAP_STR88_SELF_B8_OFF: usize = 0xB8;
/// : `FUN_00861090` Ok is a clone of `*(self+0xB8)`, not nonce `.text`.
pub const BOSMINER_HASHMAP_HELPER_LDR_INNER_VA: u64 = 0x0086_109C;
pub const BOSMINER_HASHMAP_HELPER_LDR_INNER_INSN: u32 = 0xF940_0016;
pub const BOSMINER_HASHMAP_HELPER_SAVE_X0_VA: u64 = 0x0086_10A0;
pub const BOSMINER_HASHMAP_HELPER_SAVE_X0_INSN: u32 = 0xAA00_03F4;
pub const BOSMINER_HASHMAP_HELPER_SRET_MOV_VA: u64 = 0x0086_10A4;
pub const BOSMINER_HASHMAP_HELPER_SRET_MOV_INSN: u32 = 0xAA08_03F3;
pub const BOSMINER_HASHMAP_HELPER_ADD10_VA: u64 = 0x0086_10B0;
pub const BOSMINER_HASHMAP_HELPER_ADD10_INSN: u32 = 0x9100_42C0;
pub const BOSMINER_HASHMAP_HELPER_CLONE_BL_VA: u64 = 0x0086_10B4;
pub const BOSMINER_HASHMAP_HELPER_CLONE_BL_INSN: u32 = 0x9401_53FE;
pub const BOSMINER_HASHMAP_HELPER_CLONE_FN_VA: u64 = 0x008B_60AC;
pub const BOSMINER_HASHMAP_HELPER_OK_STR_VA: u64 = 0x0086_1148;
pub const BOSMINER_HASHMAP_HELPER_OK_STR_INSN: u32 = 0xF900_0660;
pub const BOSMINER_HASHMAP_HELPER_OK_HI_VA: u64 = 0x0086_114C;
pub const BOSMINER_HASHMAP_HELPER_OK_HI_INSN: u32 = 0xF900_0A61;
pub const BOSMINER_HASHMAP_HELPER_TAG_VA: u64 = 0x0086_1150;
pub const BOSMINER_HASHMAP_HELPER_TAG_INSN: u32 = 0xF900_027F;
pub const BOSMINER_HASHMAP_CLONE_ALLOC_SZ_VA: u64 = 0x008B_6120;
pub const BOSMINER_HASHMAP_CLONE_ALLOC_SZ_INSN: u32 = 0x5280_0301;
pub const BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN_VA: u64 = 0x008B_6124;
pub const BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN_INSN: u32 = 0x5280_0102;
pub const BOSMINER_HASHMAP_CLONE_ALLOC_SIZE: u16 = 0x18;
pub const BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN: u16 = 8;
/// The 8 HashMap dests that are not the  X20 family.
pub const BOSMINER_HASHMAP_STR88_REST_HITS: usize = 8;
pub const BOSMINER_HASHMAP_STR88_REST_VA: [u64; 8] = [
    0x005D_E708,
    0x0062_6AAC,
    0x0065_4C10,
    0x0065_5098,
    0x009F_3F00,
    0x00B8_24C8,
    0x0115_C698,
    0x0115_C788,
];
pub const BOSMINER_HASHMAP_STR88_SLICE10_REST_VA: u64 = 0x0065_5098;
pub const BOSMINER_HASHMAP_STR88_SLICE10_REST_ADD_BEFORE: u64 = 0x10;
/// : `FUN_008b60ac` extracts a pair from `[X0,#8]+0x10` then **dealloc**s 0x18.
pub const BOSMINER_HASHMAP_18_NODE_LDR_VA: u64 = 0x008B_60B8;
pub const BOSMINER_HASHMAP_18_NODE_LDR_INSN: u32 = 0xF940_0413;
pub const BOSMINER_HASHMAP_18_NODE_ADD10_VA: u64 = 0x008B_60C0;
pub const BOSMINER_HASHMAP_18_NODE_ADD10_INSN: u32 = 0x9100_4268;
pub const BOSMINER_HASHMAP_18_PAIR_LO_VA: u64 = 0x008B_6100;
pub const BOSMINER_HASHMAP_18_PAIR_LO_INSN: u32 = 0xF940_0115;
pub const BOSMINER_HASHMAP_18_PAIR_HI_VA: u64 = 0x008B_60F8;
pub const BOSMINER_HASHMAP_18_PAIR_HI_INSN: u32 = 0xF940_0514;
pub const BOSMINER_HASHMAP_18_DEALLOC_X0_VA: u64 = 0x008B_611C;
pub const BOSMINER_HASHMAP_18_DEALLOC_X0_INSN: u32 = 0xAA13_03E0;
pub const BOSMINER_HASHMAP_18_DEALLOC_BL_VA: u64 = 0x008B_6128;
pub const BOSMINER_HASHMAP_18_DEALLOC_BL_INSN: u32 = 0x97F4_FA55;
pub const BOSMINER_HASHMAP_18_RET_X0_VA: u64 = 0x008B_612C;
pub const BOSMINER_HASHMAP_18_RET_X0_INSN: u32 = 0xAA15_03E0;
pub const BOSMINER_HASHMAP_18_RET_X1_VA: u64 = 0x008B_6130;
pub const BOSMINER_HASHMAP_18_RET_X1_INSN: u32 = 0xAA14_03E1;
pub const BOSMINER_RUSTC_HEAP_THUNK0_VA: u64 = 0x005F_4A7C;
pub const BOSMINER_RUSTC_HEAP_THUNK0_INSN: u32 = 0x1432_99AB;
pub const BOSMINER_RUSTC_HEAP_THUNK1_VA: u64 = 0x005F_4A80;
pub const BOSMINER_RUSTC_HEAP_THUNK2_VA: u64 = 0x005F_4A84;
/// `0x5de708`: `STR X0` after `LDR [X19,#0xA0]` + `BL 0x586cd8`.
pub const BOSMINER_HASHMAP_5DE708_VA: u64 = 0x005D_E708;
pub const BOSMINER_HASHMAP_5DE708_STR_INSN: u32 = 0xF900_4660;
pub const BOSMINER_HASHMAP_5DE708_LDR_A0_VA: u64 = 0x005D_E704;
pub const BOSMINER_HASHMAP_5DE708_LDR_A0_INSN: u32 = 0xF940_5268;
pub const BOSMINER_HASHMAP_5DE708_BL_VA: u64 = 0x005D_E6FC;
pub const BOSMINER_HASHMAP_5DE708_BL_INSN: u32 = 0x97FE_A177;
pub const BOSMINER_HASHMAP_5DE708_BL_TGT: u64 = 0x0058_6CD8;
/// `0x115c698`: rewrite `X21+0x88` after `LDR [X21,#0x88]` / `LDR [X21,#0xA8]`.
pub const BOSMINER_HASHMAP_115C698_VA: u64 = 0x0115_C698;
pub const BOSMINER_HASHMAP_115C698_STR_INSN: u32 = 0xF900_46A8;
pub const BOSMINER_HASHMAP_115C680_LDR88_VA: u64 = 0x0115_C680;
pub const BOSMINER_HASHMAP_115C680_LDR88_INSN: u32 = 0xF940_46B4;
pub const BOSMINER_HASHMAP_115C694_LDR_A8_VA: u64 = 0x0115_C694;
pub const BOSMINER_HASHMAP_115C694_LDR_A8_INSN: u32 = 0xF940_56B4;
pub const BOSMINER_HASHMAP_115C6B0_STR_A8_VA: u64 = 0x0115_C6B0;
pub const BOSMINER_HASHMAP_115C6B0_STR_A8_INSN: u32 = 0xF900_56A8;
/// : rustc heap thunk0 **body** is a 4-insn dummy-frame tail trampoline.
pub const BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA: u64 = 0x0129_B128;
pub const BOSMINER_RUSTC_HEAP_THUNK0_STP_INSN: u32 = 0xA9BF_7BFD;
pub const BOSMINER_RUSTC_HEAP_THUNK0_MOV_INSN: u32 = 0x9100_03FD;
pub const BOSMINER_RUSTC_HEAP_THUNK0_LDP_VA: u64 = 0x0129_B130;
pub const BOSMINER_RUSTC_HEAP_THUNK0_LDP_INSN: u32 = 0xA8C1_7BFD;
pub const BOSMINER_RUSTC_HEAP_THUNK0_B_VA: u64 = 0x0129_B134;
pub const BOSMINER_RUSTC_HEAP_THUNK0_B_INSN: u32 = 0x17E4_BB77;
pub const BOSMINER_RUSTC_HEAP_THUNK0_B_TGT: u64 = 0x00BC_9F10;
/// `0xbc9f10` first arm: `B 0xbca3cc`.
pub const BOSMINER_RUSTC_HEAP_DISP_VA: u64 = 0x00BC_9F10;
pub const BOSMINER_RUSTC_HEAP_DISP_B_INSN: u32 = 0x1400_012F;
pub const BOSMINER_RUSTC_HEAP_DISP_B_TGT: u64 = 0x00BC_A3CC;
/// `0xbca3cc` starts `CBZ X0` — dealloc null-ptr skip, not realloc.
pub const BOSMINER_RUSTC_HEAP_DEALLOC_ARM_VA: u64 = 0x00BC_A3CC;
pub const BOSMINER_RUSTC_HEAP_DEALLOC_CBZ_INSN: u32 = 0xB400_12A0;
/// thunk1 body is a real `SUB SP,#0x40` realloc-shaped fn, not a trampoline.
pub const BOSMINER_RUSTC_HEAP_THUNK1_BODY_VA: u64 = 0x0129_B138;
pub const BOSMINER_RUSTC_HEAP_THUNK1_SUB_INSN: u32 = 0xD101_03FF;
/// `0x4538b0` is the destructor-cleanup panic stub (string len `0x24`).
pub const BOSMINER_PANIC_DTOR_FN_VA: u64 = 0x0045_38B0;
pub const BOSMINER_PANIC_DTOR_STP_INSN: u32 = 0xA9BF_7BFD;
pub const BOSMINER_PANIC_DTOR_MOVZ_VA: u64 = 0x0045_38C0;
pub const BOSMINER_PANIC_DTOR_MOVZ_INSN: u32 = 0x5280_0481;
pub const BOSMINER_PANIC_DTOR_MSG_LEN: u16 = 0x24;
pub const BOSMINER_PANIC_DTOR_MSG: &[u8] = b"panic in a destructor during cleanup";
pub const BOSMINER_PANIC_DTOR_MSG_VA: u64 = 0x0160_B3A6;
/// rest[1] `0x626aac`: `STR X0` after `LDR X0,[X23]` / `B`; not panic return.
pub const BOSMINER_HASHMAP_626AAC_VA: u64 = 0x0062_6AAC;
pub const BOSMINER_HASHMAP_626AAC_STR_INSN: u32 = 0xF900_4660;
pub const BOSMINER_HASHMAP_626AA8_PANIC_BL_VA: u64 = 0x0062_6AA8;
pub const BOSMINER_HASHMAP_626AA8_PANIC_BL_INSN: u32 = 0x97F8_B382;
pub const BOSMINER_HASHMAP_62672C_LDR_VA: u64 = 0x0062_672C;
pub const BOSMINER_HASHMAP_62672C_LDR_INSN: u32 = 0xF940_02E0;
pub const BOSMINER_HASHMAP_626730_B_VA: u64 = 0x0062_6730;
pub const BOSMINER_HASHMAP_626730_B_INSN: u32 = 0x1400_00DF;
/// rest[2] `0x654c10`: `STR X24` after `LDR X24,[X19,#0x90]`.
pub const BOSMINER_HASHMAP_654C10_VA: u64 = 0x0065_4C10;
pub const BOSMINER_HASHMAP_654C10_STR_INSN: u32 = 0xF900_4678;
pub const BOSMINER_HASHMAP_654690_LDR90_VA: u64 = 0x0065_4690;
pub const BOSMINER_HASHMAP_654690_LDR90_INSN: u32 = 0xF940_4A78;
pub const BOSMINER_HASHMAP_654698_B_VA: u64 = 0x0065_4698;
pub const BOSMINER_HASHMAP_654698_B_INSN: u32 = 0x1400_015E;
/// rest[4] `0x9f3f00`: `STR X8` after `LDR X8,[SP,#0x58]`.
pub const BOSMINER_HASHMAP_9F3F00_VA: u64 = 0x009F_3F00;
pub const BOSMINER_HASHMAP_9F3F00_STR_INSN: u32 = 0xF900_4668;
pub const BOSMINER_HASHMAP_9F3ED8_LDR_VA: u64 = 0x009F_3ED8;
pub const BOSMINER_HASHMAP_9F3ED8_LDR_INSN: u32 = 0xF940_0BE8;
pub const BOSMINER_HASHMAP_9F3ED8_SP_OFF: u16 = 0x58;
/// rest[5] `0xb824c8`: `STR X9` after `ADD X9,X8,#8`; not panic return.
pub const BOSMINER_HASHMAP_B824C8_VA: u64 = 0x00B8_24C8;
pub const BOSMINER_HASHMAP_B824C8_STR_INSN: u32 = 0xF900_4669;
pub const BOSMINER_HASHMAP_B824C0_ADD8_VA: u64 = 0x00B8_24C0;
pub const BOSMINER_HASHMAP_B824C0_ADD8_INSN: u32 = 0x9100_2109;
pub const BOSMINER_HASHMAP_B824BC_PANIC_BL_VA: u64 = 0x00B8_24BC;
pub const BOSMINER_HASHMAP_B824BC_PANIC_BL_INSN: u32 = 0x97E3_44FD;
/// rest[7] `0x115c788`: sibling rewrite of rest[6].
pub const BOSMINER_HASHMAP_115C788_VA: u64 = 0x0115_C788;
pub const BOSMINER_HASHMAP_115C788_STR_INSN: u32 = 0xF900_46A8;
pub const BOSMINER_HASHMAP_115C784_LDR_A8_VA: u64 = 0x0115_C784;
pub const BOSMINER_HASHMAP_115C784_LDR_A8_INSN: u32 = 0xF940_56B4;
/// : thunk2 body is a real `SUB SP,#0x30` fn that tails to `0xbc9e18`.
pub const BOSMINER_RUSTC_HEAP_THUNK2_BODY_VA: u64 = 0x0129_B1E4;
pub const BOSMINER_RUSTC_HEAP_THUNK2_SUB_INSN: u32 = 0xD100_C3FF;
pub const BOSMINER_RUSTC_HEAP_THUNK2_CMP_VA: u64 = 0x0129_B1F4;
pub const BOSMINER_RUSTC_HEAP_THUNK2_CMP_INSN: u32 = 0xF100_403F;
pub const BOSMINER_RUSTC_HEAP_THUNK2_SAVE_VA: u64 = 0x0129_B1F8;
pub const BOSMINER_RUSTC_HEAP_THUNK2_SAVE_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_RUSTC_HEAP_THUNK2_B_VA: u64 = 0x0129_B21C;
pub const BOSMINER_RUSTC_HEAP_THUNK2_B_INSN: u32 = 0x17E4_BAFF;
pub const BOSMINER_RUSTC_HEAP_THUNK2_B_TGT: u64 = 0x00BC_9E18;
pub const BOSMINER_RUSTC_HEAP_THUNK2_TGT_STP_INSN: u32 = 0xA9BD_7BFD;
pub const BOSMINER_RUSTC_HEAP_THUNK2_TGT_CBZ_VA: u64 = 0x00BC_9E24;
pub const BOSMINER_RUSTC_HEAP_THUNK2_TGT_CBZ_INSN: u32 = 0xB400_0061;
pub const BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_VA: u64 = 0x00BC_9E28;
pub const BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_INSN: u32 = 0x9BC1_7C02;
pub const BOSMINER_RUSTC_HEAP_THUNK2_TGT_MUL_VA: u64 = 0x00BC_9E30;
pub const BOSMINER_RUSTC_HEAP_THUNK2_TGT_MUL_INSN: u32 = 0x9B00_7C33;
/// rest[1] second inbound: `ADD X0,X8,#0x20` then `B 0x626aac`.
pub const BOSMINER_HASHMAP_626FB0_ADD20_VA: u64 = 0x0062_6FB0;
pub const BOSMINER_HASHMAP_626FB0_ADD20_INSN: u32 = 0x9100_8100;
pub const BOSMINER_HASHMAP_626FC0_B_VA: u64 = 0x0062_6FC0;
pub const BOSMINER_HASHMAP_626FC0_B_INSN: u32 = 0x17FF_FEBB;
/// : fill type-1 +0x88 template is spawn `X24`, not an ADRP identity store.
/// `LDR X23,[X1]` after HashMap-get; `BLR X23` sret `SP+0x68`; Ok qword `SP+0x78` → X24.
pub const BOSMINER_SPAWN_X23_LDR_VA: u64 = 0x0087_E094;
pub const BOSMINER_SPAWN_X23_LDR_INSN: u32 = 0xF940_0037;
pub const BOSMINER_SPAWN_SRET_ADD_VA: u64 = 0x0087_E144;
pub const BOSMINER_SPAWN_SRET_ADD_INSN: u32 = 0x9101_A3E8;
pub const BOSMINER_SPAWN_BLR_VA: u64 = 0x0087_E15C;
pub const BOSMINER_SPAWN_BLR_INSN: u32 = 0xD63F_02E0;
pub const BOSMINER_SPAWN_OK_LDR_VA: u64 = 0x0087_E168;
pub const BOSMINER_SPAWN_OK_LDR_INSN: u32 = 0xF940_3FE8;
pub const BOSMINER_SPAWN_OK_SP: u16 = 0x78;
pub const BOSMINER_SPAWN_X24_STASH_VA: u64 = 0x0087_E170;
pub const BOSMINER_SPAWN_X24_STASH_INSN: u32 = 0xF900_33E8;
pub const BOSMINER_SPAWN_X24_LDR_VA: u64 = 0x0087_E188;
pub const BOSMINER_SPAWN_X24_LDR_INSN: u32 = 0xF940_33F8;
pub const BOSMINER_ADRP_ADD_STR88_HITS: usize = 0;
pub const BOSMINER_ADRP_LDR_TEXT_STR88_NONSP_HITS: usize = 0;
pub const BOSMINER_E02C_METHODS_STR88_HITS: usize = 0;
/// : HashMap-get returns `(X0=tag, X1=payload)`; spawn `X23` is `payload[0]`.
pub const BOSMINER_HASHMAP_GET_HIT_ADD8_VA: u64 = 0x0087_8910;
pub const BOSMINER_HASHMAP_GET_HIT_ADD8_INSN: u32 = 0x9100_22B4;
pub const BOSMINER_HASHMAP_GET_HIT_XZR_VA: u64 = 0x0087_8918;
pub const BOSMINER_HASHMAP_GET_HIT_XZR_INSN: u32 = 0xAA1F_03F3;
pub const BOSMINER_HASHMAP_GET_HIT_X0_VA: u64 = 0x0087_891C;
pub const BOSMINER_HASHMAP_GET_HIT_X1_VA: u64 = 0x0087_8920;
pub const BOSMINER_HASHMAP_GET_RET_X0_INSN: u32 = 0xAA13_03E0;
pub const BOSMINER_HASHMAP_GET_RET_X1_INSN: u32 = 0xAA14_03E1;
pub const BOSMINER_HASHMAP_GET_HIT_RET_VA: u64 = 0x0087_8930;
pub const BOSMINER_HASHMAP_GET_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_HASHMAP_GET_MISS_TAG_VA: u64 = 0x0087_88E4;
pub const BOSMINER_HASHMAP_GET_MISS_TAG_INSN: u32 = 0x5280_0033;
pub const BOSMINER_HASHMAP_GET_MISS_X0_VA: u64 = 0x0087_8938;
pub const BOSMINER_HASHMAP_GET_MISS_X1_VA: u64 = 0x0087_893C;
pub const BOSMINER_HASHMAP_GET_MISS_RET_VA: u64 = 0x0087_894C;
pub const BOSMINER_SPAWN_TBZ_VA: u64 = 0x0087_E08C;
pub const BOSMINER_SPAWN_TBZ_INSN: u32 = 0x3700_0F60;
pub const BOSMINER_SPAWN_TBZ_TGT: u64 = 0x0087_E278;
pub const BOSMINER_SPAWN_DEFAULT_FN_VA: u64 = 0x0040_B55C;
pub const BOSMINER_SPAWN_DEFAULT_ALLOC_VA: u64 = 0x0040_BE58;
pub const BOSMINER_SPAWN_DEFAULT_SIZE: u16 = 0x50;
pub const BOSMINER_SPAWN_DEFAULT_ALIGN: u16 = 8;
pub const BOSMINER_SPAWN_DEFAULT_ALIGN_VA: u64 = 0x0040_BE80;
pub const BOSMINER_SPAWN_DEFAULT_ALIGN_INSN: u32 = 0x5280_0101;
pub const BOSMINER_SPAWN_DEFAULT_SIZE_VA: u64 = 0x0040_BE90;
pub const BOSMINER_SPAWN_DEFAULT_SIZE_INSN: u32 = 0x5280_0A00;
pub const BOSMINER_SPAWN_DEFAULT_ALLOC_BL_VA: u64 = 0x0040_BEA4;
pub const BOSMINER_SPAWN_DEFAULT_ALLOC_BL_INSN: u32 = 0x9407_A2F5;
pub const BOSMINER_SPAWN_DEFAULT_ALLOC_BL_TGT: u64 = 0x005F_4A78;
pub const BOSMINER_SPAWN_MISS_TYPEINFO_ADRP_VA: u64 = 0x0040_BE64;
pub const BOSMINER_SPAWN_MISS_TYPEINFO_ADRP_INSN: u32 = 0xD000_AD88;
pub const BOSMINER_SPAWN_MISS_TYPEINFO_ADD_VA: u64 = 0x0040_BE68;
pub const BOSMINER_SPAWN_MISS_TYPEINFO_ADD_INSN: u32 = 0x9139_4108;
pub const BOSMINER_SPAWN_MISS_TYPEINFO_STR_VA: u64 = 0x0040_BE70;
pub const BOSMINER_SPAWN_MISS_TYPEINFO_STR_INSN: u32 = 0xF900_03E8;
pub const BOSMINER_SPAWN_MISS_PAYLOAD0_VA: u64 = 0x019B_DE50;
/// : HashMap insert helper copies **0x18** from `X3`/`entry|8`, not +0x88.
pub const BOSMINER_HASHMAP_INSERT_FN_VA: u64 = 0x008D_A510;
pub const BOSMINER_HASHMAP_INSERT_SRC_MOV_VA: u64 = 0x008D_A530;
pub const BOSMINER_HASHMAP_INSERT_SRC_MOV_INSN: u32 = 0xAA03_03F5;
pub const BOSMINER_HASHMAP_INSERT_HASH_BL_VA: u64 = 0x008D_A53C;
pub const BOSMINER_HASHMAP_INSERT_HASH_BL_INSN: u32 = 0x97FF_79D2;
pub const BOSMINER_HASHMAP_HASH_FN_VA: u64 = 0x008B_8C84;
pub const BOSMINER_HASHMAP_GET_HASH_BL_INSN: u32 = 0x9401_012A;
pub const BOSMINER_HASHMAP_INSERT_LDR_Q_VA: u64 = 0x008D_A610;
pub const BOSMINER_HASHMAP_INSERT_LDR_Q_INSN: u32 = 0x3DC0_02A1;
pub const BOSMINER_HASHMAP_INSERT_LDR_X10_VA: u64 = 0x008D_A614;
pub const BOSMINER_HASHMAP_INSERT_LDR_X10_INSN: u32 = 0xF940_0AA9;
pub const BOSMINER_HASHMAP_INSERT_STUR_Q_VA: u64 = 0x008D_A620;
pub const BOSMINER_HASHMAP_INSERT_STUR_Q_INSN: u32 = 0x3C9E_8221;
pub const BOSMINER_HASHMAP_INSERT_STUR_X18_VA: u64 = 0x008D_A624;
pub const BOSMINER_HASHMAP_INSERT_STUR_X18_INSN: u32 = 0xF81F_8229;
pub const BOSMINER_HASHMAP_INSERT_VALUE_SIZE: u16 = 0x18;
pub const BOSMINER_HASHMAP_INSERT_ORR8_VA: u64 = 0x008D_4A4C;
pub const BOSMINER_HASHMAP_INSERT_ORR8_INSN: u32 = 0xB27D_02A3;
pub const BOSMINER_HASHMAP_INSERT_CALL_BL_VA: u64 = 0x008D_4A5C;
pub const BOSMINER_HASHMAP_INSERT_CALL_BL_INSN: u32 = 0x9400_16AD;
pub const BOSMINER_HASHMAP_INSERT_NONSP_STR88_HITS: usize = 0;
/// : `entry|8` qword0 is factory `#4` `FUN_00877d40`, not identity `.text`.
pub const BOSMINER_ENTRY8_QWORD0_FN_VA: u64 = 0x0087_7D40;
pub const BOSMINER_ENTRY8_QWORD0_ADRP_VA: u64 = 0x0086_24A0;
pub const BOSMINER_ENTRY8_QWORD0_ADRP_INSN: u32 = 0xB000_00A9;
pub const BOSMINER_ENTRY8_QWORD0_ADD_VA: u64 = 0x0086_24A4;
pub const BOSMINER_ENTRY8_QWORD0_ADD_INSN: u32 = 0x9135_0129;
pub const BOSMINER_ENTRY8_QWORD0_STP_VA: u64 = 0x0086_24BC;
pub const BOSMINER_ENTRY8_QWORD0_STP_INSN: u32 = 0xA903_A3E9;
pub const BOSMINER_ENTRY8_1366_STP_VA: u64 = 0x0086_24D4;
pub const BOSMINER_ENTRY8_1366_STP_INSN: u32 = 0xA905_ABE9;
pub const BOSMINER_ENTRY8_SRC_ADD_VA: u64 = 0x0086_256C;
pub const BOSMINER_ENTRY8_SRC_ADD_INSN: u32 = 0x9100_C3E1;
pub const BOSMINER_ENTRY8_INSERT_BL_VA: u64 = 0x0086_2570;
pub const BOSMINER_ENTRY8_INSERT_BL_INSN: u32 = 0x9401_C928;
pub const BOSMINER_ENTRY8_INSERT_FN_VA: u64 = 0x008D_4A10;
pub const BOSMINER_ENTRY8_LDP_SRC_VA: u64 = 0x008D_4A40;
pub const BOSMINER_ENTRY8_LDP_SRC_INSN: u32 = 0xAD40_0680;
pub const BOSMINER_ENTRY8_STP_SP_VA: u64 = 0x008D_4A54;
pub const BOSMINER_ENTRY8_STP_SP_INSN: u32 = 0xAD00_07E0;
pub const BOSMINER_ENTRY8_SP_MOV_VA: u64 = 0x008D_4A44;
pub const BOSMINER_ENTRY8_SP_MOV_INSN: u32 = 0x9100_03F5;
pub const BOSMINER_FACTORY4_PROLOGUE_INSN: u32 = 0xA9BA_7BFD;
pub const BOSMINER_VT0_250_NONSP_STR88_HITS: usize = 0;
/// : factory4 vs `FUN_00876ca8` are sibling monomorphs; 1366 uses both.
pub const BOSMINER_FACTORY4_FN_VA: u64 = 0x0087_7D40;
pub const BOSMINER_FACTORY4_FRAME: u16 = 0x6C0;
pub const BOSMINER_FACTORY4_FRAME_VA: u64 = 0x0087_7D78;
pub const BOSMINER_FACTORY4_FRAME_INSN: u32 = 0xD11B_03FF;
pub const BOSMINER_FACTORY_876_FRAME: u16 = 0x690;
pub const BOSMINER_FACTORY_876_FRAME_VA: u64 = 0x0087_6CE0;
pub const BOSMINER_FACTORY_876_FRAME_INSN: u32 = 0xD11A_43FF;
pub const BOSMINER_FACTORY4_SNAP_SIZE: u16 = 0x1608;
pub const BOSMINER_FACTORY4_SNAP_SIZE_VA: u64 = 0x0087_7E50;
pub const BOSMINER_FACTORY4_SNAP_SIZE_INSN: u32 = 0x5282_C102;
pub const BOSMINER_FACTORY4_WORKER_NEW_VA: u64 = 0x0090_4434;
pub const BOSMINER_FACTORY4_WORKER_NEW_BL_VA: u64 = 0x0087_7E38;
pub const BOSMINER_FACTORY4_WORKER_NEW_BL_INSN: u32 = 0x9402_317F;
pub const BOSMINER_FACTORY_876_WORKER_NEW_VA: u64 = 0x0090_3534;
pub const BOSMINER_FACTORY4_CLONE_BL_VA: u64 = 0x0087_7DBC;
pub const BOSMINER_FACTORY_876_CLONE_BL_VA: u64 = 0x0087_6D24;
pub const BOSMINER_FACTORY_CLONE_TGT: u64 = 0x0087_5F54;
/// : worker_new monomorphs + factory extra-size family (`+0x10`).
pub const BOSMINER_WORKER_NEW_876_FRAME: u16 = 0xEE0;
pub const BOSMINER_WORKER_NEW_876_FRAME_VA: u64 = 0x0090_3550;
pub const BOSMINER_WORKER_NEW_876_FRAME_INSN: u32 = 0xD13B_83FF;
pub const BOSMINER_WORKER_NEW_FACTORY4_FRAME: u16 = 0xF00;
pub const BOSMINER_WORKER_NEW_FACTORY4_FRAME_VA: u64 = 0x0090_4450;
pub const BOSMINER_WORKER_NEW_FACTORY4_FRAME_INSN: u32 = 0xD13C_03FF;
pub const BOSMINER_FACTORY_876_COPY1600: u16 = 0x1600;
pub const BOSMINER_FACTORY_876_COPY1600_VA: u64 = 0x0087_6E58;
pub const BOSMINER_FACTORY_876_COPY1600_INSN: u32 = 0x5282_C002;
pub const BOSMINER_FACTORY4_COPY1610: u16 = 0x1610;
pub const BOSMINER_FACTORY4_COPY1610_VA: u64 = 0x0087_7EF0;
pub const BOSMINER_FACTORY4_COPY1610_INSN: u32 = 0x5282_C202;
pub const BOSMINER_FACTORY_876_COPY230_VA: u64 = 0x0087_6E80;
pub const BOSMINER_FACTORY4_COPY230_VA: u64 = 0x0087_7F18;
pub const BOSMINER_FACTORY_876_ALLOC1890: u16 = 0x1890;
pub const BOSMINER_FACTORY_876_ALLOC1890_VA: u64 = 0x0087_6EC4;
pub const BOSMINER_FACTORY_876_ALLOC1890_INSN: u32 = 0x5283_1202;
pub const BOSMINER_FACTORY4_ALLOC18A0: u16 = 0x18A0;
pub const BOSMINER_FACTORY4_ALLOC18A0_VA: u64 = 0x0087_7F5C;
pub const BOSMINER_FACTORY4_ALLOC18A0_INSN: u32 = 0x5283_1402;
pub const BOSMINER_WORKER_NEW_876_COPY1A8: u16 = 0x1A8;
pub const BOSMINER_WORKER_NEW_876_COPY1A8_VA: u64 = 0x0090_3690;
pub const BOSMINER_WORKER_NEW_876_COPY1A8_INSN: u32 = 0x5280_3502;
pub const BOSMINER_WORKER_NEW_FACTORY4_CA00: u16 = 0xCA00;
pub const BOSMINER_WORKER_NEW_FACTORY4_CA00_VA: u64 = 0x0090_44D8;
pub const BOSMINER_WORKER_NEW_FACTORY4_CA00_INSN: u32 = 0x5299_4009;
/// : `#0xca00` is the low half of `1_000_000_000`, not a type tag.
pub const BOSMINER_WORKER_NEW_FACTORY4_1E9: u32 = 1_000_000_000;
pub const BOSMINER_WORKER_NEW_FACTORY4_MOVK_VA: u64 = 0x0090_44E0;
pub const BOSMINER_WORKER_NEW_FACTORY4_MOVK_INSN: u32 = 0x72A7_7349;
pub const BOSMINER_WORKER_NEW_FACTORY4_CMP_VA: u64 = 0x0090_44E4;
pub const BOSMINER_WORKER_NEW_FACTORY4_CMP_INSN: u32 = 0x6B09_011F;
pub const BOSMINER_WORKER_NEW_FACTORY4_LDR_W8_VA: u64 = 0x0090_44D4;
pub const BOSMINER_WORKER_NEW_FACTORY4_LDR_W8_INSN: u32 = 0xB943_83E8;
pub const BOSMINER_WORKER_NEW_FACTORY4_BNE_VA: u64 = 0x0090_44E8;
pub const BOSMINER_WORKER_NEW_FACTORY4_BNE_INSN: u32 = 0x5400_06E1;
pub const BOSMINER_CA00_MOVZ_W9_HITS: usize = 230;
/// : both worker_new memcpy `#0x1a8` via `0xbc8fe0`; not the +16 field.
pub const BOSMINER_WORKER_NEW_FACTORY4_COPY1A8_VA: u64 = 0x0090_4690;
pub const BOSMINER_WORKER_NEW_876_MEMCPY_BL_VA: u64 = 0x0090_36CC;
pub const BOSMINER_WORKER_NEW_876_MEMCPY_BL_INSN: u32 = 0x940B_1645;
pub const BOSMINER_WORKER_NEW_FACTORY4_MEMCPY_BL_VA: u64 = 0x0090_46CC;
pub const BOSMINER_WORKER_NEW_FACTORY4_MEMCPY_BL_INSN: u32 = 0x940B_1245;
pub const BOSMINER_WORKER_NEW_MEMCPY_TGT: u64 = 0x00BC_8FE0;
pub const BOSMINER_WORKER_NEW_COPY1A8_TO_MEMCPY: u16 = 0x3C;
pub const BOSMINER_WORKER_NEW_1A8_MOVZ_HITS: usize = 64;
/// : extra 16 B is snap tail; dest `SP+#0x40` shared; src `#0x640` vs `#0x650`.
pub const BOSMINER_FACTORY4_SNAP_DEST_ADD_VA: u64 = 0x0087_7E4C;
pub const BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_VA: u64 = 0x0087_6DB0;
pub const BOSMINER_FACTORY4_SNAP_SRC_HIGH_ADD_VA: u64 = 0x0087_7E48;
pub const BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_INSN: u32 = 0x9140_07E8;
pub const BOSMINER_FACTORY_SNAP_SRC_HIGH: u16 = 0x1000;
pub const BOSMINER_FACTORY_876_SNAP_SRC_LOW_ADD_VA: u64 = 0x0087_6DBC;
pub const BOSMINER_FACTORY_876_SNAP_SRC_LOW_ADD_INSN: u32 = 0x9119_0108;
pub const BOSMINER_FACTORY4_SNAP_SRC_LOW_ADD_VA: u64 = 0x0087_7E54;
pub const BOSMINER_FACTORY4_SNAP_SRC_LOW_ADD_INSN: u32 = 0x9119_4108;
pub const BOSMINER_FACTORY_SNAP_SRC_LOW: u16 = 0x640;
pub const BOSMINER_FACTORY4_SNAP_SRC_LOW: u16 = 0x650;
pub const BOSMINER_FACTORY_SNAP_DEST_OFF: u16 = 0x40;
pub const BOSMINER_ENTRY8_PLUS10_STR_VA: u64 = 0x0086_24C8;
pub const BOSMINER_ENTRY8_PLUS10_STR_INSN: u32 = 0xF900_27E8;
pub const BOSMINER_ENTRY8_PLUS10_MOVZ_VA: u64 = 0x0086_24C0;
pub const BOSMINER_ENTRY8_PLUS10_MOVZ_INSN: u32 = 0x5295_E108;
pub const BOSMINER_ENTRY8_PLUS10_MOVK_VA: u64 = 0x0086_24C4;
pub const BOSMINER_ENTRY8_PLUS10_MOVK_INSN: u32 = 0x72A0_05E8;
pub const BOSMINER_ENTRY8_PLUS10_VALUE: u32 = 0x002F_AF08;
/// : extra 16 B is worker_new `STR` at `+0x15F8` and `+0x1600`.
pub const BOSMINER_WORKER_NEW_876_STR_15F8_VA: u64 = 0x0090_3F90;
pub const BOSMINER_WORKER_NEW_876_STR_15F8_INSN: u32 = 0xF90A_FEC9;
pub const BOSMINER_WORKER_NEW_876_STR_1600_VA: u64 = 0x0090_3FC4;
pub const BOSMINER_WORKER_NEW_876_STR_1600_INSN: u32 = 0xF90B_02D5;
pub const BOSMINER_WORKER_NEW_FACTORY4_STR_15F8_VA: u64 = 0x0090_4ED4;
pub const BOSMINER_WORKER_NEW_FACTORY4_STR_15F8_INSN: u32 = 0xF90A_FEB3;
pub const BOSMINER_WORKER_NEW_FACTORY4_STR_1600_VA: u64 = 0x0090_4EC0;
pub const BOSMINER_WORKER_NEW_FACTORY4_STR_1600_INSN: u32 = 0xF90B_02A9;
pub const BOSMINER_WORKER_NEW_TAIL_Q0_OFF: u16 = 0x15F8;
pub const BOSMINER_WORKER_NEW_TAIL_Q1_OFF: u16 = 0x1600;
/// : 876 `+0x15F8` is arg0 (`X0`); `+0x1600` is the following call return.
pub const BOSMINER_WORKER_NEW_876_MOV_X24_X0_VA: u64 = 0x0090_3560;
pub const BOSMINER_WORKER_NEW_876_MOV_X24_X0_INSN: u32 = 0xAA00_03F8;
pub const BOSMINER_WORKER_NEW_876_MOV_X22_X8_VA: u64 = 0x0090_3564;
pub const BOSMINER_WORKER_NEW_876_MOV_X22_X8_INSN: u32 = 0xAA08_03F6;
pub const BOSMINER_WORKER_NEW_876_STR_X24_SP30_VA: u64 = 0x0090_3E30;
pub const BOSMINER_WORKER_NEW_876_STR_X24_SP30_INSN: u32 = 0xF900_1BF8;
pub const BOSMINER_WORKER_NEW_876_LDR_X9_SP30_VA: u64 = 0x0090_3F64;
pub const BOSMINER_WORKER_NEW_876_LDR_X9_SP30_INSN: u32 = 0xF940_1BE9;
pub const BOSMINER_WORKER_NEW_876_STR_13B8_VA: u64 = 0x0090_3F78;
pub const BOSMINER_WORKER_NEW_876_STR_13B8_INSN: u32 = 0xF909_DEC9;
pub const BOSMINER_WORKER_NEW_876_MOV_X0_X24_VA: u64 = 0x0090_3754;
pub const BOSMINER_WORKER_NEW_876_MOV_X0_X24_INSN: u32 = 0xAA18_03E0;
pub const BOSMINER_WORKER_NEW_876_CALL_BL_VA: u64 = 0x0090_375C;
pub const BOSMINER_WORKER_NEW_876_CALL_BL_INSN: u32 = 0x940B_BF12;
pub const BOSMINER_WORKER_NEW_876_CALL_TGT: u64 = 0x00BF_33A4;
pub const BOSMINER_WORKER_NEW_876_STR_SP5F0_VA: u64 = 0x0090_3768;
pub const BOSMINER_WORKER_NEW_876_STR_SP5F0_INSN: u32 = 0xF902_FBE0;
pub const BOSMINER_WORKER_NEW_876_LDR_X21_SP5F0_VA: u64 = 0x0090_3F00;
pub const BOSMINER_WORKER_NEW_876_LDR_X21_SP5F0_INSN: u32 = 0xF942_FBF5;
pub const BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_VA: u64 = 0x0090_4E6C;
pub const BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN: u32 = 0x5282_4129;
pub const BOSMINER_WORKER_NEW_FACTORY4_1209: u16 = 0x1209;
pub const BOSMINER_AF08_MOVZ_W8_HITS: usize = 4;
pub const BOSMINER_AF08_CMP_VA: u64 = 0x00BC_00B4;
pub const BOSMINER_AF08_CMP_INSN: u32 = 0xEB08_003F;
pub const BOSMINER_AF08_CLASS11_VA: u64 = 0x00BC_00BC;
pub const BOSMINER_AF08_CLASS11_INSN: u32 = 0x5280_0174;
pub const BOSMINER_AF08_CLASS10_VA: u64 = 0x00BC_00C4;
pub const BOSMINER_AF08_CLASS10_INSN: u32 = 0x5280_0154;
/// : factory X23 is factory X0; `FUN_00bf33a4` is a 0x70 box; `#0x1209` is end offset.
pub const BOSMINER_FACTORY_876_MOV_X23_X0_VA: u64 = 0x0087_6D08;
pub const BOSMINER_FACTORY4_MOV_X23_X0_VA: u64 = 0x0087_7DA0;
pub const BOSMINER_FACTORY_MOV_X23_X0_INSN: u32 = 0xAA00_03F7;
pub const BOSMINER_FACTORY4_MOV_X0_X23_VA: u64 = 0x0087_7E24;
pub const BOSMINER_FACTORY_MOV_X0_X23_INSN: u32 = 0xAA17_03E0;
pub const BOSMINER_BF33A4_FRAME_INSN: u32 = 0xD102_03FF;
pub const BOSMINER_BF33A4_SIZE: u16 = 0x70;
pub const BOSMINER_BF33A4_SIZE_VA: u64 = 0x00BF_33E4;
pub const BOSMINER_BF33A4_SIZE_INSN: u32 = 0x5280_0E00;
pub const BOSMINER_BF33A4_ALIGN_VA: u64 = 0x00BF_33E8;
pub const BOSMINER_BF33A4_ALIGN_INSN: u32 = 0x5280_0101;
pub const BOSMINER_BF33A4_ALLOC_BL_VA: u64 = 0x00BF_3400;
pub const BOSMINER_BF33A4_ALLOC_BL_INSN: u32 = 0x97E8_059E;
pub const BOSMINER_BF33A4_STR20_VA: u64 = 0x00BF_3424;
pub const BOSMINER_BF33A4_STR20_INSN: u32 = 0xF900_1017;
pub const BOSMINER_BF33A4_RET_VA: u64 = 0x00BF_3448;
pub const BOSMINER_BF33A4_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_WORKER_NEW_876_MOVZ_1209_VA: u64 = 0x0090_3F2C;
pub const BOSMINER_WORKER_NEW_876_ADD_1209_VA: u64 = 0x0090_3F34;
pub const BOSMINER_WORKER_NEW_876_ADD_1209_INSN: u32 = 0x8B09_02C0;
pub const BOSMINER_WORKER_NEW_876_MOVZ_1208_VA: u64 = 0x0090_3F44;
pub const BOSMINER_WORKER_NEW_COPY1208_INSN: u32 = 0x5282_4108;
pub const BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1208_VA: u64 = 0x0090_4E74;
pub const BOSMINER_WORKER_NEW_FACTORY4_ADD_1209_VA: u64 = 0x0090_4E78;
pub const BOSMINER_WORKER_NEW_FACTORY4_ADD_1209_INSN: u32 = 0x8B09_02A0;
pub const BOSMINER_WORKER_NEW_COPY1208: u16 = 0x1208;
/// : 0x70 box fields; 0x1af copy to obj+0x1209; no factory-self LDR.
pub const BOSMINER_BF33A4_STR10_VA: u64 = 0x00BF_3414;
pub const BOSMINER_BF33A4_STR10_INSN: u32 = 0xF900_0816;
pub const BOSMINER_BF33A4_STRB18_VA: u64 = 0x00BF_341C;
pub const BOSMINER_BF33A4_STRB18_INSN: u32 = 0x3900_6015;
pub const BOSMINER_BF33A4_STP60_VA: u64 = 0x00BF_342C;
pub const BOSMINER_BF33A4_STP60_INSN: u32 = 0xA906_4C14;
pub const BOSMINER_BF33A4_STP48_VA: u64 = 0x00BF_3440;
pub const BOSMINER_BF33A4_STP48_INSN: u32 = 0xA904_FC08;
pub const BOSMINER_BF33A4_STRQ0_VA: u64 = 0x00BF_3438;
pub const BOSMINER_BF33A4_STRQ0_INSN: u32 = 0x3D80_0000;
pub const BOSMINER_BF33A4_BL_HITS: usize = 6;
pub const BOSMINER_BF33A4_FACTORY4_BL_VA: u64 = 0x0090_4758;
pub const BOSMINER_BF33A4_FACTORY4_BL_INSN: u32 = 0x940B_BB13;
pub const BOSMINER_BF33A4_FACTORY4_STR_SP610_VA: u64 = 0x0090_4764;
pub const BOSMINER_BF33A4_FACTORY4_STR_SP610_INSN: u32 = 0xF903_0BE0;
pub const BOSMINER_WORKER_NEW_COPY1AF: u16 = 0x1AF;
pub const BOSMINER_WORKER_NEW_COPY1AF_INSN: u32 = 0x5280_35E2;
pub const BOSMINER_WORKER_NEW_876_COPY1AF_VA: u64 = 0x0090_3F38;
pub const BOSMINER_WORKER_NEW_FACTORY4_COPY1AF_VA: u64 = 0x0090_4E5C;
pub const BOSMINER_WORKER_NEW_COPY1AF_HITS: usize = 6;
pub const BOSMINER_WORKER_NEW_876_SRC840_VA: u64 = 0x0090_3F30;
pub const BOSMINER_WORKER_NEW_876_SRC840_INSN: u32 = 0x9121_03E1;
pub const BOSMINER_WORKER_NEW_FACTORY4_SRC860_VA: u64 = 0x0090_4E58;
pub const BOSMINER_WORKER_NEW_FACTORY4_SRC860_INSN: u32 = 0x9121_83E1;
pub const BOSMINER_WORKER_NEW_876_STR_11E0_VA: u64 = 0x0090_3F48;
pub const BOSMINER_WORKER_NEW_876_STR_11E0_INSN: u32 = 0xF908_F2DF;
pub const BOSMINER_WORKER_NEW_876_STR_1200_VA: u64 = 0x0090_3F54;
pub const BOSMINER_WORKER_NEW_876_STR_1200_INSN: u32 = 0xF909_02D9;
pub const BOSMINER_WORKER_NEW_876_STRB_1208_VA: u64 = 0x0090_3F58;
pub const BOSMINER_WORKER_NEW_876_STRB_1208_INSN: u32 = 0x3828_6AD3;
pub const BOSMINER_FACTORY_SELF_X23_LDR_HITS: usize = 0;
pub const BOSMINER_FACTORY_DIRECT_BL_HITS: usize = 0;
/// : `FUN_011f26f8` zeros + tag; `0x1af=7+0x1a8`; factory4 `SP+#0x610` drop.
pub const BOSMINER_F11F26F8_FN_VA: u64 = 0x011F_26F8;
pub const BOSMINER_F11F26F8_LSR_INSN: u32 = 0xD37D_FC09;
pub const BOSMINER_F11F26F8_LSL_VA: u64 = 0x011F_2700;
pub const BOSMINER_F11F26F8_LSL_INSN: u32 = 0xD37F_F809;
pub const BOSMINER_F11F26F8_STP0_VA: u64 = 0x011F_2704;
pub const BOSMINER_F11F26F8_STP0_INSN: u32 = 0xA900_7D1F;
pub const BOSMINER_F11F26F8_STR20_VA: u64 = 0x011F_2710;
pub const BOSMINER_F11F26F8_STR20_INSN: u32 = 0xF900_1109;
pub const BOSMINER_F11F26F8_RET_VA: u64 = 0x011F_2714;
pub const BOSMINER_F11F26F8_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_BF33A4_INIT_ARG: u8 = 1;
pub const BOSMINER_BF33A4_INIT_TAG: u8 = 2;
pub const BOSMINER_BF33A4_LDURQ0_VA: u64 = 0x00BF_33D4;
pub const BOSMINER_BF33A4_LDURQ0_INSN: u32 = 0x3CC2_83E0;
pub const BOSMINER_BF33A4_LDURQ1_VA: u64 = 0x00BF_33D8;
pub const BOSMINER_BF33A4_LDURQ1_INSN: u32 = 0x3CC3_83E1;
pub const BOSMINER_BF33A4_INIT_DEST_ADD_VA: u64 = 0x00BF_33C8;
pub const BOSMINER_BF33A4_INIT_DEST_ADD_INSN: u32 = 0x9100_A3E8;
pub const BOSMINER_BF33A4_INIT_ARG_VA: u64 = 0x00BF_33CC;
pub const BOSMINER_BF33A4_INIT_ARG_INSN: u32 = 0x5280_0020;
pub const BOSMINER_WORKER_NEW_1AF_PREFIX: u16 = 7;
pub const BOSMINER_WORKER_NEW_876_BLOB840_VA: u64 = 0x0090_3E60;
pub const BOSMINER_WORKER_NEW_876_BLOB840_INSN: u32 = 0x9121_03E8;
pub const BOSMINER_WORKER_NEW_BLOB_PLUS7_VA: u64 = 0x0090_3E64;
pub const BOSMINER_WORKER_NEW_BLOB_PLUS7_INSN: u32 = 0x9100_1D00;
pub const BOSMINER_WORKER_NEW_FACTORY4_BLOB860_VA: u64 = 0x0090_4D7C;
pub const BOSMINER_WORKER_NEW_FACTORY4_BLOB860_INSN: u32 = 0x9121_83E8;
pub const BOSMINER_FACTORY4_610_DROP_ADD_VA: u64 = 0x0090_51C0;
pub const BOSMINER_FACTORY4_610_DROP_ADD_INSN: u32 = 0x9118_43E0;
pub const BOSMINER_FACTORY4_610_DROP_BL_VA: u64 = 0x0090_51C4;
pub const BOSMINER_FACTORY4_610_DROP_BL_INSN: u32 = 0x9408_F2EF;
pub const BOSMINER_FACTORY4_610_DROP_TGT: u64 = 0x00B4_1D80;
pub const BOSMINER_FACTORY4_610_LDR_HITS: usize = 3;
/// : 7-byte prefix source; `FUN_00b41d80` is 0x70/8 drop; Q2 from `LDP [SP]`.
pub const BOSMINER_B41D80_FN_VA: u64 = 0x00B4_1D80;
pub const BOSMINER_B41D80_LDR_SLOT_VA: u64 = 0x00B4_1D88;
pub const BOSMINER_B41D80_LDR_SLOT_INSN: u32 = 0xF940_0013;
pub const BOSMINER_B41D80_SIZE_VA: u64 = 0x00B4_1DDC;
pub const BOSMINER_B41D80_SIZE_INSN: u32 = 0x5280_0E01;
pub const BOSMINER_B41D80_ALIGN_VA: u64 = 0x00B4_1DE4;
pub const BOSMINER_B41D80_ALIGN_INSN: u32 = 0x5280_0102;
pub const BOSMINER_B41D80_B_DEALLOC_VA: u64 = 0x00B4_1DEC;
pub const BOSMINER_B41D80_B_DEALLOC_INSN: u32 = 0x17EA_CB24;
pub const BOSMINER_B41D80_BL_HITS: usize = 54;
pub const BOSMINER_BF33A4_LDP_Q12_VA: u64 = 0x00BF_340C;
pub const BOSMINER_BF33A4_LDP_Q12_INSN: u32 = 0xAD40_0BE1;
pub const BOSMINER_BF33A4_STURQ2_VA: u64 = 0x00BF_343C;
pub const BOSMINER_BF33A4_STURQ2_INSN: u32 = 0x3C83_8002;
pub const BOSMINER_FACTORY4_PREFIX_LDR_VA: u64 = 0x0090_4C98;
pub const BOSMINER_FACTORY4_PREFIX_LDR_INSN: u32 = 0xF947_67E9;
pub const BOSMINER_FACTORY4_PREFIX_STR_VA: u64 = 0x0090_4CA8;
pub const BOSMINER_FACTORY4_PREFIX_STR_INSN: u32 = 0xF904_23E9;
pub const BOSMINER_876_EC8_STR_VA: u64 = 0x0090_3E24;
pub const BOSMINER_876_EC8_STR_INSN: u32 = 0xF907_67E1;
pub const BOSMINER_876_BLOB840_STR_HITS: usize = 0;
/// : factory4 prefix is `FUN_00887c34` 0x98 box; Q2 is helper zeros; `FUN_00bbd3dc` dual-inc.
pub const BOSMINER_887C34_FN_VA: u64 = 0x0088_7C34;
pub const BOSMINER_887C34_FRAME_INSN: u32 = 0xD102_C3FF;
pub const BOSMINER_887C34_SIZE_VA: u64 = 0x0088_7C70;
pub const BOSMINER_887C34_SIZE_INSN: u32 = 0x5280_1300;
pub const BOSMINER_887C34_ALIGN_VA: u64 = 0x0088_7C44;
pub const BOSMINER_887C34_ALIGN_INSN: u32 = 0x5280_0101;
pub const BOSMINER_887C34_ALLOC_BL_VA: u64 = 0x0088_7C8C;
pub const BOSMINER_887C34_ALLOC_BL_INSN: u32 = 0x97F5_B37B;
pub const BOSMINER_887C34_MOV_X1_X0_VA: u64 = 0x0088_7CDC;
pub const BOSMINER_887C34_MOV_X1_X0_INSN: u32 = 0xAA00_03E1;
pub const BOSMINER_887C34_RET_VA: u64 = 0x0088_7CE4;
pub const BOSMINER_887C34_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_887C34_BL_HITS: usize = 5;
pub const BOSMINER_887C34_SIZE: u16 = 0x98;
pub const BOSMINER_FACTORY4_XZR_VA: u64 = 0x0090_46D0;
pub const BOSMINER_FACTORY4_XZR_INSN: u32 = 0xAA1F_03E0;
pub const BOSMINER_FACTORY4_887C34_BL_VA: u64 = 0x0090_46D4;
pub const BOSMINER_FACTORY4_887C34_BL_INSN: u32 = 0x97FE_0D58;
pub const BOSMINER_FACTORY4_STR600_VA: u64 = 0x0090_46E4;
pub const BOSMINER_FACTORY4_STR600_INSN: u32 = 0xF903_03E0;
pub const BOSMINER_FACTORY4_STR608_VA: u64 = 0x0090_46EC;
pub const BOSMINER_FACTORY4_STR608_INSN: u32 = 0xF903_07E1;
pub const BOSMINER_FACTORY4_LDR600_VA: u64 = 0x0090_4AA8;
pub const BOSMINER_FACTORY4_LDR600_INSN: u32 = 0xF943_03E8;
pub const BOSMINER_FACTORY4_STR_EC8_FROM600_VA: u64 = 0x0090_4AB0;
pub const BOSMINER_FACTORY4_STR_EC8_FROM600_INSN: u32 = 0xF907_67E8;
pub const BOSMINER_876_XZR_VA: u64 = 0x0090_36D0;
pub const BOSMINER_876_XZR_INSN: u32 = 0xAA1F_03E0;
pub const BOSMINER_876_887C34_BL_VA: u64 = 0x0090_36D4;
pub const BOSMINER_876_887C34_BL_INSN: u32 = 0x97FE_1158;
pub const BOSMINER_876_STR5E0_VA: u64 = 0x0090_36E8;
pub const BOSMINER_876_STR5E0_INSN: u32 = 0xF902_F3E0;
pub const BOSMINER_BBD3DC_FN_VA: u64 = 0x00BB_D3DC;
pub const BOSMINER_BBD3DC_LDR_INSN: u32 = 0xF940_0000;
pub const BOSMINER_BBD3DC_LDAXR_VA: u64 = 0x00BB_D3E0;
pub const BOSMINER_BBD3DC_LDAXR_INSN: u32 = 0xC85F_7C08;
pub const BOSMINER_BBD3DC_ADD48_VA: u64 = 0x00BB_D3F4;
pub const BOSMINER_BBD3DC_ADD48_INSN: u32 = 0x9101_2008;
pub const BOSMINER_BBD3DC_LDAXR1_VA: u64 = 0x00BB_D3F8;
pub const BOSMINER_BBD3DC_LDAXR1_INSN: u32 = 0xC85F_FD01;
pub const BOSMINER_BBD3DC_RET_VA: u64 = 0x00BB_D408;
pub const BOSMINER_BBD3DC_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_BBD3DC_BL_HITS: usize = 11;
pub const BOSMINER_876_BBD3DC_BL_VA: u64 = 0x0090_3E14;
pub const BOSMINER_876_BBD3DC_BL_INSN: u32 = 0x940A_E572;
pub const BOSMINER_876_STR_EC0_VA: u64 = 0x0090_3E1C;
pub const BOSMINER_876_STR_EC0_INSN: u32 = 0xF907_63E0;
pub const BOSMINER_FACTORY4_BBD3DC_BL_VA: u64 = 0x0090_4D30;
pub const BOSMINER_FACTORY4_BBD3DC_BL_INSN: u32 = 0x940A_E1AB;
pub const BOSMINER_FACTORY4_STR_EE0_VA: u64 = 0x0090_4D38;
pub const BOSMINER_FACTORY4_STR_EE0_INSN: u32 = 0xF907_73E0;
pub const BOSMINER_FACTORY4_STR_EE8_VA: u64 = 0x0090_4D40;
pub const BOSMINER_FACTORY4_STR_EE8_INSN: u32 = 0xF907_77E1;
pub const BOSMINER_BF33A4_STRQ0_SP_VA: u64 = 0x00BF_33EC;
pub const BOSMINER_BF33A4_STRQ0_SP_INSN: u32 = 0x3D80_03E0;
pub const BOSMINER_BF33A4_STRQ1_SP10_VA: u64 = 0x00BF_33F4;
pub const BOSMINER_BF33A4_STRQ1_SP10_INSN: u32 = 0x3D80_07E1;
pub const BOSMINER_BF33A4_STURQ1_28_VA: u64 = 0x00BF_3434;
pub const BOSMINER_BF33A4_STURQ1_28_INSN: u32 = 0x3C82_8001;
/// : 0x98 box is ArcInner; +0 strong; arg at +0x58; three `#8` at +0x20/+0x40/+0x68.
pub const BOSMINER_887C34_MOVZ8_VA: u64 = 0x0088_7C4C;
pub const BOSMINER_887C34_MOVZ8_INSN: u32 = 0x5280_0108;
pub const BOSMINER_887C34_STRQ0_VA: u64 = 0x0088_7C5C;
pub const BOSMINER_887C34_STRQ0_INSN: u32 = 0x3D80_03E0;
pub const BOSMINER_887C34_STP20_VA: u64 = 0x0088_7C64;
pub const BOSMINER_887C34_STP20_INSN: u32 = 0xA901_A3FF;
pub const BOSMINER_887C34_STP40_VA: u64 = 0x0088_7C68;
pub const BOSMINER_887C34_STP40_INSN: u32 = 0xA903_A3FF;
pub const BOSMINER_887C34_STP58_VA: u64 = 0x0088_7C6C;
pub const BOSMINER_887C34_STP58_INSN: u32 = 0xA905_FFE0;
pub const BOSMINER_887C34_STR68_VA: u64 = 0x0088_7C74;
pub const BOSMINER_887C34_STR68_INSN: u32 = 0xF900_37E8;
pub const BOSMINER_887C34_LDAXR_VA: u64 = 0x0088_7CC4;
pub const BOSMINER_887C34_LDAXR_INSN: u32 = 0xC85F_7C08;
pub const BOSMINER_887C34_STR90_VA: u64 = 0x0088_7CAC;
pub const BOSMINER_887C34_STR90_INSN: u32 = 0xF900_4808;
pub const BOSMINER_887C34_ARG_OFF: u16 = 0x58;
pub const BOSMINER_887C34_USIZE8_OFFS: [u16; 3] = [0x20, 0x40, 0x68];
/// : 0x1af prefix is unwritten; Arc slot != blob; three `8`s are Layout.align.
pub const BOSMINER_FACTORY4_ARC_SLOT: u16 = 0x840;
pub const BOSMINER_FACTORY4_BLOB_SLOT: u16 = 0x860;
pub const BOSMINER_876_BLOB_SLOT: u16 = 0x840;
pub const BOSMINER_FACTORY4_ARC_BLOB_GAP: u16 = 0x20;
pub const BOSMINER_FACTORY4_BLOB860_STR_HITS: usize = 0;
pub const BOSMINER_FACTORY4_BLOB_PLUS7_VA: u64 = 0x0090_4D80;
pub const BOSMINER_FACTORY4_BLOB_PLUS7_INSN: u32 = 0x9100_1D00;
pub const BOSMINER_FACTORY4_1AF_SRC_VA: u64 = 0x0090_4E58;
pub const BOSMINER_FACTORY4_1AF_SRC_INSN: u32 = 0x9121_83E1;
pub const BOSMINER_887C34_LAYOUT_ALIGN: u16 = 8;
pub const BOSMINER_887C34_LAYOUT_SIZE_OFFS: [u16; 3] = [0x18, 0x38, 0x60];
/// : 0x1af = 7-byte pad after u8 @ +0x1208 so payload is 8-aligned @ +0x1210.
pub const BOSMINER_WORKER_NEW_1AF_ALIGNED: u16 = 0x1210;
pub const BOSMINER_WORKER_NEW_1AF_END: u16 = 0x13B8;
pub const BOSMINER_FACTORY4_STRB_1208_VA: u64 = 0x0090_4E84;
pub const BOSMINER_FACTORY4_STRB_1208_INSN: u32 = 0x3828_6AB4;
pub const BOSMINER_FACTORY4_DEST1209_ADD_VA: u64 = 0x0090_4E78;
pub const BOSMINER_FACTORY4_DEST1209_ADD_INSN: u32 = 0x8B09_02A0;
pub const BOSMINER_FACTORY4_STR_13B8_VA: u64 = 0x0090_4EA4;
pub const BOSMINER_FACTORY4_STR_13B8_INSN: u32 = 0xF909_DEA9;
pub const BOSMINER_876_STR_13B8_VA: u64 = 0x0090_3F78;
pub const BOSMINER_876_STR_13B8_INSN: u32 = 0xF909_DEC9;
/// : +0x1208 u8 is `*(Worker::new X1 + 0xC8)` via bf33a4 box+0x18; 0x1a8 src is local.
pub const BOSMINER_WORKER_NEW_ARG1_C8: u16 = 0xC8;
pub const BOSMINER_WORKER_NEW_ARG1_158: u16 = 0x158;
pub const BOSMINER_876_LDRB_ARG1_C8_VA: u64 = 0x0090_373C;
pub const BOSMINER_876_LDRB_ARG1_C8_INSN: u32 = 0x3943_233A;
pub const BOSMINER_876_MOV_W4_W26_VA: u64 = 0x0090_3758;
pub const BOSMINER_876_MOV_W4_W26_INSN: u32 = 0x2A1A_03E4;
pub const BOSMINER_FACTORY4_LDRB_ARG1_C8_VA: u64 = 0x0090_4740;
pub const BOSMINER_FACTORY4_LDRB_ARG1_C8_INSN: u32 = 0x3943_2304;
pub const BOSMINER_876_BOX_STR_5F0_VA: u64 = 0x0090_3768;
pub const BOSMINER_876_BOX_STR_5F0_INSN: u32 = 0xF902_FBE0;
pub const BOSMINER_876_BOX_LDR_5F0_VA: u64 = 0x0090_3DE0;
pub const BOSMINER_876_BOX_LDR_5F0_INSN: u32 = 0xF942_FBE8;
pub const BOSMINER_876_LDRB_BOX18_VA: u64 = 0x0090_3E04;
pub const BOSMINER_876_LDRB_BOX18_INSN: u32 = 0x3940_6113;
pub const BOSMINER_FACTORY4_LDRB_BOX18_VA: u64 = 0x0090_4D28;
pub const BOSMINER_FACTORY4_LDRB_BOX18_INSN: u32 = 0x3940_6116;
pub const BOSMINER_FACTORY4_MOV_W20_W22_VA: u64 = 0x0090_4DE4;
pub const BOSMINER_FACTORY4_MOV_W20_W22_INSN: u32 = 0x2A16_03F4;
pub const BOSMINER_876_1A8_SRC_VA: u64 = 0x0090_3E50;
pub const BOSMINER_876_1A8_SRC_INSN: u32 = 0x910D_43E1;
pub const BOSMINER_FACTORY4_1A8_SRC_VA: u64 = 0x0090_4D68;
pub const BOSMINER_FACTORY4_1A8_SRC_INSN: u32 = 0x910D_C3E1;
/// : HashChain+0xC8 is a u8 state tag; 0x1a8 local is Registry wrap output.
pub const BOSMINER_HASHCHAIN_C8_MATCH_LDRB_VA: u64 = 0x008D_6858;
pub const BOSMINER_HASHCHAIN_C8_MATCH_LDRB_INSN: u32 = 0x3943_2008;
pub const BOSMINER_HASHCHAIN_C8_CMP1_VA: u64 = 0x008D_6864;
pub const BOSMINER_HASHCHAIN_C8_CMP1_INSN: u32 = 0x7100_051F;
pub const BOSMINER_HASHCHAIN_C8_CMP3_VA: u64 = 0x008D_689C;
pub const BOSMINER_HASHCHAIN_C8_CMP3_INSN: u32 = 0x7100_0D1F;
pub const BOSMINER_HASHCHAIN_C8_CMP2_VA: u64 = 0x008D_68B0;
pub const BOSMINER_HASHCHAIN_C8_CMP2_INSN: u32 = 0x7100_091F;
pub const BOSMINER_HASHCHAIN_C8_SET1_VA: u64 = 0x008D_69BC;
pub const BOSMINER_HASHCHAIN_C8_SET1_INSN: u32 = 0x5280_0028;
pub const BOSMINER_HASHCHAIN_C8_STR1_VA: u64 = 0x008D_69C0;
pub const BOSMINER_HASHCHAIN_C8_STR_INSN: u32 = 0x3903_2268;
pub const BOSMINER_HASHCHAIN_C8_SET3_VA: u64 = 0x008D_69DC;
pub const BOSMINER_HASHCHAIN_C8_SET3_INSN: u32 = 0x5280_0068;
pub const BOSMINER_HASHCHAIN_C8_SET2_VA: u64 = 0x008D_6A84;
pub const BOSMINER_HASHCHAIN_C8_SET2_INSN: u32 = 0x5280_0048;
pub const BOSMINER_HASHCHAIN_C8_CMP3_HITS: usize = 77;
pub const BOSMINER_HASHCHAIN_C8_CMP1_HITS: usize = 11;
pub const BOSMINER_876_REGISTRY_WRAP_DEST_VA: u64 = 0x0090_3678;
pub const BOSMINER_876_REGISTRY_WRAP_DEST_INSN: u32 = 0x910D_43F3;
pub const BOSMINER_876_REGISTRY_WRAP_BL_VA: u64 = 0x0090_367C;
pub const BOSMINER_876_REGISTRY_WRAP_BL_INSN: u32 = 0x940B_D047;
pub const BOSMINER_FACTORY4_REGISTRY_WRAP_DEST_VA: u64 = 0x0090_4674;
pub const BOSMINER_FACTORY4_REGISTRY_WRAP_DEST_INSN: u32 = 0x910D_C3F3;
/// : FUN_008d684c is `command.rs:700` async poll. +0xC8 tags are
/// rustc Future states, not HashChain Running/Starting.
pub const BOSMINER_HAL_COMMAND_RS: &str = "/build/source/open/bosminer/bosminer-hal/src/command.rs";
pub const BOSMINER_HAL_COMMAND_RS_LEN: usize = 55;
pub const BOSMINER_C8_ASYNC_FN_LINE: u16 = 700;
pub const BOSMINER_C8_ASYNC_FN_COL: u16 = 51;
pub const BOSMINER_C8_NESTED_ASYNC_LINE: u16 = 719;
pub const BOSMINER_C8_NESTED_ASYNC_COL: u16 = 12;
pub const BOSMINER_C8_ASYNC_LOC_VA: u64 = 0x019C_7190;
pub const BOSMINER_C8_NESTED_ASYNC_LOC_VA: u64 = 0x019C_7160;
pub const BOSMINER_C8_TAG_UNRESUMED: u8 = 0;
pub const BOSMINER_C8_TAG_COMPLETED: u8 = 1;
pub const BOSMINER_C8_TAG_PANICKED: u8 = 2;
pub const BOSMINER_C8_TAG_SUSPENDED: u8 = 3;
/// `CBNZ W8,0x8d69f8` after `CMP #1`/`B.GT` — tag==1 → completed-resume panic.
pub const BOSMINER_C8_TAG1_CBNZ_VA: u64 = 0x008D_686C;
pub const BOSMINER_C8_TAG1_CBNZ_INSN: u32 = 0x3500_0C68;
/// `B.NE 0x8d6a04` after `CMP #3` — tag>1 && tag!=3 → panicked-resume helper.
pub const BOSMINER_C8_TAG_NE3_B_VA: u64 = 0x008D_68A0;
pub const BOSMINER_C8_TAG_NE3_B_INSN: u32 = 0x5400_0B21;
pub const BOSMINER_C8_ASYNC_DONE_ADRP_VA: u64 = 0x008D_69F8;
pub const BOSMINER_C8_ASYNC_DONE_ADRP_INSN: u32 = 0xB000_8780;
pub const BOSMINER_C8_ASYNC_DONE_ADD_VA: u64 = 0x008D_69FC;
pub const BOSMINER_C8_ASYNC_DONE_ADD_INSN: u32 = 0x9106_4000;
pub const BOSMINER_C8_ASYNC_DONE_BL_VA: u64 = 0x008D_6A00;
pub const BOSMINER_C8_ASYNC_DONE_BL_INSN: u32 = 0x97ED_F490;
pub const BOSMINER_C8_ASYNC_PANIC_BL_VA: u64 = 0x008D_6A0C;
pub const BOSMINER_C8_ASYNC_PANIC_BL_INSN: u32 = 0x97ED_F49A;
pub const BOSMINER_C8_NESTED_ADD_VA: u64 = 0x008D_6A1C;
pub const BOSMINER_C8_NESTED_ADD_INSN: u32 = 0x9105_8000;
pub const BOSMINER_C8_COMPLETE_RET_VA: u64 = 0x008D_69B8;
pub const BOSMINER_C8_COMPLETE_RET_INSN: u32 = 0x2A1F_03E0;
pub const BOSMINER_C8_PENDING_RET_VA: u64 = 0x008D_69E0;
pub const BOSMINER_C8_PENDING_RET_INSN: u32 = 0x5280_0020;
pub const BOSMINER_ASYNC_DONE_HELPER_VA: u64 = 0x0045_3C40;
pub const BOSMINER_ASYNC_PANIC_HELPER_VA: u64 = 0x0045_3C74;
pub const BOSMINER_ASYNC_DONE_HELPER_ADD_VA: u64 = 0x0045_3C50;
pub const BOSMINER_ASYNC_DONE_HELPER_ADD_INSN: u32 = 0x9111_C108;
pub const BOSMINER_ASYNC_PANIC_HELPER_ADD_VA: u64 = 0x0045_3C84;
pub const BOSMINER_ASYNC_PANIC_HELPER_ADD_INSN: u32 = 0x9112_0108;
pub const BOSMINER_ASYNC_DONE_MSG: &str = "`async fn` resumed after completion";
pub const BOSMINER_ASYNC_PANIC_MSG: &str = "`async fn` resumed after panicking";
pub const BOSMINER_ASYNC_DONE_MSG_VA: u64 = 0x0160_EAAA;
pub const BOSMINER_ASYNC_PANIC_MSG_VA: u64 = 0x0160_EACD;
pub const BOSMINER_ASYNC_DONE_MSG_LEN: usize = 35;
pub const BOSMINER_ASYNC_PANIC_MSG_LEN: usize = 34;
/// rustc Location file ptr shared by :700 and :719.
pub const BOSMINER_HAL_COMMAND_RS_PTR_VA: u64 = 0x0132_29BE;
/// : command.rs:700 Future is polled only from these 6 first-LOAD BLs.
pub const BOSMINER_C8_POLL_BL_HITS: usize = 6;
pub const BOSMINER_C8_POLL_BL_VAS: [u64; 6] = [
    0x008D_D0B8,
    0x008D_D194,
    0x008D_D2BC,
    0x008D_DC48,
    0x008D_DCFC,
    0x008D_F6B8,
];
pub const BOSMINER_C8_POLL_BL_INSNS: [u32; 6] = [
    0x97FF_E5E5,
    0x97FF_E5AE,
    0x97FF_E564,
    0x97FF_E301,
    0x97FF_E2D4,
    0x97FF_DC65,
];
pub const BOSMINER_C8_POLL_FN_VA: u64 = 0x008D_684C;
/// Caller async fns that contain those polls.
pub const BOSMINER_C8_POLL_BM1366_FN_VA: u64 = 0x008D_CFBC;
pub const BOSMINER_C8_POLL_BM1366_LINE: u16 = 127;
pub const BOSMINER_C8_POLL_BM1366_COL: u16 = 66;
pub const BOSMINER_C8_POLL_BM1366_ADD_VA: u64 = 0x008D_D040;
pub const BOSMINER_C8_POLL_BM1366_ADD_INSN: u32 = 0x913B_A000;
pub const BOSMINER_C8_POLL_BM136X_LINE: u16 = 107;
pub const BOSMINER_C8_POLL_BM136X_COL: u16 = 18;
pub const BOSMINER_C8_POLL_BM136X_ADD_VA: u64 = 0x008D_DD38;
pub const BOSMINER_C8_POLL_BM136X_ADD_INSN: u32 = 0x9131_6000;
pub const BOSMINER_C8_POLL_BM1397_RS: &str =
    "open/bosminer/bosminer-am2-s17/src/hashchain/bm1397.rs";
pub const BOSMINER_C8_POLL_BM1397_LINE: u16 = 147;
pub const BOSMINER_C8_POLL_BM1397_COL: u16 = 72;
pub const BOSMINER_C8_POLL_BM1397_ADD_VA: u64 = 0x008D_F798;
pub const BOSMINER_C8_POLL_BM1397_ADD_INSN: u32 = 0x9105_4000;
/// Inline Future offsets in those three caller state machines.
pub const BOSMINER_C8_FUTURE_OFF_BM1366: u16 = 0x30;
pub const BOSMINER_C8_FUTURE_OFF_BM136X: u16 = 0x70;
pub const BOSMINER_C8_FUTURE_OFF_BM1397: u16 = 0x18;
pub const BOSMINER_C8_POLL_ADD30_VA: u64 = 0x008D_D0B0;
pub const BOSMINER_C8_POLL_ADD30_INSN: u32 = 0x9100_C260;
pub const BOSMINER_C8_POLL_ADD70_VA: u64 = 0x008D_DCF4;
pub const BOSMINER_C8_POLL_ADD70_INSN: u32 = 0x9101_C260;
pub const BOSMINER_C8_POLL_ADD18_VA: u64 = 0x008D_F6B0;
pub const BOSMINER_C8_POLL_ADD18_INSN: u32 = 0x9100_6260;
/// Pre-poll `LDR X8,[X8,#0x230]` then `ADD X8,X8,#0x10`.
pub const BOSMINER_C8_POLL_VT230_OFF: u16 = 0x230;
pub const BOSMINER_C8_POLL_VT230_LDR_VA: u64 = 0x008D_D098;
pub const BOSMINER_C8_POLL_VT230_LDR_INSN: u32 = 0xF941_1908;
pub const BOSMINER_C8_POLL_VT10_ADD_VA: u64 = 0x008D_D0A4;
pub const BOSMINER_C8_POLL_VT10_ADD_INSN: u32 = 0x9100_4108;
/// bm136x.rs:108 assert — packed_struct, not a command ident.
pub const BOSMINER_BM136X_FIELDSET_MSG: &str = "FieldSet corrupted (this is a bug)";
pub const BOSMINER_BM136X_FIELDSET_MSG_VA: u64 = 0x0132_3243;
pub const BOSMINER_BM136X_FIELDSET_MSG_LEN: usize = 34;
/// : +0x230 is a pointer on `*(async_self+8)`; `+0x10` is stored at Future+0x10.
/// Future+0xC8 Unresumed is zeroed at caller `+0xF8` / `+0x138` / `+0xE0`.
pub const BOSMINER_C8_CTX8_LDR_VA: u64 = 0x008D_D094;
pub const BOSMINER_C8_CTX8_LDR_INSN: u32 = 0xF940_0668;
pub const BOSMINER_C8_FUT_ZERO_VA: u64 = 0x008D_D09C;
pub const BOSMINER_C8_FUT_ZERO_INSN: u32 = 0xF900_1A7F;
pub const BOSMINER_C8_FUT_IMM_STR_VA: u64 = 0x008D_D0A0;
pub const BOSMINER_C8_FUT_IMM_STR_INSN: u32 = 0xB900_3A77;
pub const BOSMINER_C8_STATE_ZERO_F8_VA: u64 = 0x008D_D0A8;
pub const BOSMINER_C8_STATE_ZERO_F8_INSN: u32 = 0x3903_E27F;
pub const BOSMINER_C8_FUT10_STR_VA: u64 = 0x008D_D0AC;
pub const BOSMINER_C8_FUT10_STR_INSN: u32 = 0xF900_2268;
pub const BOSMINER_C8_STATE_ZERO_138_VA: u64 = 0x008D_DC34;
pub const BOSMINER_C8_STATE_ZERO_138_INSN: u32 = 0x3904_E27F;
pub const BOSMINER_C8_STATE_ZERO_E0_VA: u64 = 0x008D_F6A8;
pub const BOSMINER_C8_STATE_ZERO_E0_INSN: u32 = 0x3903_827F;
pub const BOSMINER_C8_FUT_PLUS_C8_BM1366: u16 = 0xF8;
pub const BOSMINER_C8_FUT_PLUS_C8_BM136X: u16 = 0x138;
pub const BOSMINER_C8_FUT_PLUS_C8_BM1397: u16 = 0xE0;
/// Wrap `FUN_00bf7798` is `registry.rs:109:32`. 0x1a8 interior: +0x110 / +0x118 / +0x168.
pub const BOSMINER_REGISTRY_WRAP_LINE: u16 = 109;
pub const BOSMINER_REGISTRY_WRAP_COL: u16 = 32;
pub const BOSMINER_REGISTRY_WRAP_LOC_VA: u64 = 0x01A0_81E0;
pub const BOSMINER_REGISTRY_WRAP_LOC_ADRP_VA: u64 = 0x00BF_77E4;
pub const BOSMINER_REGISTRY_WRAP_LOC_ADRP_INSN: u32 = 0xB000_7082;
pub const BOSMINER_REGISTRY_WRAP_LOC_ADD_VA: u64 = 0x00BF_77E8;
pub const BOSMINER_REGISTRY_WRAP_LOC_ADD_INSN: u32 = 0x9107_8042;
pub const BOSMINER_REGISTRY_WRAP_NEW_BL_VA: u64 = 0x00BF_77F8;
pub const BOSMINER_REGISTRY_WRAP_NEW_BL_INSN: u32 = 0x97FF_BA93;
pub const BOSMINER_REGISTRY_WRAP_STR110_VA: u64 = 0x00BF_796C;
pub const BOSMINER_REGISTRY_WRAP_STR110_INSN: u32 = 0xF900_8AE8;
pub const BOSMINER_REGISTRY_WRAP_ADD118_VA: u64 = 0x00BF_7958;
pub const BOSMINER_REGISTRY_WRAP_ADD118_INSN: u32 = 0x9104_62E9;
pub const BOSMINER_REGISTRY_WRAP_ADD168_VA: u64 = 0x00BF_797C;
pub const BOSMINER_REGISTRY_WRAP_ADD168_INSN: u32 = 0x9105_A2E9;
pub const BOSMINER_REGISTRY_WRAP_STR1A8_VA: u64 = 0x00BF_7980;
pub const BOSMINER_REGISTRY_WRAP_STR1A8_INSN: u32 = 0xF900_D6E8;
pub const BOSMINER_REGISTRY_1A8_OFF_110: u16 = 0x110;
pub const BOSMINER_REGISTRY_1A8_OFF_118: u16 = 0x118;
pub const BOSMINER_REGISTRY_1A8_OFF_168: u16 = 0x168;
/// `FUN_00c0d4ac` — wrap temp 1e9 initializer (not the 0x1a8 dest).
pub const BOSMINER_REGISTRY_1E9_INIT_FN_VA: u64 = 0x00C0_D4AC;
pub const BOSMINER_REGISTRY_1E9_MOVZ_VA: u64 = 0x00C0_D4B8;
pub const BOSMINER_REGISTRY_1E9_MOVZ_INSN: u32 = 0x5299_4008;
pub const BOSMINER_REGISTRY_1E9_MOVK_VA: u64 = 0x00C0_D4C0;
pub const BOSMINER_REGISTRY_1E9_MOVK_INSN: u32 = 0x72A7_7348;
/// : HashChain+0x230 is initialized to usize 0x10 at hashchain.rs:323:73.
pub const BOSMINER_HC_PLUS230_INIT_LINE: u16 = 323;
pub const BOSMINER_HC_PLUS230_INIT_COL: u16 = 73;
pub const BOSMINER_HC_PLUS230_INIT_LOC_VA: u64 = 0x019B_BAD0;
pub const BOSMINER_HC_PLUS230_MOVZ10_VA: u64 = 0x0083_6BEC;
pub const BOSMINER_HC_PLUS230_MOVZ10_INSN: u32 = 0x5280_0208;
pub const BOSMINER_HC_PLUS230_STR_VA: u64 = 0x0083_6BF8;
pub const BOSMINER_HC_PLUS230_STR_INSN: u32 = 0xF901_1948;
pub const BOSMINER_HC_PLUS230_INIT_VALUE: u16 = 0x10;
pub const BOSMINER_HC_PLUS240_1E8: u32 = 0x05F5_E100;
pub const BOSMINER_HC_PLUS240_MOVZ_VA: u64 = 0x0083_6BFC;
pub const BOSMINER_HC_PLUS240_MOVZ_INSN: u32 = 0x529C_2008;
pub const BOSMINER_HC_PLUS240_MOVK_VA: u64 = 0x0083_6C04;
pub const BOSMINER_HC_PLUS240_MOVK_INSN: u32 = 0x72A0_BEA8;
pub const BOSMINER_HC_PLUS240_STR_VA: u64 = 0x0083_6C0C;
pub const BOSMINER_HC_PLUS240_STR_INSN: u32 = 0xB902_4148;
pub const BOSMINER_HC_PLUS238_ZERO_VA: u64 = 0x0083_6C24;
pub const BOSMINER_HC_PLUS238_ZERO_INSN: u32 = 0xF901_1D5F;
pub const BOSMINER_HC_PLUS258_SELF_VA: u64 = 0x0083_6C30;
pub const BOSMINER_HC_PLUS258_SELF_INSN: u32 = 0xF901_2D4A;
pub const BOSMINER_HC_PLUS230_LOC_ADD_VA: u64 = 0x0083_6CB0;
pub const BOSMINER_HC_PLUS230_LOC_ADD_INSN: u32 = 0x912B_4000;
/// Wrap SIMD: dest+0x118 is 32 B from SP+#0x158; dest+0x168 is 32 B of the 1e9 temp.
pub const BOSMINER_WRAP_SIMD_118_LEN: usize = 32;
pub const BOSMINER_WRAP_SIMD_168_LEN: usize = 32;
pub const BOSMINER_WRAP_STP158_LEN: usize = 16;
pub const BOSMINER_WRAP_SIMD_118_STP_VA: u64 = 0x00BF_7974;
pub const BOSMINER_WRAP_SIMD_118_STP_INSN: u32 = 0xAD00_0520;
pub const BOSMINER_WRAP_SIMD_118_LDP_VA: u64 = 0x00BF_7968;
pub const BOSMINER_WRAP_SIMD_118_LDP_INSN: u32 = 0xAD40_06C0;
pub const BOSMINER_WRAP_SIMD_168_LDP_VA: u64 = 0x00BF_798C;
pub const BOSMINER_WRAP_SIMD_168_LDP_INSN: u32 = 0xAD51_8BE0;
pub const BOSMINER_WRAP_SIMD_168_STP_VA: u64 = 0x00BF_7998;
pub const BOSMINER_WRAP_SIMD_168_STP_INSN: u32 = 0xAD00_0920;
pub const BOSMINER_WRAP_STP158_VA: u64 = 0x00BF_7960;
pub const BOSMINER_WRAP_STP158_INSN: u32 = 0xA915_D2F5;
/// : poll-time +0x230 is the HashChain usize-0x10 field; wrap +0x188..+0x1a8 unwritten.
pub const BOSMINER_POLL_FUT0_LDR_VA: u64 = 0x008D_D020;
pub const BOSMINER_POLL_FUT0_LDR_INSN: u32 = 0xF940_0269;
pub const BOSMINER_POLL_FUT8_STR_VA: u64 = 0x008D_D02C;
pub const BOSMINER_POLL_FUT8_STR_INSN: u32 = 0xF900_0669;
pub const BOSMINER_POLL_STATE_OFF: u16 = 0x2A;
pub const BOSMINER_POLL_STATE_LDRB_VA: u64 = 0x008D_CFCC;
pub const BOSMINER_POLL_STATE_LDRB_INSN: u32 = 0x3940_A808;
pub const BOSMINER_POLL_230_PLUS10_SUM: u16 = 0x20;
pub const BOSMINER_WRAP_1A8_UNWRITTEN_OFF: u16 = 0x188;
pub const BOSMINER_WRAP_1A8_UNWRITTEN_LEN: usize = 32;
pub const BOSMINER_WRAP_FN_START_VA: u64 = 0x00BF_7798;
pub const BOSMINER_WRAP_FN_END_VA: u64 = 0x00BF_7A48;
pub const BOSMINER_WRAP_188_STORE_HITS: usize = 0;
/// : dest+0x168 is the 32 B NANOS_PER_SEC prefix of `FUN_00c0d4ac`,
/// which calls `SystemTime::now` (`Timespec::now(CLOCK_REALTIME=0)`).
/// HashChain+0x230 is not Instant / SystemTime / Duration.
pub const BOSMINER_NANOS_PER_SEC: u32 = 1_000_000_000;
pub const BOSMINER_CLOCK_REALTIME: u32 = 0;
pub const BOSMINER_C0D4AC_NOW_OFF: u16 = 0x28;
pub const BOSMINER_C0D4AC_NSEC_OFF: u16 = 0x30;
pub const BOSMINER_C0D4AC_SCALE8_OFF: u16 = 0x08;
pub const BOSMINER_C0D4AC_SCALE18_OFF: u16 = 0x18;
pub const BOSMINER_C0D4AC_NOW_BL_VA: u64 = 0x00C0_D4B4;
pub const BOSMINER_C0D4AC_NOW_BL_INSN: u32 = 0x941A_3315;
pub const BOSMINER_C0D4AC_STR8_VA: u64 = 0x00C0_D4CC;
pub const BOSMINER_C0D4AC_STR8_INSN: u32 = 0xB900_0A68;
pub const BOSMINER_C0D4AC_STR18_VA: u64 = 0x00C0_D4D0;
pub const BOSMINER_C0D4AC_STR18_INSN: u32 = 0xB900_1A68;
pub const BOSMINER_C0D4AC_STR30_VA: u64 = 0x00C0_D4C4;
pub const BOSMINER_C0D4AC_STR30_INSN: u32 = 0xB900_3261;
pub const BOSMINER_C0D4AC_STP20_VA: u64 = 0x00C0_D4D4;
pub const BOSMINER_C0D4AC_STP20_INSN: u32 = 0xA902_027F;
pub const BOSMINER_C0D4AC_ZERO38_VA: u64 = 0x00C0_D4BC;
pub const BOSMINER_C0D4AC_ZERO38_INSN: u32 = 0xF900_1E7F;
pub const BOSMINER_C0D4AC_ZERO40_VA: u64 = 0x00C0_D4C8;
pub const BOSMINER_C0D4AC_ZERO40_INSN: u32 = 0xB900_427F;
pub const BOSMINER_SYSNOW_FN_VA: u64 = 0x0129_A108;
pub const BOSMINER_SYSNOW_W0_VA: u64 = 0x0129_A110;
pub const BOSMINER_SYSNOW_W0_INSN: u32 = 0x2A1F_03E0;
pub const BOSMINER_SYSNOW_B_VA: u64 = 0x0129_A118;
pub const BOSMINER_SYSNOW_B_INSN: u32 = 0x1400_137D;
pub const BOSMINER_SYSNOW_TGT_VA: u64 = 0x0129_EF0C;
pub const BOSMINER_TIMESPEC_1E9_MOVZ_VA: u64 = 0x0129_EF30;
pub const BOSMINER_TIMESPEC_1E9_MOVZ_INSN: u32 = 0x5299_4008;
pub const BOSMINER_TIMESPEC_1E9_MOVK_VA: u64 = 0x0129_EF34;
pub const BOSMINER_TIMESPEC_1E9_MOVK_INSN: u32 = 0x72A7_7348;
pub const BOSMINER_TIMESPEC_NOW_LINE_137: u16 = 137;
pub const BOSMINER_TIMESPEC_NOW_COL_137: u16 = 68;
pub const BOSMINER_TIMESPEC_NOW_LOC137_VA: u64 = 0x01AC_AEA0;
pub const BOSMINER_TIMESPEC_NOW_LINE_139: u16 = 139;
pub const BOSMINER_TIMESPEC_NOW_COL_139: u16 = 58;
pub const BOSMINER_TIMESPEC_NOW_LOC139_VA: u64 = 0x01AC_AEB8;
pub const BOSMINER_DURATION_NEW_FN_VA: u64 = 0x0129_EFF0;
pub const BOSMINER_DURATION_NEW_LINE: u16 = 201;
pub const BOSMINER_DURATION_NEW_COL: u16 = 18;
pub const BOSMINER_DURATION_NEW_LOC_VA: u64 = 0x01AC_9208;
pub const BOSMINER_DURATION_NEW_1E9_MOVZ_VA: u64 = 0x0129_F02C;
pub const BOSMINER_DURATION_NEW_1E9_MOVZ_INSN: u32 = 0x5299_400D;
pub const BOSMINER_DURATION_NEW_1E9_MOVK_VA: u64 = 0x0129_F034;
pub const BOSMINER_DURATION_NEW_1E9_MOVK_INSN: u32 = 0x72A7_734D;
pub const BOSMINER_DURATION_NEW_STR10_VA: u64 = 0x0129_F070;
pub const BOSMINER_DURATION_NEW_STR10_INSN: u32 = 0xB900_1268;
pub const BOSMINER_DURATION_NEW_BL_HITS: usize = 8;
pub const BOSMINER_HC_PLUS260_FN_VA: u64 = 0x0089_B720;
pub const BOSMINER_HC_PLUS260_MOVZ_VA: u64 = 0x0089_B720;
pub const BOSMINER_HC_PLUS260_MOVZ_INSN: u32 = 0x5280_0020;
pub const BOSMINER_HC_PLUS260_RET_VA: u64 = 0x0089_B724;
pub const BOSMINER_HC_PLUS260_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_HC_PLUS260_STR_VA: u64 = 0x0083_6C34;
pub const BOSMINER_HC_PLUS260_STR_INSN: u32 = 0xF901_3148;
pub const BOSMINER_INVALID_TIMESTAMP_MSG: &str = "invalid timestamp";
pub const BOSMINER_UNIX_TIME_RS: &str = "library/std/src/sys/pal/unix/time.rs";
pub const BOSMINER_CORE_TIME_RS: &str =
    "/rustc/17067e9ac6d7ecb70e50f92c1944e545188d2359/library/core/src/time.rs";
/// : `FUN_00c0d4ac` object is 0x48; 37 BLs = 6 FPGA + 25 UART + 6 wrap.
pub const BOSMINER_C0D4AC_SIZE: u16 = 0x48;
pub const BOSMINER_C0D4AC_BL_HITS: usize = 37;
pub const BOSMINER_C0D4AC_FPGA_HITS: usize = 6;
pub const BOSMINER_C0D4AC_UART_HITS: usize = 25;
pub const BOSMINER_C0D4AC_WRAP_HITS: usize = 6;
pub const BOSMINER_C0D4AC_FPGA_FIRST_DEST: u16 = 0xC8;
pub const BOSMINER_C0D4AC_FPGA_SECOND_DEST: u16 = 0x110;
pub const BOSMINER_C0D4AC_FPGA_LAST_DEST: u16 = 0x230;
pub const BOSMINER_C0D4AC_FPGA_ADD_C8_VA: u64 = 0x008A_F910;
pub const BOSMINER_C0D4AC_FPGA_ADD_C8_INSN: u32 = 0x9103_23E8;
pub const BOSMINER_C0D4AC_FPGA_BL0_VA: u64 = 0x008A_F914;
pub const BOSMINER_C0D4AC_FPGA_BL0_INSN: u32 = 0x940D_76E6;
pub const BOSMINER_C0D4AC_FPGA_ADD_230_VA: u64 = 0x008A_F938;
pub const BOSMINER_C0D4AC_FPGA_ADD_230_INSN: u32 = 0x9108_C3E8;
pub const BOSMINER_C0D478_SIBLING_SIZE: u16 = 0x20;
pub const BOSMINER_C0D478_FPGA_BL_VA: u64 = 0x008A_F90C;
pub const BOSMINER_C0D478_FPGA_BL_INSN: u32 = 0x940D_76DB;
pub const BOSMINER_C0D4AC_UART_BL0_VA: u64 = 0x008F_836C;
pub const BOSMINER_C0D4AC_UART_BL0_INSN: u32 = 0x940C_5450;
pub const BOSMINER_C0D4AC_UART_CLUSTERS: usize = 5;
pub const BOSMINER_C0D4AC_WRAP_ADD230_VA: u64 = 0x00BF_78A4;
pub const BOSMINER_C0D4AC_WRAP_ADD230_INSN: u32 = 0x9108_C3E8;
pub const BOSMINER_C0D4AC_WRAP_BL0_VA: u64 = 0x00BF_78A8;
pub const BOSMINER_C0D4AC_WRAP_BL0_INSN: u32 = 0x9400_5701;
pub const BOSMINER_C0D4AC_WRAP_SECOND_DEST: u16 = 0x278;
/// : 0x48 cell lives in FPGA `FUN_008af670` + UART `worker.rs:68`; not Timespec.
pub const BOSMINER_TIMESPEC_SIZE: u16 = 16;
pub const BOSMINER_INSTANT_SIZE: u16 = 16;
pub const BOSMINER_SYSTEMTIME_SIZE: u16 = 16;
pub const BOSMINER_DURATION_SIZE: u16 = 16;
pub const BOSMINER_C0D4AC_UART_WORKER_LINE: u16 = 68;
pub const BOSMINER_C0D4AC_UART_WORKER_COL: u16 = 18;
pub const BOSMINER_C0D4AC_UART_WORKER_LOC_VA: u64 = 0x019C_8878;
pub const BOSMINER_C0D4AC_UART_WORKER_RS: &str =
    "/build/source/open/bosminer/bosminer-backend/src/worker.rs";
pub const BOSMINER_C0D4AC_FPGA_HOST_VA: u64 = 0x008A_F670;
pub const BOSMINER_C0D4AC_FPGA_HOST_STP_INSN: u32 = 0xA9BA_7BFD;
pub const BOSMINER_C0D4AC_FPGA_HOST_SUB_VA: u64 = 0x008A_F688;
pub const BOSMINER_C0D4AC_FPGA_HOST_SUB_INSN: u32 = 0xD10E_03FF;
/// : +0x230 owner async fn nests `command.rs:647`; 0x48 is not Metrics.stop_watch.
pub const BOSMINER_HC_PLUS230_NESTED_CMD_LINE: u16 = 647;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_COL: u16 = 21;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_LOC_VA: u64 = 0x019B_B040;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_ADRP_VA: u64 = 0x0083_6CDC;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_ADRP_INSN: u32 = 0xB000_8C20;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_ADD_VA: u64 = 0x0083_6CE0;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_ADD_INSN: u32 = 0x9101_0000;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_BL_VA: u64 = 0x0083_6CE4;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_BL_INSN: u32 = 0x97F0_73D7;
pub const BOSMINER_HC_PLUS230_NESTED_CMD_RS: &str =
    "/build/source/open/bosminer/bosminer-hal/src/command.rs";
pub const BOSMINER_METRICS_RS: &str = "open/bosminer/bosminer-hal/src/metrics.rs";
pub const BOSMINER_METRICS_STOP_WATCH: &str = "stop_watch";
pub const BOSMINER_METRICS_PERF_TIME: &str = "perf_time";
pub const BOSMINER_METRICS_223_LINE: u16 = 223;
pub const BOSMINER_METRICS_223_COL: u16 = 43;
pub const BOSMINER_METRICS_223_LOC_VA: u64 = 0x01A0_3180;
pub const BOSMINER_METRICS_223_ADRP_VA: u64 = 0x0041_EAA4;
pub const BOSMINER_METRICS_223_ADRP_INSN: u32 = 0xB000_AF21;
pub const BOSMINER_METRICS_223_ADD_VA: u64 = 0x0041_EAA8;
pub const BOSMINER_METRICS_223_ADD_INSN: u32 = 0x9106_0021;
pub const BOSMINER_METRICS_223_BL_VA: u64 = 0x0041_EAB0;
pub const BOSMINER_METRICS_223_BL_INSN: u32 = 0x942C_2E2B;
pub const BOSMINER_METRICS_223_BL_TGT: u64 = 0x00F2_A35C;
pub const BOSMINER_HASHES_TIME_MEAN_ELEMENTS: u8 = 2;
/// : 0x48 cell is Copy (no drop_in_place / no rustc v0); workpair.rs is wrap sibling.
pub const BOSMINER_DROP_IN_PLACE_HITS: usize = 0;
pub const BOSMINER_RUSTC_V0_RNV_HITS: usize = 0;
pub const BOSMINER_C0D4AC_IS_COPY: bool = true;
pub const BOSMINER_C0D4E0_SWAP_FN_VA: u64 = 0x00C0_D4E0;
pub const BOSMINER_C0D4E0_LDRB_INSN: u32 = 0x3940_0028;
pub const BOSMINER_C0D4E0_BL_HITS: usize = 1;
pub const BOSMINER_C0D4E0_BL_VA: u64 = 0x0042_38A0;
pub const BOSMINER_C0D4E0_BL_INSN: u32 = 0x941F_A710;
pub const BOSMINER_WORKPAIR_RS: &str = "open/bosminer/bosminer-hal/src/workpair.rs";
pub const BOSMINER_WORKPAIR_MODULE: &str = "bosminer_hal::workpair";
pub const BOSMINER_WORKPAIR_LINE_110: u16 = 110;
pub const BOSMINER_WORKPAIR_COL_110: u16 = 22;
pub const BOSMINER_WORKPAIR_LOC110_VA: u64 = 0x01A0_80D8;
pub const BOSMINER_WORKPAIR_110_ADRP_VA: u64 = 0x00BF_65D0;
pub const BOSMINER_WORKPAIR_110_ADRP_INSN: u32 = 0xD000_7084;
pub const BOSMINER_WORKPAIR_110_ADD_VA: u64 = 0x00BF_65D4;
pub const BOSMINER_WORKPAIR_110_ADD_INSN: u32 = 0x9103_6084;
pub const BOSMINER_WORKPAIR_RET_VA: u64 = 0x00BF_7568;
pub const BOSMINER_WORKPAIR_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_WORKPAIR_C0D4AC_BL_HITS: usize = 0;
///  correction: the ticket-mask future `FUN_00836934` aliases X10=X19
/// then stores usize 0x10
/// at obj+0x230. After RET, the same async jump-table state calls
/// `(+0x238).vtable[+0x40](+0x230)` with that usize as X0.
/// hashchain.rs:323:73 after RET is the async-resume pad, not the STR site.
/// Ticket-mask log is hashchain.rs:298:9 at later VAs 0x838008/0x838024.
/// Poll ADD #0x10 stores 0x20 at Future+0x40 — it does not write HashChain+0x230.
pub const BOSMINER_HC_PLUS230_X10_FROM_X19_VA: u64 = 0x0083_6BD8;
pub const BOSMINER_HC_PLUS230_X10_FROM_X19_INSN: u32 = 0xAA13_03EA;
pub const BOSMINER_HC_PLUS230_RET_VA: u64 = 0x0083_6CA8;
pub const BOSMINER_HC_PLUS230_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_HC_PLUS230_CONSUMER_LDR238_VA: u64 = 0x0083_6E8C;
pub const BOSMINER_HC_PLUS230_CONSUMER_LDR238_INSN: u32 = 0xF941_1D09;
pub const BOSMINER_HC_PLUS230_CONSUMER_LDR230_VA: u64 = 0x0083_6E90;
pub const BOSMINER_HC_PLUS230_CONSUMER_LDR230_INSN: u32 = 0xF941_1900;
pub const BOSMINER_HC_PLUS230_CONSUMER_VT40_VA: u64 = 0x0083_6E94;
pub const BOSMINER_HC_PLUS230_CONSUMER_VT40_INSN: u32 = 0xF940_2128;
pub const BOSMINER_HC_PLUS230_CONSUMER_BLR_VA: u64 = 0x0083_6E98;
pub const BOSMINER_HC_PLUS230_CONSUMER_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_HC_PLUS230_VT_OFF: u16 = 0x40;
pub const BOSMINER_JUMP_TABLE_BR_VA: u64 = 0x0083_6E78;
pub const BOSMINER_JUMP_TABLE_BR_INSN: u32 = 0xD61F_0140;
/// `BOSMINER_C8_FUT10_STR_*` is the  name; the imm is Future+0x40.
pub const BOSMINER_POLL_FUT40_OFF: u16 = 0x40;
pub const BOSMINER_POLL_FUT40_STR_VA: u64 = 0x008D_D0AC;
pub const BOSMINER_POLL_FUT40_STR_INSN: u32 = 0xF900_2268;
pub const BOSMINER_HASHCHAIN_TICKET_COL: u16 = 9;
pub const BOSMINER_HASHCHAIN_TICKET_LOC_VA: u64 = 0x019B_B4F0;
pub const BOSMINER_HASHCHAIN_TICKET_ADRP_VA: u64 = 0x0083_8008;
pub const BOSMINER_HASHCHAIN_TICKET_ADRP_INSN: u32 = 0xF000_8C02;
pub const BOSMINER_HASHCHAIN_TICKET_ADD_VA: u64 = 0x0083_800C;
pub const BOSMINER_HASHCHAIN_TICKET_ADD_INSN: u32 = 0x9113_C042;
pub const BOSMINER_HASHCHAIN_TICKET_BL_VA: u64 = 0x0083_8014;
pub const BOSMINER_HASHCHAIN_TICKET_BL_INSN: u32 = 0x97F0_6DA7;
pub const BOSMINER_HASHCHAIN_TICKET_LOG: &str = "Setting ticket mask register for difficulty";
/// : +0x230/+0x238 is a rust fat pointer (data, vtable).
/// Clone path: `memcpy(dst, src, 0x230)` (`FUN_00bc8fe0`) then `STR` X0/X1
/// pair at +0x230/+0x238. Jump-table calls: X0=data, X9=vtable, BLR [X9,slot].
/// Seven slots: 0x28,0x30,0x38,0x40,0x48,0x50,0x78. command.rs:472 sits
/// in the installer. 0x8dc5a4 is Future-local shuffle, not this fill.
pub const BOSMINER_FAT_VT_SLOT_HITS: usize = 7;
pub const BOSMINER_FAT_VT_SLOTS: [u16; 7] = [0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x78];
pub const BOSMINER_CLONE_MEMCPY_SIZE: u16 = 0x230;
pub const BOSMINER_CLONE_MEMCPY_FN_VA: u64 = 0x00BC_8FE0;
pub const BOSMINER_CLONE_MEMCPY_ENTRY_INSN: u32 = 0x8B02_0024;
pub const BOSMINER_CLONE_MEMCPY_MOVZ_VA: u64 = 0x0083_5320;
pub const BOSMINER_CLONE_MEMCPY_MOVZ_INSN: u32 = 0x5280_4602;
pub const BOSMINER_CLONE_MEMCPY_BL_VA: u64 = 0x0083_5324;
pub const BOSMINER_CLONE_MEMCPY_BL_INSN: u32 = 0x940E_4F2F;
pub const BOSMINER_FAT_BLR_VA: u64 = 0x0083_5308;
pub const BOSMINER_FAT_BLR_INSN: u32 = 0xD63F_02E0;
pub const BOSMINER_FAT_MOV_X24_X0_VA: u64 = 0x0083_530C;
pub const BOSMINER_FAT_MOV_X24_X0_INSN: u32 = 0xAA00_03F8;
pub const BOSMINER_FAT_MOV_X23_X1_VA: u64 = 0x0083_5310;
pub const BOSMINER_FAT_MOV_X23_X1_INSN: u32 = 0xAA01_03F7;
pub const BOSMINER_FAT_PAIR_STR230_VA: u64 = 0x0083_532C;
pub const BOSMINER_FAT_PAIR_STR230_INSN: u32 = 0xF901_1A98;
pub const BOSMINER_FAT_PAIR_STR238_VA: u64 = 0x0083_5330;
pub const BOSMINER_FAT_PAIR_STR238_INSN: u32 = 0xF901_1E97;
pub const BOSMINER_CMD_472_LINE: u16 = 472;
pub const BOSMINER_CMD_472_COL: u16 = 36;
pub const BOSMINER_CMD_472_LOC_VA: u64 = 0x019B_AFE8;
pub const BOSMINER_CMD_472_ADRP_VA: u64 = 0x0083_4ED4;
pub const BOSMINER_CMD_472_ADRP_INSN: u32 = 0xD000_8C21;
pub const BOSMINER_CMD_472_ADD_VA: u64 = 0x0083_4ED8;
pub const BOSMINER_CMD_472_ADD_INSN: u32 = 0x913F_A021;
pub const BOSMINER_VT_SLOT_28_LDR_VA: u64 = 0x0083_89F8;
pub const BOSMINER_VT_SLOT_28_LDR_INSN: u32 = 0xF940_1528;
pub const BOSMINER_VT_SLOT_30_LDR_VA: u64 = 0x0083_7BC8;
pub const BOSMINER_VT_SLOT_30_LDR_INSN: u32 = 0xF940_1928;
pub const BOSMINER_VT_SLOT_38_LDR_VA: u64 = 0x0083_7668;
pub const BOSMINER_VT_SLOT_38_LDR_INSN: u32 = 0xF940_1D28;
pub const BOSMINER_VT_SLOT_50_LDR_VA: u64 = 0x0083_76FC;
pub const BOSMINER_VT_SLOT_50_LDR_INSN: u32 = 0xF940_2929;
pub const BOSMINER_VT_SLOT_48_LDR_VA: u64 = 0x0083_862C;
pub const BOSMINER_VT_SLOT_48_LDR_INSN: u32 = 0xF940_2528;
pub const BOSMINER_VT_SLOT_78_LDR_VA: u64 = 0x0083_7DD8;
pub const BOSMINER_VT_SLOT_78_LDR_INSN: u32 = 0xF940_3D28;
pub const BOSMINER_FUTURE_SHUFFLE_STR238_VA: u64 = 0x008D_C5A4;
pub const BOSMINER_FUTURE_SHUFFLE_STR238_INSN: u32 = 0xF901_1E6A;
/// : 6 slots STP (X0,X1) return pair; +0x50 is X8 sret.
/// +0x30 takes X1 from Future+0x10. +0x28 post-BLR is packing.rs:40.
/// +0x78 post-BLR resume is hashchain.rs:336:84.
/// command.rs:119 is FUN_00bf3264 work-resp divider, not the trait.
/// Hashchip:/read_register are error labels; tuner write_reg list is not this.
pub const BOSMINER_FAT_PAIR_RETURN_HITS: usize = 6;
pub const BOSMINER_FAT_SRET_HITS: usize = 1;
pub const BOSMINER_FAT_SLOT30_X1_LDR_VA: u64 = 0x0083_7BBC;
pub const BOSMINER_FAT_SLOT30_X1_LDR_INSN: u32 = 0xF940_0A61;
pub const BOSMINER_FAT_SLOT50_SRET_ADD_VA: u64 = 0x0083_7700;
pub const BOSMINER_FAT_SLOT50_SRET_ADD_INSN: u32 = 0x9105_83E8;
pub const BOSMINER_FAT_SLOT50_SRET_OFF: u16 = 0x160;
pub const BOSMINER_FAT_STP_28_INSN: u32 = 0xA902_8660;
pub const BOSMINER_FAT_STP_40_INSN: u32 = 0xA904_0660;
pub const BOSMINER_FAT_STP_58_INSN: u32 = 0xA905_8660;
pub const BOSMINER_FAT_SLOT28_STP_VA: u64 = 0x0083_8A00;
pub const BOSMINER_FAT_SLOT40_STP_VA: u64 = 0x0083_6E9C;
pub const BOSMINER_FAT_SLOT48_STP_VA: u64 = 0x0083_8634;
pub const BOSMINER_FAT_SLOT28_PACK_ADRP_VA: u64 = 0x0083_8A10;
pub const BOSMINER_FAT_SLOT28_PACK_ADRP_INSN: u32 = 0x9000_8C22;
pub const BOSMINER_FAT_SLOT28_PACK_ADD_VA: u64 = 0x0083_8A14;
pub const BOSMINER_FAT_SLOT28_PACK_ADD_INSN: u32 = 0x9131_A042;
pub const BOSMINER_PACKING_40_LINE: u16 = 40;
pub const BOSMINER_PACKING_40_COL: u16 = 23;
pub const BOSMINER_FAT_SLOT78_336_ADRP_VA: u64 = 0x0083_7E04;
pub const BOSMINER_FAT_SLOT78_336_ADRP_INSN: u32 = 0x9000_8C20;
pub const BOSMINER_FAT_SLOT78_336_ADD_VA: u64 = 0x0083_7E08;
pub const BOSMINER_FAT_SLOT78_336_ADD_INSN: u32 = 0x912C_2000;
pub const BOSMINER_HASHCHAIN_336_LINE: u16 = 336;
pub const BOSMINER_HASHCHAIN_336_COL: u16 = 84;
pub const BOSMINER_HASHCHAIN_336_LOC_VA: u64 = 0x019B_BB08;
pub const BOSMINER_CMD_119_LINE: u16 = 119;
pub const BOSMINER_CMD_119_COL: u16 = 22;
pub const BOSMINER_CMD_119_ADRP_VA: u64 = 0x00BF_320C;
pub const BOSMINER_CMD_119_ADRP_INSN: u32 = 0x9000_70A4;
pub const BOSMINER_CMD_119_ADD_VA: u64 = 0x00BF_3210;
pub const BOSMINER_CMD_119_ADD_INSN: u32 = 0x9123_8084;
pub const BOSMINER_HAL_COMMAND_MODULE: &str = "bosminer_hal::command";
pub const BOSMINER_HASHCHIP_LABEL: &str = "Hashchip:";
pub const BOSMINER_READ_REGISTER_LABEL: &str = "read_register";
pub const BOSMINER_HASHCHIP_STR_VA: u64 = 0x0130_3FC0;
pub const BOSMINER_HASHCHIP_RODATA_PTR_VA: u64 = 0x0199_FEB0;
pub const BOSMINER_TUNER_WRITE_REG: &str = "write_reg";
/// : the 6 STP pairs are dyn Futures polled via vtable+0x18.
/// They are NOT FUN_008d684c / command.rs:700 (0 BLs in 0x836000-0x83a000).
/// They are NOT Result tag-matches. Sequence:
/// `LDR X9,[X1,#0x18]; ADD X8,SP,#0x160; MOV X1,X21; BLR X9`.
pub const BOSMINER_JUMP_TABLE_CMD700_BL_HITS: usize = 0;
pub const BOSMINER_DYN_FUT_POLL_HITS: usize = 6;
pub const BOSMINER_DYN_FUT_POLL18_OFF: u16 = 0x18;
pub const BOSMINER_DYN_FUT_POLL18_INSN: u32 = 0xF940_0C29;
pub const BOSMINER_DYN_FUT_SRET_INSN: u32 = 0x9105_83E8;
pub const BOSMINER_DYN_FUT_CX_MOV_INSN: u32 = 0xAA15_03E1;
pub const BOSMINER_DYN_FUT_BLR_INSN: u32 = 0xD63F_0120;
pub const BOSMINER_DYN_FUT_POLL_VAS: [u64; 6] = [
    0x0083_6F64,
    0x0083_6FE4,
    0x0083_7058,
    0x0083_7580,
    0x0083_7674,
    0x0083_8638,
];
pub const BOSMINER_FAT_PAIR_RELOAD28_VA: u64 = 0x0083_7054;
pub const BOSMINER_FAT_PAIR_RELOAD28_INSN: u32 = 0xF940_1660;
pub const BOSMINER_FAT_PAIR_RELOAD58_VA: u64 = 0x0083_757C;
pub const BOSMINER_FAT_PAIR_RELOAD58_INSN: u32 = 0xF940_2E60;
pub const BOSMINER_FAT_SLOT28_JOIN_B_VA: u64 = 0x0083_8A04;
pub const BOSMINER_FAT_SLOT28_JOIN_B_INSN: u32 = 0x17FF_F957;
pub const BOSMINER_FAT_SLOT40_JOIN_B_VA: u64 = 0x0083_6EA0;
pub const BOSMINER_FAT_SLOT40_JOIN_B_INSN: u32 = 0x1400_0051;
/// : Poll sret at SP+#0x160 is 0x20 bytes. Word0==9 is Pending.
/// Ready T starts at +0x168 (24 B: +0x168 qword + +0x170 Q). 0 locs in
/// 0xC0 before each fat LDR238 — slot method names stay unbound.
pub const BOSMINER_POLL_PENDING_TAG: u16 = 9;
pub const BOSMINER_POLL_SRET_OFF: u16 = 0x160;
pub const BOSMINER_POLL_SRET_SIZE: u16 = 0x20;
pub const BOSMINER_POLL_T_OFF: u16 = 0x168;
pub const BOSMINER_POLL_T_LEN: u16 = 0x18;
pub const BOSMINER_POLL_CMP9_HITS: usize = 6;
pub const BOSMINER_POLL_LDR160_X27_INSN: u32 = 0xF940_B3FB;
pub const BOSMINER_POLL_CMP9_X27_INSN: u32 = 0xF100_277F;
pub const BOSMINER_POLL_LDR160_X24_INSN: u32 = 0xF940_B3F8;
pub const BOSMINER_POLL_CMP9_X24_INSN: u32 = 0xF100_271F;
pub const BOSMINER_POLL_PENDING_MOVZ9_INSN: u32 = 0x5280_0128;
pub const BOSMINER_POLL_T168_LDR_INSN: u32 = 0xF940_B7F9;
pub const BOSMINER_POLL_T170_Q_INSN: u32 = 0x3DC0_5FE0;
pub const BOSMINER_POLL_LDR160_VAS: [u64; 6] = [
    0x0083_6F78,
    0x0083_6FF4,
    0x0083_7068,
    0x0083_7590,
    0x0083_7684,
    0x0083_8648,
];
pub const BOSMINER_POLL_T168_VA: u64 = 0x0083_7108;
pub const BOSMINER_POLL_T170_VA: u64 = 0x0083_710C;
pub const BOSMINER_POLL_READY28_VA: u64 = 0x0083_7104;
pub const BOSMINER_FAT_SLOT_PRE_BLR_LOC_HITS: usize = 0;
/// : Poll word0 is a **3-way** match, not a 2-way Pending/Ready.
/// `9` = Pending → `STR X8,[X28]` (outer Poll sret) + `MOVZ #8` + `B 0x838be8`
/// (STRB state at `X19+0x21`, `ADD SP,#0x340`, RET).
/// `8` = Ready-continue (Ok-shaped) after the Future drop.
/// other = Ready-return-with-T (Err-shaped) via `0x838a08` → `0x838cd8`.
/// rustc **1.87.0**. Slot rust method names stay unbound. T ident unbound.
pub const BOSMINER_POLL_READY_OK_TAG: u16 = 8;
pub const BOSMINER_POLL_PENDING_STR_X28_VA: u64 = 0x0083_6F88;
pub const BOSMINER_POLL_PENDING_STR_X28_INSN: u32 = 0xF900_0388;
pub const BOSMINER_POLL_PENDING_MOVZ8_VA: u64 = 0x0083_6F8C;
pub const BOSMINER_POLL_PENDING_MOVZ8_INSN: u32 = 0x5280_0108;
pub const BOSMINER_POLL_PENDING_B_SUSPEND_VA: u64 = 0x0083_6F90;
pub const BOSMINER_POLL_PENDING_B_SUSPEND_INSN: u32 = 0x1400_0716;
pub const BOSMINER_POLL_SUSPEND_VA: u64 = 0x0083_8BE8;
pub const BOSMINER_POLL_SUSPEND_STRB_INSN: u32 = 0x3900_8668;
pub const BOSMINER_POLL_SUSPEND_ADDSP_VA: u64 = 0x0083_8BEC;
pub const BOSMINER_POLL_SUSPEND_ADDSP_INSN: u32 = 0x910D_03FF;
pub const BOSMINER_POLL_SUSPEND_RET_VA: u64 = 0x0083_8C08;
pub const BOSMINER_POLL_SUSPEND_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_POLL_SUSPEND_STATE_OFF: u16 = 0x21;
pub const BOSMINER_POLL_CMP8_HITS: usize = 7;
pub const BOSMINER_POLL_CMP8_X27_INSN: u32 = 0xF100_237F;
pub const BOSMINER_POLL_CMP8_X24_INSN: u32 = 0xF100_231F;
pub const BOSMINER_POLL_CMP8_VAS: [u64; 7] = [
    0x0083_70B8,
    0x0083_7138,
    0x0083_71B0,
    0x0083_7600,
    0x0083_76DC,
    0x0083_86A8,
    0x0083_89E4,
];
pub const BOSMINER_POLL_READY28_CMP8_VA: u64 = 0x0083_7138;
pub const BOSMINER_POLL_READY28_BNE_VA: u64 = 0x0083_713C;
pub const BOSMINER_POLL_READY28_BNE_INSN: u32 = 0x5400_C661;
pub const BOSMINER_POLL_ERR_JOIN_VA: u64 = 0x0083_8A08;
pub const BOSMINER_POLL_ERR_JOIN_LDR_INSN: u32 = 0x3DC0_0FE0;
pub const BOSMINER_POLL_ERR_JOIN_B_VA: u64 = 0x0083_8A0C;
pub const BOSMINER_POLL_ERR_JOIN_B_INSN: u32 = 0x1400_00B3;
pub const BOSMINER_POLL_ERR_PACK_VA: u64 = 0x0083_8CD8;
pub const BOSMINER_POLL_ERR_PACK_STP_INSN: u32 = 0xA900_679B;
pub const BOSMINER_POLL_ERR_PACK_MOVZ1_VA: u64 = 0x0083_8CDC;
pub const BOSMINER_POLL_ERR_PACK_MOVZ1_INSN: u32 = 0x5280_0028;
pub const BOSMINER_POLL_ERR_PACK_STRQ_VA: u64 = 0x0083_8CE0;
pub const BOSMINER_POLL_ERR_PACK_STRQ_INSN: u32 = 0x3D80_0780;
pub const BOSMINER_POLL_ERR_PACK_B_VA: u64 = 0x0083_8CE4;
pub const BOSMINER_POLL_ERR_PACK_B_INSN: u32 = 0x17FF_FFC1;
pub const BOSMINER_CMD_EVENT_LINES: [u16; 4] = [594, 621, 656, 675];
pub const BOSMINER_CMD_LOC_LINE_HITS: usize = 27;
pub const BOSMINER_CMD_LOC_RECORD_HITS: usize = 104;
/// : 7 CMP #8 = 6 post-poll Ready-Ok + 1 slot-+0x28 prelude.
/// Prelude: `MOVZ W27,#8` @ `0x8389d0`, `BL 0x831314` @ `0x8389e0`, then
/// `CMP X27,#8` @ `0x8389e4` immediately before fat `LDR [X9,#0x28]`.
/// command.rs `:418/:514/:693/:719` before the ticket-mask log are panic pads.
pub const BOSMINER_POLL_CMP8_POST_POLL_HITS: usize = 6;
pub const BOSMINER_POLL_CMP8_PRELUDE_HITS: usize = 1;
pub const BOSMINER_POLL_CMP8_POST_POLL_VAS: [u64; 6] = [
    0x0083_70B8,
    0x0083_7138,
    0x0083_71B0,
    0x0083_7600,
    0x0083_76DC,
    0x0083_86A8,
];
pub const BOSMINER_POLL_CMP8_PRELUDE_VA: u64 = 0x0083_89E4;
pub const BOSMINER_SLOT28_PRELUDE_MOVZ8_VA: u64 = 0x0083_89D0;
pub const BOSMINER_SLOT28_PRELUDE_MOVZ8_INSN: u32 = 0x5280_011B;
pub const BOSMINER_SLOT28_PRELUDE_BL_VA: u64 = 0x0083_89E0;
pub const BOSMINER_SLOT28_PRELUDE_BL_INSN: u32 = 0x97FF_E24D;
pub const BOSMINER_SLOT28_PRELUDE_BL_TARGET: u64 = 0x0083_1314;
pub const BOSMINER_CMD_PANIC_PAD_LINES: [u16; 4] = [418, 514, 693, 719];
/// : `FUN_00831314` is a **state-tagged drop dispatcher**, not the
/// +0x28 slot method. `LDRB [X0,#0x10]` then: 3=drop pair at +0x18;
/// 4|6=tail `0x831d18(X0+0x40)`; 5=tail `0x831668(X0+0x18)`; else RET.
/// Exactly 2 first-LOAD BLs, both `MOV X0,X22`. 0 locs in the body.
pub const BOSMINER_FN831314_VA: u64 = 0x0083_1314;
pub const BOSMINER_FN831314_ENTRY_INSN: u32 = 0xF81E_0FFE;
pub const BOSMINER_FN831314_STP_VA: u64 = 0x0083_1318;
pub const BOSMINER_FN831314_STP_INSN: u32 = 0xA901_4FF4;
pub const BOSMINER_FN831314_LDRB10_VA: u64 = 0x0083_131C;
pub const BOSMINER_FN831314_LDRB10_INSN: u32 = 0x3940_4008;
pub const BOSMINER_FN831314_TAG_OFF: u16 = 0x10;
pub const BOSMINER_FN831314_CMP4_VA: u64 = 0x0083_1320;
pub const BOSMINER_FN831314_CMP4_INSN: u32 = 0x7100_111F;
pub const BOSMINER_FN831314_CMP3_VA: u64 = 0x0083_1328;
pub const BOSMINER_FN831314_CMP3_INSN: u32 = 0x7100_0D1F;
pub const BOSMINER_FN831314_BGT5_VA: u64 = 0x0083_1324;
pub const BOSMINER_FN831314_BGT5_INSN: u32 = 0x5400_00CC;
pub const BOSMINER_FN831314_TAG3_DROP_OFF: u16 = 0x18;
pub const BOSMINER_FN831314_TAG46_ADD40_VA: u64 = 0x0083_135C;
pub const BOSMINER_FN831314_TAG46_ADD40_INSN: u32 = 0x9101_0000;
pub const BOSMINER_FN831314_TAG46_B_VA: u64 = 0x0083_1364;
pub const BOSMINER_FN831314_TAG46_B_INSN: u32 = 0x1400_026D;
pub const BOSMINER_FN831314_TAG46_TARGET: u64 = 0x0083_1D18;
pub const BOSMINER_FN831314_TAG5_ADD18_VA: u64 = 0x0083_13A8;
pub const BOSMINER_FN831314_TAG5_ADD18_INSN: u32 = 0x9100_6000;
pub const BOSMINER_FN831314_TAG5_TARGET: u64 = 0x0083_1668;
pub const BOSMINER_FN831314_RET_VA: u64 = 0x0083_13A0;
pub const BOSMINER_FN831314_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_FN831314_BL_HITS: usize = 2;
pub const BOSMINER_FN831314_BL_VAS: [u64; 2] = [0x0083_89E0, 0x0083_8B90];
pub const BOSMINER_FN831314_BL2_INSN: u32 = 0x97FF_E1E1;
pub const BOSMINER_FN831314_MOV_X0_X22_INSN: u32 = 0xAA16_03E0;
pub const BOSMINER_FN831314_MOV2_VA: u64 = 0x0083_8B8C;
pub const BOSMINER_FN831314_BODY_LOC_HITS: usize = 0;
/// : `FUN_00831d18` / `FUN_00831668` are isomorphic drop helpers.
/// Shared: LDRB tag, CMP #3/#4, drop pair + `0x5f4a7c`, `MOVZ W1,#1`,
/// `BL 0x11f2764`. Split: tag +0x19 / pair +0x20 / helper *self+0
/// vs tag +0x70 / pair +0x78 / helper *self+0x68. BL hits 12 / 6.
/// 0 locs in either body. Jump-table uses `ADD X19,#0x68` into 831d18.
pub const BOSMINER_FN831D18_VA: u64 = 0x0083_1D18;
pub const BOSMINER_FN831668_VA: u64 = 0x0083_1668;
pub const BOSMINER_DROP_SIB_ENTRY_INSN: u32 = 0xA9BE_57FE;
pub const BOSMINER_DROP_SIB_CMP3_INSN: u32 = 0x7100_0D1F;
pub const BOSMINER_DROP_SIB_CMP4_INSN: u32 = 0x7100_111F;
pub const BOSMINER_DROP_SIB_MOVZ1_INSN: u32 = 0x5280_0021;
pub const BOSMINER_DROP_SIB_HELPER_VA: u64 = 0x011F_2764;
pub const BOSMINER_FN831D18_TAG_OFF: u16 = 0x19;
pub const BOSMINER_FN831D18_LDRB_INSN: u32 = 0x3940_6408;
pub const BOSMINER_FN831D18_PAIR_OFF: u16 = 0x20;
pub const BOSMINER_FN831D18_LDP_INSN: u32 = 0xA942_5275;
pub const BOSMINER_FN831D18_HELPER_ARG_OFF: u16 = 0x00;
pub const BOSMINER_FN831D18_LDR0_INSN: u32 = 0xF940_0260;
pub const BOSMINER_FN831D18_BL_HELPER_VA: u64 = 0x0083_1D68;
pub const BOSMINER_FN831D18_BL_HELPER_INSN: u32 = 0x9427_027F;
pub const BOSMINER_FN831D18_RET_VA: u64 = 0x0083_1DBC;
pub const BOSMINER_FN831D18_BL_HITS: usize = 12;
pub const BOSMINER_FN831668_TAG_OFF: u16 = 0x70;
pub const BOSMINER_FN831668_LDRB_INSN: u32 = 0x3941_C008;
pub const BOSMINER_FN831668_PAIR_OFF: u16 = 0x78;
pub const BOSMINER_FN831668_LDP_INSN: u32 = 0xA947_D275;
pub const BOSMINER_FN831668_HELPER_ARG_OFF: u16 = 0x68;
pub const BOSMINER_FN831668_LDR68_INSN: u32 = 0xF940_3660;
pub const BOSMINER_FN831668_BL_HELPER_VA: u64 = 0x0083_16B8;
pub const BOSMINER_FN831668_BL_HELPER_INSN: u32 = 0x9427_042B;
pub const BOSMINER_FN831668_RET_VA: u64 = 0x0083_1724;
pub const BOSMINER_FN831668_BL_HITS: usize = 6;
pub const BOSMINER_FN831D18_HC68_HITS: usize = 4;
pub const BOSMINER_FN831D18_HC68_ADD_INSN: u32 = 0x9101_A260;
pub const BOSMINER_FN831D18_HC68_VAS: [u64; 4] =
    [0x0083_8700, 0x0083_89CC, 0x0083_8AC4, 0x0083_8B58];
pub const BOSMINER_DROP_SIB_BODY_LOC_HITS: usize = 0;
/// : `FUN_0011f2764` is a **refcount helper**: `CBZ X1,RET`;
/// `LDXR W8,[X0]`; old==0 → `STXR #1`; else `W2=1e9` + `BL 0x44e4a0`.
/// 557 first-LOAD BLs, 537 immediately `MOVZ W1,#1`. String
/// `reference count overflow!` exists. `FUN_011f26f8` is 0x6c earlier
/// (zeros+tag), not this fn. Jump-table `X19+0x68` is `*(*X19+0x240)+0x10`,
/// dropped when `X19+0x108==3` — not a proven HashChain field ident.
pub const BOSMINER_FN11F2764_VA: u64 = 0x011F_2764;
pub const BOSMINER_FN11F2764_CBZ_INSN: u32 = 0xB400_0241;
pub const BOSMINER_FN11F2764_LDXR_VA: u64 = 0x011F_2770;
pub const BOSMINER_FN11F2764_LDXR_INSN: u32 = 0x085F_FC08;
pub const BOSMINER_FN11F2764_CBNZ0_VA: u64 = 0x011F_277C;
pub const BOSMINER_FN11F2764_CBNZ0_INSN: u32 = 0x3500_01A8;
pub const BOSMINER_FN11F2764_STXR1_VA: u64 = 0x011F_2780;
pub const BOSMINER_FN11F2764_STXR1_MOVZ_INSN: u32 = 0x5280_0028;
pub const BOSMINER_FN11F2764_STXR_VA: u64 = 0x011F_2784;
pub const BOSMINER_FN11F2764_STXR_INSN: u32 = 0x0809_7E68;
pub const BOSMINER_FN11F2764_RET_VA: u64 = 0x011F_27AC;
pub const BOSMINER_FN11F2764_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_FN11F2764_OVF_MOVZ_VA: u64 = 0x011F_27B4;
pub const BOSMINER_FN11F2764_OVF_MOVZ_INSN: u32 = 0x5299_4002;
pub const BOSMINER_FN11F2764_OVF_MOVK_VA: u64 = 0x011F_27BC;
pub const BOSMINER_FN11F2764_OVF_MOVK_INSN: u32 = 0x72A7_7342;
pub const BOSMINER_FN11F2764_OVF_BL_VA: u64 = 0x011F_27C0;
pub const BOSMINER_FN11F2764_OVF_BL_INSN: u32 = 0x97C9_6F38;
pub const BOSMINER_FN11F2764_OVF_TARGET: u64 = 0x0044_E4A0;
pub const BOSMINER_FN11F2764_BL_HITS: usize = 557;
pub const BOSMINER_FN11F2764_MOVZ1_PREV_HITS: usize = 537;
pub const BOSMINER_REFCOUNT_OVERFLOW_MSG: &str = "reference count overflow!";
pub const BOSMINER_FN11F26F8_TO_764_DELTA: u16 = 0x6C;
pub const BOSMINER_JT_PLUS68_STR_VA: u64 = 0x0083_8604;
pub const BOSMINER_JT_PLUS68_STR_INSN: u32 = 0xF900_3660;
pub const BOSMINER_JT_PLUS68_SRC240_VA: u64 = 0x0083_85F4;
pub const BOSMINER_JT_PLUS68_SRC240_INSN: u32 = 0xF941_2108;
pub const BOSMINER_JT_PLUS68_ADD10_VA: u64 = 0x0083_8600;
pub const BOSMINER_JT_PLUS68_ADD10_INSN: u32 = 0x9100_4100;
pub const BOSMINER_JT_PLUS108_OFF: u16 = 0x108;
pub const BOSMINER_JT_PLUS108_LDRB_INSN: u32 = 0x3944_2268;
/// : `FUN_0121e588` is **parking_lot_core 0.9.10 TLS get**, not Arc
/// increment/drop. `MRS TPIDR_EL0` + `ADD #0x280`; TLS tag CMP #1/#2;
/// loc `parking_lot.rs:1226:58`. 681 first-LOAD BLs. `11f2764` BL at
/// `0x11f2790` — so the W1=#1 helper is lock-word 0→1 + Parker TLS, not Arc.
pub const BOSMINER_FN121E588_VA: u64 = 0x0121_E588;
pub const BOSMINER_FN121E588_ENTRY_INSN: u32 = 0xD103_C3FF;
pub const BOSMINER_FN121E588_MOV_X19_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_FN121E588_MOV_X19_VA: u64 = 0x0121_E594;
pub const BOSMINER_FN121E588_MOVZ_VA: u64 = 0x0121_E59C;
pub const BOSMINER_FN121E588_MOVZ_INSN: u32 = 0xD2A0_0000;
pub const BOSMINER_FN121E588_MOVK_VA: u64 = 0x0121_E5A0;
pub const BOSMINER_FN121E588_MOVK_INSN: u32 = 0xF280_5000;
pub const BOSMINER_FN121E588_TLS_OFF: u16 = 0x280;
pub const BOSMINER_FN121E588_MRS_VA: u64 = 0x0121_E5AC;
pub const BOSMINER_FN121E588_MRS_INSN: u32 = 0xD53B_D048;
pub const BOSMINER_FN121E588_ADD_VA: u64 = 0x0121_E5B0;
pub const BOSMINER_FN121E588_ADD_INSN: u32 = 0x8B00_0114;
pub const BOSMINER_FN121E588_LDR_VA: u64 = 0x0121_E5B4;
pub const BOSMINER_FN121E588_LDR_INSN: u32 = 0xF840_8689;
pub const BOSMINER_FN121E588_CMP1_VA: u64 = 0x0121_E5B8;
pub const BOSMINER_FN121E588_CMP1_INSN: u32 = 0xF100_053F;
pub const BOSMINER_FN121E588_CMP2_VA: u64 = 0x0121_E5C0;
pub const BOSMINER_FN121E588_CMP2_INSN: u32 = 0xF100_093F;
pub const BOSMINER_FN121E588_RET_VA: u64 = 0x0121_E688;
pub const BOSMINER_FN121E588_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_FN121E588_BL_HITS: usize = 681;
pub const BOSMINER_FN11F2764_TLS_BL_VA: u64 = 0x011F_2790;
pub const BOSMINER_FN11F2764_TLS_BL_INSN: u32 = 0x9400_AF7E;
pub const BOSMINER_PARK_1226_LINE: u16 = 1226;
pub const BOSMINER_PARK_1226_COL: u16 = 58;
pub const BOSMINER_PARK_1226_ADRP_VA: u64 = 0x0121_E610;
pub const BOSMINER_PARK_1226_ADRP_INSN: u32 = 0xD000_4521;
pub const BOSMINER_PARK_1226_ADD_VA: u64 = 0x0121_E614;
pub const BOSMINER_PARK_1226_ADD_INSN: u32 = 0x9131_C021;
pub const BOSMINER_PARK_1226_LOC_VA: u64 = 0x01AC_4C70;
pub const BOSMINER_PARK_RS_SUFFIX: &str = "parking_lot_core-0.9.10/src/parking_lot.rs";
/// : fat-slot +0x28 BLR is the **only** `+0x238/+0x230/+0x28/BLR`
/// sequence in the jump table. X0 = fat data (`+0x230`); **no X1 write**
/// in the prelude window — `(&self) -> (X0,X1)` Future. Pair stored at
/// frame+0x28; join `B 0x836f60` is the first dyn-poll. packing.rs:40 is
/// the post-join panic pad, not the method name.
pub const BOSMINER_FAT_SLOT28_SELF_LDR_VA: u64 = 0x0083_89EC;
pub const BOSMINER_FAT_SLOT28_SELF_LDR_INSN: u32 = 0xF940_0268;
pub const BOSMINER_FAT_SLOT28_VT_LDR_VA: u64 = 0x0083_89F0;
pub const BOSMINER_FAT_SLOT28_VT_LDR_INSN: u32 = 0xF941_1D09;
pub const BOSMINER_FAT_SLOT28_DATA_LDR_VA: u64 = 0x0083_89F4;
pub const BOSMINER_FAT_SLOT28_DATA_LDR_INSN: u32 = 0xF941_1900;
pub const BOSMINER_FAT_SLOT28_BLR_VA: u64 = 0x0083_89FC;
pub const BOSMINER_FAT_SLOT28_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_FAT_SLOT28_X1_WRITES: usize = 0;
pub const BOSMINER_FAT_SLOT28_PATTERN_HITS: usize = 1;
pub const BOSMINER_FAT_SLOT28_JOIN_TARGET: u64 = 0x0083_6F60;
/// : fat-slot +0x30 BLR is the **only** `+0x238/+0x230/+0x30/BLR`
/// sequence in the jump table. X0 = fat data (`+0x230`); **one X1 write**
/// — `LDR X1,[X19,#0x10]` (Future+0x10). ABI
/// `fn(&self, Future+0x10) -> (X0,X1)` Future. Pair stored at frame+0x28;
/// join `B 0x837054` is the +0x30 dyn-poll (reload pair then poll18).
/// 0 command.rs/hashchain.rs locs in 0xC0 before the BLR.
/// The other LDR `#0x30`+BLR at `0x839d9c` is `[X22,#0x30]`, not the fat slot.
pub const BOSMINER_FAT_SLOT30_SELF_LDR_VA: u64 = 0x0083_7BB8;
pub const BOSMINER_FAT_SLOT30_SELF_LDR_INSN: u32 = 0xF940_0268;
pub const BOSMINER_FAT_SLOT30_VT_LDR_VA: u64 = 0x0083_7BC0;
pub const BOSMINER_FAT_SLOT30_VT_LDR_INSN: u32 = 0xF941_1D09;
pub const BOSMINER_FAT_SLOT30_DATA_LDR_VA: u64 = 0x0083_7BC4;
pub const BOSMINER_FAT_SLOT30_DATA_LDR_INSN: u32 = 0xF941_1900;
pub const BOSMINER_FAT_SLOT30_BLR_VA: u64 = 0x0083_7BCC;
pub const BOSMINER_FAT_SLOT30_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_FAT_SLOT30_X1_WRITES: usize = 1;
pub const BOSMINER_FAT_SLOT30_PATTERN_HITS: usize = 1;
pub const BOSMINER_FAT_SLOT30_JOIN_TARGET: u64 = 0x0083_7054;
pub const BOSMINER_FAT_SLOT30_STP_VA: u64 = 0x0083_7BD0;
pub const BOSMINER_FAT_SLOT30_JOIN_B_VA: u64 = 0x0083_7BD4;
pub const BOSMINER_FAT_SLOT30_JOIN_B_INSN: u32 = 0x17FF_FD20;
pub const BOSMINER_FAT_SLOT30_PRE_BLR_LOC_HITS: usize = 0;
pub const BOSMINER_FAT_SLOT30_OTHER_LDR30_VA: u64 = 0x0083_9D9C;
pub const BOSMINER_FAT_SLOT30_OTHER_LDR30_INSN: u32 = 0xF940_1AC8;
/// : slot +0x30 X1 is **poll-self frame+0x10**, not command.rs:700
/// Future+0x10 (that lives at bm1366 Future+0x40). Jump-table poll ABI:
/// `MOV X21,X1` / `MOV X19,X0` / `BR X10`. **0 STR** `[X19,#0x10]` in
/// `0x836000-0x83a000` — the field is construct-time. Second consumer
/// `LDR X25,[X19,#0x10]` @ `0x8371b8` joins the  Err-pack.
/// FUN_00836934 `STP [X20,#0x10]` is HashChain **object** +0x10, a
/// different function (RET before the jump table).
pub const BOSMINER_JT_POLL_CX_MOV_VA: u64 = 0x0083_6E70;
pub const BOSMINER_JT_POLL_CX_MOV_INSN: u32 = 0xAA01_03F5;
pub const BOSMINER_JT_POLL_X19_MOV_VA: u64 = 0x0083_6E74;
pub const BOSMINER_JT_POLL_X19_MOV_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_FRAME10_STR_HITS: usize = 0;
pub const BOSMINER_FRAME10_ERR_LDR_VA: u64 = 0x0083_71B8;
pub const BOSMINER_FRAME10_ERR_LDR_INSN: u32 = 0xF940_0A79;
pub const BOSMINER_FRAME10_ERR_B_VA: u64 = 0x0083_71BC;
pub const BOSMINER_FRAME10_ERR_B_INSN: u32 = 0x1400_06C7;
pub const BOSMINER_FRAME10_ERR_TARGET: u64 = 0x0083_8CD8;
pub const BOSMINER_HC_OBJ_STP10_VA: u64 = 0x0083_6B94;
pub const BOSMINER_HC_OBJ_STP10_INSN: u32 = 0xA901_6289;
/// : fat-slot +0x38 BLR is the **only** `+0x238/+0x230/+0x38/BLR`
/// sequence. **0 X1 writes** before BLR — zero-extra-arg like +0x28, but
/// Family B: STP pair at frame+0x58 and **immediate** dyn-poll (no join B).
/// `LDR X9,[X1,#0x10]` @ `0x837638` is pre-call bookkeeping, not an extra
/// slot argument. 0 locs in 0xC0 before the BLR.
pub const BOSMINER_FAT_SLOT38_SELF_LDR_VA: u64 = 0x0083_763C;
pub const BOSMINER_FAT_SLOT38_SELF_LDR_INSN: u32 = 0xF940_0268;
pub const BOSMINER_FAT_SLOT38_VT_LDR_VA: u64 = 0x0083_7660;
pub const BOSMINER_FAT_SLOT38_VT_LDR_INSN: u32 = 0xF941_1D09;
pub const BOSMINER_FAT_SLOT38_DATA_LDR_VA: u64 = 0x0083_7664;
pub const BOSMINER_FAT_SLOT38_DATA_LDR_INSN: u32 = 0xF941_1900;
pub const BOSMINER_FAT_SLOT38_BLR_VA: u64 = 0x0083_766C;
pub const BOSMINER_FAT_SLOT38_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_FAT_SLOT38_X1_WRITES: usize = 0;
pub const BOSMINER_FAT_SLOT38_PATTERN_HITS: usize = 1;
pub const BOSMINER_FAT_SLOT38_STP_VA: u64 = 0x0083_7670;
pub const BOSMINER_FAT_SLOT38_POLL_VA: u64 = 0x0083_7674;
pub const BOSMINER_FAT_SLOT38_PRE_X1_LDR_VA: u64 = 0x0083_7638;
pub const BOSMINER_FAT_SLOT38_PRE_X1_LDR_INSN: u32 = 0xF940_0829;
pub const BOSMINER_FAT_SLOT38_PRE_BLR_LOC_HITS: usize = 0;
/// : remaining-slot census. +0x40 / +0x48 / +0x78 are unique
/// `+0x238/+0x230/+slot/BLR` hits; +0x50 has **0** exact hits (sret).
/// Strongest unique ABI is **+0x40**: first fat call after poll entry,
/// copies `*[X19,#0x18]` onto `[X19,#0]`, 0 extra X1, Family-A STP at
/// frame+0x28, join `B 0x836fe4` (dyn-poll[1]).
pub const BOSMINER_FAT_SLOT40_PATTERN_HITS: usize = 1;
pub const BOSMINER_FAT_SLOT48_PATTERN_HITS: usize = 1;
pub const BOSMINER_FAT_SLOT50_PATTERN_HITS: usize = 0;
pub const BOSMINER_FAT_SLOT78_PATTERN_HITS: usize = 1;
pub const BOSMINER_FAT_SLOT40_X1_WRITES: usize = 0;
pub const BOSMINER_FAT_SLOT40_SRC18_LDR_VA: u64 = 0x0083_6E7C;
pub const BOSMINER_FAT_SLOT40_SRC18_LDR_INSN: u32 = 0xF940_0E68;
pub const BOSMINER_FAT_SLOT40_COPY0_STR_VA: u64 = 0x0083_6E84;
pub const BOSMINER_FAT_SLOT40_COPY0_STR_INSN: u32 = 0xF900_0268;
pub const BOSMINER_FAT_SLOT40_JOIN_TARGET: u64 = 0x0083_6FE4;
/// : +0x48 is unique zero-arg immediate-poll. Copies self onto
/// frame+0x28 and +0x30, STP at frame+0x40, poll is dyn-poll[5].
pub const BOSMINER_FAT_SLOT48_X1_WRITES: usize = 0;
pub const BOSMINER_FAT_SLOT48_SELF_LDR_VA: u64 = 0x0083_860C;
pub const BOSMINER_FAT_SLOT48_SELF_LDR_INSN: u32 = 0xF940_0268;
pub const BOSMINER_FAT_SLOT48_COPY28_STR_VA: u64 = 0x0083_861C;
pub const BOSMINER_FAT_SLOT48_COPY28_STR_INSN: u32 = 0xF900_1668;
pub const BOSMINER_FAT_SLOT48_COPY30_STR_VA: u64 = 0x0083_8620;
pub const BOSMINER_FAT_SLOT48_COPY30_STR_INSN: u32 = 0xF900_1A68;
pub const BOSMINER_FAT_SLOT48_VT_LDR_VA: u64 = 0x0083_8624;
pub const BOSMINER_FAT_SLOT48_VT_LDR_INSN: u32 = 0xF941_1D09;
pub const BOSMINER_FAT_SLOT48_DATA_LDR_VA: u64 = 0x0083_8628;
pub const BOSMINER_FAT_SLOT48_DATA_LDR_INSN: u32 = 0xF941_1900;
pub const BOSMINER_FAT_SLOT48_BLR_VA: u64 = 0x0083_8630;
pub const BOSMINER_FAT_SLOT48_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_FAT_SLOT48_POLL_VA: u64 = 0x0083_8638;
/// : +0x78 is unique Family-B. Prelude `LDP X8,X1,[X19,#0x30]`
/// (X1 from frame+0x38, not +0x10). STP at +0x58, join reload58.
/// hashchain.rs:336 is the post-join panic pad, not the method.
pub const BOSMINER_FAT_SLOT78_LDP_VA: u64 = 0x0083_7DCC;
pub const BOSMINER_FAT_SLOT78_LDP_INSN: u32 = 0xA943_0668;
pub const BOSMINER_FAT_SLOT78_VT_LDR_VA: u64 = 0x0083_7DD0;
pub const BOSMINER_FAT_SLOT78_VT_LDR_INSN: u32 = 0xF941_1D09;
pub const BOSMINER_FAT_SLOT78_DATA_LDR_VA: u64 = 0x0083_7DD4;
pub const BOSMINER_FAT_SLOT78_DATA_LDR_INSN: u32 = 0xF941_1900;
pub const BOSMINER_FAT_SLOT78_BLR_VA: u64 = 0x0083_7DDC;
pub const BOSMINER_FAT_SLOT78_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_FAT_SLOT78_STP_VA: u64 = 0x0083_7DE0;
pub const BOSMINER_FAT_SLOT78_JOIN_B_VA: u64 = 0x0083_7DE8;
pub const BOSMINER_FAT_SLOT78_JOIN_B_INSN: u32 = 0x17FF_FDE5;
pub const BOSMINER_FAT_SLOT78_JOIN_TARGET: u64 = 0x0083_757C;
pub const BOSMINER_FAT_SLOT78_X1_FROM_LDP: bool = true;
/// : Future+0x18 is the construct-time fat-host pointer.
/// Unique jump-table consumer is the +0x40 `LDR [X19,#0x18]`. 0 STR
/// `[X19,#0x18]` in `0x836000-0x83a000`. `0x8369b4` is HashChain-init.
pub const BOSMINER_FUTURE18_JT_STR_HITS: usize = 0;
pub const BOSMINER_HC_INIT_PLUS18_LDR_VA: u64 = 0x0083_69B4;
pub const BOSMINER_HC_INIT_PLUS18_LDR_INSN: u32 = 0xF940_0E68;
/// : construct-time writer of Future+0x10/+0x18 is the **0x188
/// clone** — not a jump-table STR. Vtable at `0x19bbae8`: drop
/// `0x831814`, size `0x188`, align `8`, poll `0x836e2c`. Unique
/// first-LOAD materialize is `ADD X1,#0xae8` after ADRP page
/// `0x19bb000`. Clone allocs `0x188`, memcpy from `SP+#8`, RET
/// `(box, vtable)`. **0 BLs** to the clone in the first LOAD.
pub const BOSMINER_FUTURE_VT_VA: u64 = 0x019B_BAE8;
pub const BOSMINER_FUTURE_VT_DROP: u64 = 0x0083_1814;
pub const BOSMINER_FUTURE_VT_SIZE: u64 = 0x188;
pub const BOSMINER_FUTURE_VT_ALIGN: u64 = 8;
pub const BOSMINER_FUTURE_VT_POLL: u64 = 0x0083_6E2C;
pub const BOSMINER_FUTURE_VT_FILE_OFF: u64 = 0x015A_BAE8;
pub const BOSMINER_FUTURE_CLONE_VA: u64 = 0x0083_6DA4;
pub const BOSMINER_FUTURE_CLONE_ENTRY_INSN: u32 = 0xD106_C3FF;
pub const BOSMINER_FUTURE_CLONE_MOVZ188_VA: u64 = 0x0083_6DC0;
pub const BOSMINER_FUTURE_CLONE_MOVZ188_INSN: u32 = 0x5280_3100;
pub const BOSMINER_FUTURE_CLONE_SRC_ADD_VA: u64 = 0x0083_6DD8;
pub const BOSMINER_FUTURE_CLONE_SRC_ADD_INSN: u32 = 0x9100_23E1;
pub const BOSMINER_FUTURE_CLONE_SIZE_MOVZ_VA: u64 = 0x0083_6DDC;
pub const BOSMINER_FUTURE_CLONE_SIZE_MOVZ_INSN: u32 = 0x5280_3102;
pub const BOSMINER_FUTURE_CLONE_MEMCPY_BL_VA: u64 = 0x0083_6DE4;
pub const BOSMINER_FUTURE_CLONE_MEMCPY_BL_INSN: u32 = 0x940E_487F;
pub const BOSMINER_FUTURE_CLONE_VT_ADD_VA: u64 = 0x0083_6DF8;
pub const BOSMINER_FUTURE_CLONE_VT_ADD_INSN: u32 = 0x912B_A021;
pub const BOSMINER_FUTURE_CLONE_BL_HITS: usize = 0;
pub const BOSMINER_FUTURE_VT_ADD_IMM: u16 = 0xAE8;
/// : the SP+#8 0x188 template is filled **by the clone
/// itself**, not a separate caller. Template base `SP+#8` ⇒
/// `STR X0,[SP,#0x20]` is Future+0x18 (fat host). `STRB WZR,[SP,#0x29]`
/// is Future+0x21 = 0. `STRB W1,[SP,#0x2a]` is Future+0x22. **No store
/// at SP+#0x18** (Future+0x10). Clone is a vtable method at
/// `0x19c17b0` on a **0x260 / align-16** owner (0 BLs). Sibling
/// `0x85a014` stores X0 at SP+#8 and uses ADD #0x1a8 — not this Future.
pub const BOSMINER_FUTURE_TMPL_BASE: u16 = 8;
pub const BOSMINER_FUTURE_TMPL_X0_SP_OFF: u16 = 0x20;
pub const BOSMINER_FUTURE_TMPL_X0_STR_VA: u64 = 0x0083_6DBC;
pub const BOSMINER_FUTURE_TMPL_X0_STR_INSN: u32 = 0xF900_13E0;
pub const BOSMINER_FUTURE_TMPL_ST21_VA: u64 = 0x0083_6DB0;
pub const BOSMINER_FUTURE_TMPL_ST21_INSN: u32 = 0x3900_A7FF;
pub const BOSMINER_FUTURE_TMPL_ST22_VA: u64 = 0x0083_6DC4;
pub const BOSMINER_FUTURE_TMPL_ST22_INSN: u32 = 0x3900_ABE1;
pub const BOSMINER_FUTURE_PLUS21_OFF: u16 = 0x21;
pub const BOSMINER_FUTURE_PLUS22_OFF: u16 = 0x22;
pub const BOSMINER_OWNER260_SIZE: u16 = 0x260;
pub const BOSMINER_OWNER260_ALIGN: u16 = 0x10;
pub const BOSMINER_OWNER260_VT_SIZE_VA: u64 = 0x019C_17A0;
pub const BOSMINER_OWNER260_VT_METHOD_VA: u64 = 0x019C_17B0;
pub const BOSMINER_OWNER260_VT_FILE_OFF: u64 = 0x015B_17A0;
pub const BOSMINER_SIB188_CLONE_VA: u64 = 0x0085_A014;
pub const BOSMINER_SIB188_X0_STR_VA: u64 = 0x0085_A02C;
pub const BOSMINER_SIB188_X0_STR_INSN: u32 = 0xF900_07E0;
pub const BOSMINER_SIB188_VT_ADD_VA: u64 = 0x0085_A064;
pub const BOSMINER_SIB188_VT_ADD_INSN: u32 = 0x9106_A021;
pub const BOSMINER_SIB188_VT_ADD_IMM: u16 = 0x1A8;
/// : fat-slot **+0x50** is the unique **sret** method.
/// Host is `*[X19,#0x30]` via `LDR pre X1,[X28,#0x38]` then
/// `LDUR X8,[X28,#-8]`. Extra **X1** is `*[X19,#0x38]`. Hidden
/// sret is `ADD X8,SP,#0x160` then `BLR X9`. After return: `LDP`
/// `X10,X20` from SP+#0x160, `LDR Q0` +0x170, `LDR` +0x180,
/// `CMP X10,XZR-via-X9`, `BL 0x40c2c4`. **Not** Poll tag-9
/// (that CMP is the previous slot at `0x837688`). Exact
/// `+0x238/+0x230/+0x50/BLR` pattern hits stay **0**.
pub const BOSMINER_FAT_SLOT50_MOV28_VA: u64 = 0x0083_76E8;
pub const BOSMINER_FAT_SLOT50_MOV28_INSN: u32 = 0xAA13_03FC;
pub const BOSMINER_FAT_SLOT50_LDR_PRE38_VA: u64 = 0x0083_76EC;
pub const BOSMINER_FAT_SLOT50_LDR_PRE38_INSN: u32 = 0xF843_8F81;
pub const BOSMINER_FAT_SLOT50_LDUR_M8_VA: u64 = 0x0083_76F0;
pub const BOSMINER_FAT_SLOT50_LDUR_M8_INSN: u32 = 0xF85F_8388;
pub const BOSMINER_FAT_SLOT50_HOST_OFF: u16 = 0x30;
pub const BOSMINER_FAT_SLOT50_X1_OFF: u16 = 0x38;
pub const BOSMINER_FAT_SLOT50_BLR_VA: u64 = 0x0083_7704;
pub const BOSMINER_FAT_SLOT50_BLR_INSN: u32 = 0xD63F_0120;
pub const BOSMINER_FAT_SLOT50_LDP_VA: u64 = 0x0083_7708;
pub const BOSMINER_FAT_SLOT50_LDP_INSN: u32 = 0xA956_53EA;
pub const BOSMINER_FAT_SLOT50_CMP0_VA: u64 = 0x0083_7718;
pub const BOSMINER_FAT_SLOT50_CMP0_INSN: u32 = 0xEB09_015F;
pub const BOSMINER_FAT_SLOT50_CONV_BL_VA: u64 = 0x0083_7740;
pub const BOSMINER_FAT_SLOT50_CONV_BL_INSN: u32 = 0x97EF_52E1;
pub const BOSMINER_FAT_SLOT50_CONV_FN_VA: u64 = 0x0040_C2C4;
pub const BOSMINER_FAT_SLOT50_SRET_SIZE: u16 = 0x28;
pub const BOSMINER_FAT_SLOT50_X1_WRITES: usize = 1;
pub const BOSMINER_FAT_SLOT50_PREV_CMP9_VA: u64 = 0x0083_7688;
pub const BOSMINER_FAT_SLOT50_PREV_CMP9_INSN: u32 = 0xF100_271F;
/// : 0x260 owner vtable **starts at drop** `0x19c1798` =
/// `FUN_00873d10`. Drop loads `+0x240` then the `+0x238/+0x230`
/// fat pair. Unique first-LOAD materialize is `0x87e3c4` ADRP
/// `0x19c1000` + `ADD #0x798`. Boxer `MOVZ #0x260` / `#0x10` then
/// `STP (box, vt)` at `[X20,#0x10]`. **Not** HashChain (that type
/// already has a field at `+0x260`). **Not** Hashboard — adjacent
/// strings are `"Hashboard "` / `": not present"` and
/// `hardware.rs:200` is a panic loc, not a type name.
pub const BOSMINER_OWNER260_VT_DROP_VA: u64 = 0x019C_1798;
pub const BOSMINER_OWNER260_VT_DROP_FILE_OFF: u64 = 0x015B_1798;
pub const BOSMINER_OWNER260_DROP_FN_VA: u64 = 0x0087_3D10;
pub const BOSMINER_OWNER260_DROP_PLUS240_LDR_VA: u64 = 0x0087_3D18;
pub const BOSMINER_OWNER260_DROP_PLUS240_LDR_INSN: u32 = 0xF941_2008;
pub const BOSMINER_OWNER260_DROP_PLUS238_LDR_VA: u64 = 0x0087_3D40;
pub const BOSMINER_OWNER260_DROP_PLUS238_LDR_INSN: u32 = 0xF941_1E74;
pub const BOSMINER_OWNER260_DROP_PLUS230_LDR_VA: u64 = 0x0087_3D44;
pub const BOSMINER_OWNER260_DROP_PLUS230_LDR_INSN: u32 = 0xF941_1A75;
pub const BOSMINER_OWNER260_BOXER_MOVZ260_VA: u64 = 0x0087_E394;
pub const BOSMINER_OWNER260_BOXER_MOVZ260_INSN: u32 = 0x5280_4C00;
pub const BOSMINER_OWNER260_BOXER_MOVZ10_VA: u64 = 0x0087_E398;
pub const BOSMINER_OWNER260_BOXER_MOVZ10_INSN: u32 = 0x5280_0201;
pub const BOSMINER_OWNER260_BOXER_ADRP_VA: u64 = 0x0087_E3C4;
pub const BOSMINER_OWNER260_BOXER_ADRP_INSN: u32 = 0xF000_8A08;
pub const BOSMINER_OWNER260_BOXER_ADD_VA: u64 = 0x0087_E3C8;
pub const BOSMINER_OWNER260_BOXER_ADD_INSN: u32 = 0x911E_6108;
pub const BOSMINER_OWNER260_BOXER_ADD_IMM: u16 = 0x798;
pub const BOSMINER_OWNER260_BOXER_STP_VA: u64 = 0x0087_E3D0;
pub const BOSMINER_OWNER260_BOXER_STP_INSN: u32 = 0xA901_2296;
pub const BOSMINER_HW200_LINE: u16 = 200;
pub const BOSMINER_HW200_COL: u16 = 14;
/// : `FUN_0040c2c4` has **4** exclusive first-LOAD BLs.
/// Three jump-table arms pass `ADD X0,SP,#0x160` (the +0x50 sret).
/// The fourth (`0x83a770`) passes `ADD X0,SP,#0x30` in a smaller
/// frame. Inner `BL 0x128ea88` is the rustc backtrace helper
/// (`RUST_LIB_BACKTRACE`, 171 BLs) — not a type name.
pub const BOSMINER_SLOT50_CONV_BL_HITS: usize = 4;
pub const BOSMINER_SLOT50_CONV_BL_VAS: [u64; 4] =
    [0x0083_7740, 0x0083_7768, 0x0083_78B4, 0x0083_A770];
pub const BOSMINER_SLOT50_CONV_JT160_HITS: usize = 3;
pub const BOSMINER_SLOT50_CONV_ARM2_BL_VA: u64 = 0x0083_7768;
pub const BOSMINER_SLOT50_CONV_ARM2_BL_INSN: u32 = 0x97EF_52D7;
pub const BOSMINER_SLOT50_CONV_ARM2_ADD_VA: u64 = 0x0083_7764;
pub const BOSMINER_SLOT50_CONV_ARM3_BL_VA: u64 = 0x0083_78B4;
pub const BOSMINER_SLOT50_CONV_ARM3_BL_INSN: u32 = 0x97EF_5284;
pub const BOSMINER_SLOT50_CONV_ARM3_ADD_VA: u64 = 0x0083_78B0;
pub const BOSMINER_SLOT50_CONV_ADD0_INSN: u32 = 0x9105_83E0;
pub const BOSMINER_SLOT50_CONV_OTHER_BL_VA: u64 = 0x0083_A770;
pub const BOSMINER_SLOT50_CONV_OTHER_BL_INSN: u32 = 0x97EF_46D5;
pub const BOSMINER_SLOT50_CONV_OTHER_ADD_VA: u64 = 0x0083_A768;
pub const BOSMINER_SLOT50_CONV_OTHER_ADD_INSN: u32 = 0x9100_C3E0;
pub const BOSMINER_SLOT50_CONV_OTHER_ADD_OFF: u16 = 0x30;
pub const BOSMINER_BACKTRACE_HELPER_VA: u64 = 0x0128_EA88;
pub const BOSMINER_BACKTRACE_HELPER_BL_HITS: usize = 171;
/// : first explicit writer of 0x188 Future+0x10 is **poll-time**
/// `STR X8,[X12,#0x10]` after `MOV X12,X19`. X8 is `LDR [X19,#0x48]`.
/// Clone does not write SP+#0x18. Jump table has **0** `STR [X19,#0x10]`
/// and **0** `STR X21,#0x10` (Context stays in X21 and is passed to
/// `FUN_00834f34` as X1). Join `B 0x837178 -> 0x8372e8`.
pub const BOSMINER_FUTURE10_SRC48_LDR_VA: u64 = 0x0083_72E0;
pub const BOSMINER_FUTURE10_SRC48_LDR_INSN: u32 = 0xF940_2668;
pub const BOSMINER_FUTURE10_ALIAS_MOV_VA: u64 = 0x0083_72F0;
pub const BOSMINER_FUTURE10_ALIAS_MOV_INSN: u32 = 0xAA13_03EC;
pub const BOSMINER_FUTURE10_STR_VA: u64 = 0x0083_7300;
pub const BOSMINER_FUTURE10_STR_INSN: u32 = 0xF900_0988;
pub const BOSMINER_FUTURE10_SRC48_OFF: u16 = 0x48;
pub const BOSMINER_FUTURE10_NEST48_ADD_VA: u64 = 0x0083_7238;
pub const BOSMINER_FUTURE10_NEST48_ADD_INSN: u32 = 0x9101_2260;
pub const BOSMINER_FUTURE10_NEST48_X1_VA: u64 = 0x0083_723C;
pub const BOSMINER_FUTURE10_NEST48_X1_INSN: u32 = 0xAA15_03E1;
pub const BOSMINER_FUTURE10_NEST48_BL_VA: u64 = 0x0083_7240;
pub const BOSMINER_FUTURE10_NEST48_BL_INSN: u32 = 0x97FF_F73D;
pub const BOSMINER_FUTURE10_NEST48_FN_VA: u64 = 0x0083_4F34;
pub const BOSMINER_FUTURE10_JOIN_B_VA: u64 = 0x0083_7178;
pub const BOSMINER_FUTURE10_JOIN_B_INSN: u32 = 0x1400_005C;
pub const BOSMINER_FUTURE10_JOIN_TARGET: u64 = 0x0083_72E8;
pub const BOSMINER_FUTURE10_JT_STR_X19_HITS: usize = 0;
pub const BOSMINER_FUTURE10_JT_STR_X21_HITS: usize = 0;
/// : Future+0x48 is an inlined **tokio 1.45.1 `Mutex::lock`
/// future**. Poll is `FUN_00834f34` (LDRB tag +0x70). Cold pads are
/// `mutex.rs:434:51` (`pub async fn lock`), `:435:27` (`acquire_fut`),
/// `:651:29` (`async fn acquire`), `:657:13` (`unreachable!`). 9
/// first-LOAD BLs, all `ADD X0,X19,#off` + Context in X1. First qword
/// at +0x48 is `*(fat+0x240)+0x28`. Not fat-slot +0x48 / not the 0x48
/// c0d4ac cell / not `lock_owned`.
pub const BOSMINER_MUTEX_LOCK_POLL_VA: u64 = 0x0083_4F34;
pub const BOSMINER_MUTEX_LOCK_POLL_ENTRY_INSN: u32 = 0xD101_83FF;
pub const BOSMINER_MUTEX_LOCK_TAG70_LDRB_VA: u64 = 0x0083_4F48;
pub const BOSMINER_MUTEX_LOCK_TAG70_LDRB_INSN: u32 = 0x3941_C008;
pub const BOSMINER_MUTEX_LOCK_TAG70_STRB_VA: u64 = 0x0083_502C;
pub const BOSMINER_MUTEX_LOCK_TAG70_STRB_INSN: u32 = 0x3901_C268;
pub const BOSMINER_MUTEX_LOCK_TAG70_OFF: u16 = 0x70;
pub const BOSMINER_MUTEX_LOCK_POLL_BL_HITS: usize = 9;
pub const BOSMINER_MUTEX_RS_SUFFIX: &str = "tokio-1.45.1/src/sync/mutex.rs";
pub const BOSMINER_MUTEX_RS_PATH_LEN: u16 = 157;
pub const BOSMINER_MUTEX_LOCK_LINE: u16 = 434;
pub const BOSMINER_MUTEX_LOCK_COL: u16 = 51;
pub const BOSMINER_MUTEX_ACQUIRE_FUT_LINE: u16 = 435;
pub const BOSMINER_MUTEX_ACQUIRE_FUT_COL: u16 = 27;
pub const BOSMINER_MUTEX_ACQUIRE_LINE: u16 = 651;
pub const BOSMINER_MUTEX_ACQUIRE_COL: u16 = 29;
pub const BOSMINER_MUTEX_UNREACHABLE_LINE: u16 = 657;
pub const BOSMINER_MUTEX_UNREACHABLE_COL: u16 = 13;
pub const BOSMINER_MUTEX_LOCK_LOC_VA: u64 = 0x019B_B2F0;
pub const BOSMINER_MUTEX_LOCK_LOC_FILE_OFF: u64 = 0x015A_B2F0;
pub const BOSMINER_MUTEX_LOCK_PAD_ADRP_VA: u64 = 0x0083_507C;
pub const BOSMINER_MUTEX_LOCK_PAD_ADRP_INSN: u32 = 0xD000_8C20;
pub const BOSMINER_MUTEX_LOCK_PAD_ADD_VA: u64 = 0x0083_5080;
pub const BOSMINER_MUTEX_LOCK_PAD_ADD_INSN: u32 = 0x910B_C000;
pub const BOSMINER_MUTEX_LOCK_PAD_BL_VA: u64 = 0x0083_5084;
pub const BOSMINER_MUTEX_LOCK_PAD_BL_INSN: u32 = 0x97F0_7AEF;
pub const BOSMINER_FUTURE48_STR_VA: u64 = 0x0083_70FC;
pub const BOSMINER_FUTURE48_STR_INSN: u32 = 0xF900_2668;
pub const BOSMINER_FUTURE48_SRC240_LDR_VA: u64 = 0x0083_70D4;
pub const BOSMINER_FUTURE48_SRC240_LDR_INSN: u32 = 0xF941_2108;
pub const BOSMINER_FUTURE48_ADD10_VA: u64 = 0x0083_70E4;
pub const BOSMINER_FUTURE48_ADD10_INSN: u32 = 0x9100_4108;
pub const BOSMINER_FUTURE48_ADD18_VA: u64 = 0x0083_70F0;
pub const BOSMINER_FUTURE48_ADD18_INSN: u32 = 0x9100_6108;
pub const BOSMINER_FUTURE48_SRC_OFF: u16 = 0x28;
pub const BOSMINER_MUTEX_UNREACHABLE_STR_VA: u64 = 0x0131_B6C7;
/// : fat-host **+0x240** is a **pointer to a 0x70 heap object**.
/// `Mutex::lock` `&self` is `*(host+0x240)+0x28` (address stored at
/// Future+0x48). Owner drop `FUN_00873d10` last-ref atomics on the
/// loaded pointer then `ADD X0,X19,#0x240; BL FUN_00b41d80` (0x70/8
/// dealloc). Jump table has **12** `LDR [Xn,#0x240]`. The only
/// first-LOAD `MOVZ #0x70` then `STR #0x240` is `0xcec010`→`0xcec094`
/// storing **XZR** (null, not a ctor). **Not** HashChain+0x240
/// (`STR W` 1e8 at `0x836c0c`). **Not** the Mutex itself. Do not
/// name Arc vs Box or `Mutex<T>`.
pub const BOSMINER_HOST240_OFF: u16 = 0x240;
pub const BOSMINER_HOST240_BOX_SIZE: u16 = 0x70;
pub const BOSMINER_HOST240_MUTEX_OFF: u16 = 0x28;
pub const BOSMINER_HOST240_LDR_HOST_VA: u64 = 0x0083_70C0;
pub const BOSMINER_HOST240_LDR_HOST_INSN: u32 = 0xF940_0268;
pub const BOSMINER_HOST240_LDR148_VA: u64 = 0x0083_70C8;
pub const BOSMINER_HOST240_LDR148_INSN: u32 = 0xF940_A509;
pub const BOSMINER_HOST240_STR8_VA: u64 = 0x0083_70CC;
pub const BOSMINER_HOST240_STR8_INSN: u32 = 0xF900_0669;
pub const BOSMINER_HOST240_JT_LDR_HITS: usize = 12;
pub const BOSMINER_HOST240_CTOR70_STR_HITS: usize = 1;
pub const BOSMINER_HOST240_NULL_MOVZ_VA: u64 = 0x00CE_C010;
pub const BOSMINER_HOST240_NULL_MOVZ_INSN: u32 = 0x5280_0E01;
pub const BOSMINER_HOST240_NULL_STR_VA: u64 = 0x00CE_C094;
pub const BOSMINER_HOST240_NULL_STR_INSN: u32 = 0xF901_227F;
pub const BOSMINER_HOST240_DROP_LDAXR_VA: u64 = 0x0087_3D20;
pub const BOSMINER_HOST240_DROP_LDAXR_INSN: u32 = 0xC85F_7D09;
pub const BOSMINER_HOST240_DROP_ADD_VA: u64 = 0x0087_3D38;
pub const BOSMINER_HOST240_DROP_ADD_INSN: u32 = 0x9109_0260;
pub const BOSMINER_HOST240_DROP_BL_VA: u64 = 0x0087_3D3C;
pub const BOSMINER_HOST240_DROP_BL_INSN: u32 = 0x940B_3811;
/// : **all 12** JT `LDR #0x240` project **+0x10**. Only the
/// lock-construct site (`0x8370d4`) also `ADD #0x18` on the same
/// register. Alternate Future+0x48 writer `0x837160` stores **+0x10**
/// (not +0x28) then `B 0x8372e8`. Sibling owner **+0x248** is another
/// last-ref pointer: `ADD X0,X19,#0x248` then `B 0x92462c`, which
/// `ADD #0x10` + `BL 0x9247b0` then `LDAXR` at **+0x08**. **Not**
/// Mutex-starts-at-+0x28. **Not** named Arc.
pub const BOSMINER_HOST240_ADD10_HITS: usize = 12;
pub const BOSMINER_HOST240_ADD18_HITS: usize = 1;
pub const BOSMINER_HOST240_ALT48_LDR_VA: u64 = 0x0083_7160;
pub const BOSMINER_HOST240_ALT48_LDR_INSN: u32 = 0xF941_2108;
pub const BOSMINER_HOST240_ALT48_ADD10_VA: u64 = 0x0083_716C;
pub const BOSMINER_HOST240_ALT48_ADD10_INSN: u32 = 0x9100_4108;
pub const BOSMINER_HOST240_ALT48_STR_VA: u64 = 0x0083_7174;
pub const BOSMINER_HOST240_ALT48_STR_INSN: u32 = 0xF900_2668;
pub const BOSMINER_HOST240_JT68_ADD10_VA: u64 = 0x0083_8600;
pub const BOSMINER_HOST240_JT68_ADD10_INSN: u32 = 0x9100_4100;
pub const BOSMINER_HOST240_JT68_STR_VA: u64 = 0x0083_8604;
pub const BOSMINER_HOST240_JT68_STR_INSN: u32 = 0xF900_3660;
pub const BOSMINER_HOST248_OFF: u16 = 0x248;
pub const BOSMINER_HOST248_DROP_ADD_VA: u64 = 0x0087_3DA8;
pub const BOSMINER_HOST248_DROP_ADD_INSN: u32 = 0x9109_2260;
pub const BOSMINER_HOST248_DROP_B_VA: u64 = 0x0087_3DB4;
pub const BOSMINER_HOST248_DROP_B_INSN: u32 = 0x1402_C21E;
pub const BOSMINER_HOST248_DROP_TGT_VA: u64 = 0x0092_462C;
pub const BOSMINER_HOST248_DROP_LDR_VA: u64 = 0x0092_4634;
pub const BOSMINER_HOST248_DROP_LDR_INSN: u32 = 0xF940_0013;
pub const BOSMINER_HOST248_DROP_ADD10_VA: u64 = 0x0092_4638;
pub const BOSMINER_HOST248_DROP_ADD10_INSN: u32 = 0x9100_4260;
pub const BOSMINER_HOST248_DROP_BL_VA: u64 = 0x0092_463C;
pub const BOSMINER_HOST248_DROP_BL_INSN: u32 = 0x9400_005D;
pub const BOSMINER_HOST248_DROP_BL_TGT: u64 = 0x0092_47B0;
pub const BOSMINER_HOST248_WEAK_ADD_VA: u64 = 0x0092_4660;
pub const BOSMINER_HOST248_WEAK_ADD_INSN: u32 = 0x9100_2268;
pub const BOSMINER_HOST248_WEAK_LDAXR_VA: u64 = 0x0092_4664;
pub const BOSMINER_HOST248_WEAK_LDAXR_INSN: u32 = 0xC85F_7D09;
/// : `FUN_009247b0` is a **counted fat-pointer element drop**.
/// `LDR X21,[X0,#0x10]` is the count (`CBZ` empty→RET). `LDR X8,[X0,#0x8]`
/// is the buffer. Cursor `ADD X22,X8,#0x18`; loop `SUBS` count, `ADD
/// #0x10` stride, `LDP X20,X19,[X22,#-0x18]`, `BLR` vtable drop, `BL
/// 0x5f4a7c` dealloc. **4** exclusive first-LOAD BLs; **3** pass
/// `ADD X0,#0x10`. **0** locs in the body. **Not** `Mutex::drop` /
/// `Semaphore::drop` / named `Vec::drop` (ptr is at +0x8, not +0).
pub const BOSMINER_9247B0_FN_VA: u64 = 0x0092_47B0;
pub const BOSMINER_9247B0_ENTRY_INSN: u32 = 0xF81D_0FFE;
pub const BOSMINER_9247B0_LEN_OFF: u16 = 0x10;
pub const BOSMINER_9247B0_PTR_OFF: u16 = 0x08;
pub const BOSMINER_9247B0_STRIDE: u16 = 0x10;
pub const BOSMINER_9247B0_LEN_LDR_VA: u64 = 0x0092_47BC;
pub const BOSMINER_9247B0_LEN_LDR_INSN: u32 = 0xF940_0815;
pub const BOSMINER_9247B0_PTR_LDR_VA: u64 = 0x0092_47C4;
pub const BOSMINER_9247B0_PTR_LDR_INSN: u32 = 0xF940_0408;
pub const BOSMINER_9247B0_ADD18_VA: u64 = 0x0092_47C8;
pub const BOSMINER_9247B0_ADD18_INSN: u32 = 0x9100_6116;
pub const BOSMINER_9247B0_SUBS_VA: u64 = 0x0092_47D0;
pub const BOSMINER_9247B0_SUBS_INSN: u32 = 0xF100_06B5;
pub const BOSMINER_9247B0_STRIDE_ADD_VA: u64 = 0x0092_47D4;
pub const BOSMINER_9247B0_STRIDE_ADD_INSN: u32 = 0x9100_42D6;
pub const BOSMINER_9247B0_LDP_VA: u64 = 0x0092_47DC;
pub const BOSMINER_9247B0_LDP_INSN: u32 = 0xA97E_CED4;
pub const BOSMINER_9247B0_BLR_VA: u64 = 0x0092_47EC;
pub const BOSMINER_9247B0_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_9247B0_DEALLOC_BL_VA: u64 = 0x0092_4800;
pub const BOSMINER_9247B0_DEALLOC_BL_INSN: u32 = 0x97F3_409F;
pub const BOSMINER_9247B0_RET_VA: u64 = 0x0092_4814;
pub const BOSMINER_9247B0_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_9247B0_BL_HITS: usize = 4;
pub const BOSMINER_9247B0_ADD10_CALLERS: usize = 3;
pub const BOSMINER_9247B0_BL_VAS: [u64; 4] = [0x0092_4320, 0x0092_4570, 0x0092_463C, 0x0092_6034];
pub const BOSMINER_9247B0_CALLER_ADD10_INSN: u32 = 0x9100_4000;
pub const BOSMINER_9247B0_CALLER_ADD10_VAS: [u64; 3] = [0x0092_456C, 0x0092_4638, 0x0092_6030];
/// : `FUN_0092462c` last-weak deallocs a **0x30**/8 object
/// (`MOVZ W1,#0x30` @ `0x924680`). **81** exclusive first-LOAD BLs —
/// a shared drop, not HashChain-unique. One JT site passes `SP+#0x270`
/// (`0x8365d4`/`d8`). After `0x9247b0`, `LDR [X19,#0x18]` deallocs an
/// extra pointer. lock() `&self` is `*240+0x28` on the **0x70** object
/// — not this 0x30 inner. **Not** 0x9247b0 elements as Mutex.
pub const BOSMINER_HOST248_INNER_SIZE: u16 = 0x30;
pub const BOSMINER_HOST248_INNER_ALIGN: u16 = 0x08;
pub const BOSMINER_HOST248_INNER_SIZE_VA: u64 = 0x0092_4680;
pub const BOSMINER_HOST248_INNER_SIZE_INSN: u32 = 0x5280_0601;
pub const BOSMINER_HOST248_INNER_ALIGN_VA: u64 = 0x0092_4688;
pub const BOSMINER_HOST248_INNER_ALIGN_INSN: u32 = 0x5280_0102;
pub const BOSMINER_92462C_BL_HITS: usize = 81;
pub const BOSMINER_92462C_JT_BL_HITS: usize = 1;
pub const BOSMINER_92462C_JT_ADD_VA: u64 = 0x0083_65D4;
pub const BOSMINER_92462C_JT_ADD_INSN: u32 = 0x9109_C3E0;
pub const BOSMINER_92462C_JT_ADD_OFF: u16 = 0x270;
pub const BOSMINER_92462C_JT_BL_VA: u64 = 0x0083_65D8;
pub const BOSMINER_92462C_JT_BL_INSN: u32 = 0x9403_B815;
pub const BOSMINER_92462C_EXTRA18_LDR_VA: u64 = 0x0092_4648;
pub const BOSMINER_92462C_EXTRA18_LDR_INSN: u32 = 0xF940_0E60;
pub const BOSMINER_92462C_POST_LDR_VA: u64 = 0x0092_4640;
pub const BOSMINER_92462C_POST_LDR_INSN: u32 = 0xF841_0268;
/// : lock() poll uses the stored pointer as `&Mutex` with
/// **0 extra ADD**. `LDR X8,[X19,#0]` @ `0x834f5c` then later
/// `STR` to +0x18; `ADD X0,X19,#0x28` is the lock-future acquire
/// slot (BL `0x11f2de4`), not Mutex+0x28. Therefore Mutex **starts**
/// at `*240` data+0x18 (`*240+0x28`). T has an **0x18** prefix
/// before that field. `*248` T is **0x20** (`0x30-0x10`) with
/// buf +0x08 / len +0x10 / extra +0x18. Element rust ident unbound.
pub const BOSMINER_MUTEX_SELF_IS_STORED_PTR: bool = true;
pub const BOSMINER_HOST240_DATA_PREFIX: u16 = 0x18;
pub const BOSMINER_HOST240_MUTEX_FIELD_OFF: u16 = 0x18;
pub const BOSMINER_LOCK_POLL_SELF_LDR_VA: u64 = 0x0083_4F5C;
pub const BOSMINER_LOCK_POLL_SELF_LDR_INSN: u32 = 0xF940_0268;
pub const BOSMINER_LOCK_POLL_SELF_STR18_VA: u64 = 0x0083_4FA8;
pub const BOSMINER_LOCK_POLL_SELF_STR18_INSN: u32 = 0xF900_0E68;
pub const BOSMINER_LOCK_POLL_ACQ_ADD_VA: u64 = 0x0083_4FD0;
pub const BOSMINER_LOCK_POLL_ACQ_ADD_INSN: u32 = 0x9100_A260;
pub const BOSMINER_LOCK_POLL_ACQ_BL_VA: u64 = 0x0083_4FD4;
pub const BOSMINER_LOCK_POLL_ACQ_BL_INSN: u32 = 0x9426_F784;
pub const BOSMINER_LOCK_POLL_ACQ_FN_VA: u64 = 0x011F_2DE4;
pub const BOSMINER_HOST248_T_SIZE: u16 = 0x20;
pub const BOSMINER_HOST248_T_BUF_OFF: u16 = 0x08;
pub const BOSMINER_HOST248_T_LEN_OFF: u16 = 0x10;
pub const BOSMINER_HOST248_T_EXTRA_OFF: u16 = 0x18;
/// : JT **0** field-LDRs of `*240` data+0/+8/+0x10 after
/// `ADD #0x10` — the 0x18 prefix is skipped as a unit. `0x9247b0`
/// elements are **Box-shaped** fat pointers (vtable drop then
/// `0x5f4a7c` dealloc unless size 0). `FUN_00586cd8` is a **66**-BL
/// stride-**0x18** index at `+0x10`/`+0x18` with a `+0x28` load;
/// **0** JT BLs — refuse as the JT `*240` prefix walker. Do not name
/// the prefix String/Vec or the element Trait.
pub const BOSMINER_PREFIX_JT_FIELD_LDR_HITS: usize = 0;
pub const BOSMINER_9247B0_ELEM_IS_BOX_SHAPED: bool = true;
pub const BOSMINER_586CD8_FN_VA: u64 = 0x0058_6CD8;
pub const BOSMINER_586CD8_BL_HITS: usize = 66;
pub const BOSMINER_586CD8_JT_BL_HITS: usize = 0;
pub const BOSMINER_586CD8_STRIDE: u16 = 0x18;
pub const BOSMINER_586CD8_STRIDE_MOVZ_VA: u64 = 0x0058_6D74;
pub const BOSMINER_586CD8_STRIDE_MOVZ_INSN: u32 = 0x5280_0309;
pub const BOSMINER_586CD8_BOUND_LDR_VA: u64 = 0x0058_6D68;
pub const BOSMINER_586CD8_BOUND_LDR_INSN: u32 = 0xF940_0E69;
pub const BOSMINER_586CD8_PTR_LDR_VA: u64 = 0x0058_6D78;
pub const BOSMINER_586CD8_PTR_LDR_INSN: u32 = 0xF940_0A6A;
pub const BOSMINER_586CD8_MADD_VA: u64 = 0x0058_6D7C;
pub const BOSMINER_586CD8_MADD_INSN: u32 = 0x9B09_2908;
pub const BOSMINER_586CD8_PLUS28_LDR_VA: u64 = 0x0058_6DA8;
pub const BOSMINER_586CD8_PLUS28_LDR_INSN: u32 = 0xF940_1676;
pub const BOSMINER_586CD8_PLUS20_LDR_VA: u64 = 0x0058_6DC0;
pub const BOSMINER_586CD8_PLUS20_LDR_INSN: u32 = 0xF940_1268;
/// : unique non-null fat-host `*240` installer is HashChain
/// clone `STR X25,[X20,#0x240]` @ `0x835334` after `memcpy` `0x230`
/// and fat `+0x230/+0x238`. `X25` is incoming `X1` via `LDR [SP,#8]`.
/// LDAXR+1 on that pointer is Arc-shaped. **54** non-SP non-XZR
/// `STR #0x240`; this insn is unique. `0xcec094` stays the only
/// `MOVZ #0x70` then `STR #0x240` and stores XZR. `0x51a8c8` is
/// `0x586cd8` index return on a **larger** object, not the 0x260 host.
pub const BOSMINER_HOST240_CLONE_FN_VA: u64 = 0x0083_5234;
pub const BOSMINER_HOST240_CLONE_FN_INSN: u32 = 0xD109_03FF;
pub const BOSMINER_HOST240_CLONE_BL_HITS: usize = 0;
pub const BOSMINER_HOST240_CLONE_X1_STR_VA: u64 = 0x0083_524C;
pub const BOSMINER_HOST240_CLONE_X1_STR_INSN: u32 = 0xF900_07E1;
pub const BOSMINER_HOST240_CLONE_X25_LDR_VA: u64 = 0x0083_5314;
pub const BOSMINER_HOST240_CLONE_X25_LDR_INSN: u32 = 0xF940_07F9;
pub const BOSMINER_HOST240_CLONE_MEMCPY_LEN: u16 = 0x230;
pub const BOSMINER_HOST240_CLONE_MEMCPY_MOVZ_VA: u64 = 0x0083_5320;
pub const BOSMINER_HOST240_CLONE_MEMCPY_MOVZ_INSN: u32 = 0x5280_4602;
pub const BOSMINER_HOST240_CLONE_MEMCPY_BL_VA: u64 = 0x0083_5324;
pub const BOSMINER_HOST240_CLONE_MEMCPY_BL_INSN: u32 = 0x940E_4F2F;
pub const BOSMINER_HOST240_CLONE_STR230_VA: u64 = 0x0083_532C;
pub const BOSMINER_HOST240_CLONE_STR230_INSN: u32 = 0xF901_1A98;
pub const BOSMINER_HOST240_CLONE_STR238_VA: u64 = 0x0083_5330;
pub const BOSMINER_HOST240_CLONE_STR238_INSN: u32 = 0xF901_1E97;
pub const BOSMINER_HOST240_CLONE_STR240_VA: u64 = 0x0083_5334;
pub const BOSMINER_HOST240_CLONE_STR240_INSN: u32 = 0xF901_2299;
pub const BOSMINER_HOST240_CLONE_STR248_VA: u64 = 0x0083_5338;
pub const BOSMINER_HOST240_CLONE_STR248_INSN: u32 = 0xF901_2688;
pub const BOSMINER_HOST240_CLONE_LDAXR_VA: u64 = 0x0083_52E8;
pub const BOSMINER_HOST240_CLONE_LDAXR_INSN: u32 = 0xC85F_7D09;
pub const BOSMINER_HOST240_CLONE_STR240_UNIQUE: usize = 1;
pub const BOSMINER_HOST240_NONSP_NONNULL_STR_HITS: usize = 54;
pub const BOSMINER_HOST240_INDEX_STR_VA: u64 = 0x0051_A8C8;
pub const BOSMINER_HOST240_INDEX_STR_INSN: u32 = 0xF901_2260;
/// :  `0x835234` is the **SUB SP,#0x240** (5th
/// prologue insn), **not** the function entry. Real entry is
/// `0x835220` `STR X29,[SP,#-0x50]!` (`0xF81B0FFD`) then four STPs.
/// Unique first-LOAD `BL` is `0x87e1cc` inside `FUN_0087e02c`
/// ( `0x2A0` method). Call ABI: `MOV X0,X23` (`*[X22,#0x298]`)
/// then `MOV X1,X24` (SP+#0x60, the `*240` payload). **0** vtable
/// qwords. HashChain Default `+0x240` stays `STR W` 1e8 @ `0x836c0c`.
/// `0x5fe12c` / `0x7b4d48` store stride-`0x18` index returns
/// (`FUN_0060b0fc` 27 BLs / `FUN_00681768` 99 BLs) — same
/// `MOVZ W9,#0x18` as `0x586cd8`. `0x749c58` stores a **0x228** box.
/// Do not name these the 0x70 Mutex first-alloc.
pub const BOSMINER_HOST240_CLONE_REAL_ENTRY_VA: u64 = 0x0083_5220;
pub const BOSMINER_HOST240_CLONE_REAL_ENTRY_INSN: u32 = 0xF81B_0FFD;
pub const BOSMINER_HOST240_CLONE_REAL_STP1_VA: u64 = 0x0083_5224;
pub const BOSMINER_HOST240_CLONE_REAL_STP1_INSN: u32 = 0xA901_67FE;
pub const BOSMINER_HOST240_CLONE_REAL_BL_HITS: usize = 1;
pub const BOSMINER_HOST240_CLONE_VT_QWORD_HITS: usize = 0;
pub const BOSMINER_HOST240_CLONE_CALLER_VA: u64 = 0x0087_E1CC;
pub const BOSMINER_HOST240_CLONE_CALLER_INSN: u32 = 0x97FE_DC15;
pub const BOSMINER_HOST240_CLONE_CALLER_FN_VA: u64 = 0x0087_E02C;
pub const BOSMINER_HOST240_CLONE_CALLER_X0_MOV_VA: u64 = 0x0087_E1C4;
pub const BOSMINER_HOST240_CLONE_CALLER_X0_MOV_INSN: u32 = 0xAA17_03E0;
pub const BOSMINER_HOST240_CLONE_CALLER_X1_MOV_VA: u64 = 0x0087_E1C8;
pub const BOSMINER_HOST240_CLONE_CALLER_X1_MOV_INSN: u32 = 0xAA18_03E1;
pub const BOSMINER_60B0FC_FN_VA: u64 = 0x0060_B0FC;
pub const BOSMINER_60B0FC_ENTRY_INSN: u32 = 0xD101_43FF;
pub const BOSMINER_60B0FC_BL_HITS: usize = 27;
pub const BOSMINER_60B0FC_STRIDE_MOVZ_VA: u64 = 0x0060_B198;
pub const BOSMINER_60B0FC_STRIDE_MOVZ_INSN: u32 = 0x5280_0309;
pub const BOSMINER_681768_FN_VA: u64 = 0x0068_1768;
pub const BOSMINER_681768_ENTRY_INSN: u32 = 0xD101_43FF;
pub const BOSMINER_681768_BL_HITS: usize = 99;
pub const BOSMINER_681768_STRIDE_MOVZ_VA: u64 = 0x0068_1804;
pub const BOSMINER_681768_STRIDE_MOVZ_INSN: u32 = 0x5280_0309;
pub const BOSMINER_5FE12C_STR240_VA: u64 = 0x005F_E12C;
pub const BOSMINER_5FE12C_STR240_INSN: u32 = 0xF901_2260;
pub const BOSMINER_7B4D48_STR240_VA: u64 = 0x007B_4D48;
pub const BOSMINER_7B4D48_STR240_INSN: u32 = 0xF901_2260;
pub const BOSMINER_749C58_STR240_VA: u64 = 0x0074_9C58;
pub const BOSMINER_749C58_STR240_INSN: u32 = 0xF901_2276;
pub const BOSMINER_749C58_ALLOC_SIZE: u16 = 0x228;
pub const BOSMINER_749C58_MOVZ_VA: u64 = 0x0074_9BF8;
pub const BOSMINER_749C58_MOVZ_INSN: u32 = 0x5280_4500;
pub const BOSMINER_749C58_X22_MOV_VA: u64 = 0x0074_9C18;
pub const BOSMINER_749C58_X22_MOV_INSN: u32 = 0xAA00_03F6;
/// : `FUN_0087e02c` has **0** `STR [SP,#0x78]`. The clone
/// `X24`/`X1` payload is `LDR [SP,#0x78]` = **sret+0x10** after
/// `ADD X8,SP,#0x68; BLR X23`. `X23` is `LDR [X1]` of the HashMap-get
/// payload (not the 0x70). Adjacent `FUN_0087deb4` is a **0x70/8**
/// returning boxer (`MOVZ #0x70`, `BL 0x5f4a78`, `RET X0`) with **0**
/// first-LOAD BLs and **1** data qword at `0x19c8838`. It does not
/// `STR #0x240` and is **not** proven to be the X24 mint. Do not name
/// Result/Arc/Mutex.
pub const BOSMINER_SP78_SRET_BASE_OFF: u16 = 0x68;
pub const BOSMINER_SP78_SRET_PLUS_OFF: u16 = 0x10;
pub const BOSMINER_SP78_LDR_OFF: u16 = 0x78;
pub const BOSMINER_SP78_SRET_ADD_VA: u64 = 0x0087_E144;
pub const BOSMINER_SP78_SRET_ADD_INSN: u32 = 0x9101_A3E8;
pub const BOSMINER_SP78_BLR23_VA: u64 = 0x0087_E15C;
pub const BOSMINER_SP78_BLR23_INSN: u32 = 0xD63F_02E0;
pub const BOSMINER_SP78_LDP68_VA: u64 = 0x0087_E160;
pub const BOSMINER_SP78_LDP68_INSN: u32 = 0xA946_D7F3;
pub const BOSMINER_SP78_LDR78_VA: u64 = 0x0087_E168;
pub const BOSMINER_SP78_LDR78_INSN: u32 = 0xF940_3FE8;
pub const BOSMINER_SP78_STR78_HITS: usize = 0;
pub const BOSMINER_SP78_X23_LDR_VA: u64 = 0x0087_E094;
pub const BOSMINER_SP78_X23_LDR_INSN: u32 = 0xF940_0037;
pub const BOSMINER_SP78_GET_BL_VA: u64 = 0x0087_E088;
pub const BOSMINER_SP78_GET_BL_INSN: u32 = 0x97FF_E9C8;
pub const BOSMINER_SP78_GET_FN_VA: u64 = 0x0087_87A8;
pub const BOSMINER_87DEB4_FN_VA: u64 = 0x0087_DEB4;
pub const BOSMINER_87DEB4_ENTRY_INSN: u32 = 0xD102_03FF;
pub const BOSMINER_87DEB4_MOVZ70_VA: u64 = 0x0087_DECC;
pub const BOSMINER_87DEB4_MOVZ70_INSN: u32 = 0x5280_0E00;
pub const BOSMINER_87DEB4_ALIGN_VA: u64 = 0x0087_DEC0;
pub const BOSMINER_87DEB4_ALIGN_INSN: u32 = 0x5280_0101;
pub const BOSMINER_87DEB4_ALLOC_BL_VA: u64 = 0x0087_DED8;
pub const BOSMINER_87DEB4_ALLOC_BL_INSN: u32 = 0x97F5_DAE8;
pub const BOSMINER_87DEB4_RET_VA: u64 = 0x0087_DF10;
pub const BOSMINER_87DEB4_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_87DEB4_BL_HITS: usize = 0;
pub const BOSMINER_87DEB4_VT_QWORD_HITS: usize = 1;
pub const BOSMINER_87DEB4_VT_FILE_OFF: u64 = 0x015B_8838;
pub const BOSMINER_87DEB4_VT_VA: u64 = 0x019C_8838;
pub const BOSMINER_87DEB4_IS_X24_MINT: bool = false;
/// : HashMap `V` is **0x18**. Spawn `BLR` loads **`V+0`**
/// (`LDR X23,[X1]`). Clone `BLR` loads **`V+8`** (`LDR X23,[X1,#8]`).
/// `FUN_008787a8` has exactly **3** first-LOAD `BL`s
/// (`0x83525c` / `0x8371f8` / `0x87e088`). HIT when `W0` bit0 **== 0**
/// (get miss tag is `MOVZ #1`; spawn `0x87e08c` is **TBNZ** `0x37` to
/// miss `0x87e278`; clone `0x835260` is **TBZ** `0x36` to HIT `0x8352d4`).
/// Third get `TBZ` to `0x837638` does **not** `BLR` `V` fields.
/// Spawn sret **0x18** at `SP+#0x68` is a **different** 0x18: qword0
/// `CBZ X19` (`0xB4001073` → `0x87e370`); qword2 `LDR [SP,#0x78]` then
/// `LDAXR X9,[X8]` (`0xC85F7D09`). Refuse naming sret as HashMap `V` or
/// as rust `Result`. Refuse `V+0` as factory4 `0x877d40` (no `X8` sret;
/// takes X1/X2/X5/X6) and `V+8` as vt0 `0x8dbdf4` (RET `X0` box, not
/// `(X0,X1)` pair). `V+0x10` exists in the insert copy but is unused by
/// spawn/clone `BLR`.
pub const BOSMINER_HASHMAP_GET_BL_HITS: usize = 3;
pub const BOSMINER_HASHMAP_GET_BL_B_VA: u64 = 0x0083_71F8;
pub const BOSMINER_HASHMAP_GET_BL_B_INSN: u32 = 0x9401_056C;
pub const BOSMINER_HASHMAP_V_SPAWN_OFF: u16 = 0;
pub const BOSMINER_HASHMAP_V_FACTORY_OFF: u16 = 8;
pub const BOSMINER_HASHMAP_V_EXTRA_OFF: u16 = 0x10;
pub const BOSMINER_HASHMAP_HIT_W0_BIT0: u8 = 0;
pub const BOSMINER_SPAWN_W0_TEST_IS_TBNZ: bool = true;
pub const BOSMINER_CLONE_GET_TBZ_VA: u64 = 0x0083_5260;
pub const BOSMINER_CLONE_GET_TBZ_INSN: u32 = 0x3600_03A0;
pub const BOSMINER_CLONE_GET_TBZ_TGT: u64 = 0x0083_52D4;
pub const BOSMINER_THIRD_GET_TBZ_VA: u64 = 0x0083_71FC;
pub const BOSMINER_THIRD_GET_TBZ_INSN: u32 = 0x3600_21E0;
pub const BOSMINER_THIRD_GET_TBZ_TGT: u64 = 0x0083_7638;
pub const BOSMINER_SRET18_Q0_CBZ_VA: u64 = 0x0087_E164;
pub const BOSMINER_SRET18_Q0_CBZ_INSN: u32 = 0xB400_1073;
pub const BOSMINER_SRET18_Q0_CBZ_TGT: u64 = 0x0087_E370;
pub const BOSMINER_SRET18_Q2_LDAXR_VA: u64 = 0x0087_E174;
pub const BOSMINER_SRET18_Q2_LDAXR_INSN: u32 = 0xC85F_7D09;
pub const BOSMINER_SRET18_IS_HASHMAP_V: bool = false;
pub const BOSMINER_HASHMAP_V0_IS_FACTORY4: bool = false;
pub const BOSMINER_HASHMAP_V8_IS_VT0: bool = false;
pub const BOSMINER_FACTORY4_X8_STR_HITS: usize = 0;
pub const BOSMINER_VT0_RET_VA: u64 = 0x008D_BE8C;
pub const BOSMINER_VT0_RET_INSN: u32 = 0xD65F_03C0;
/// : `FUN_011f2de4` is tokio-1.45.1
/// `sync::batch_semaphore::Acquire::poll` (`Future::poll`). Lock-future
/// `ADD #0x28` passes the Acquire sub-future as X0 and keeps Context in
/// X1. Body inlines `poll_proceed` (`coop/mod.rs:345:13` =
/// `register_waker`) and `poll_acquire` panic pads `:425:18` / `:493:9`.
/// TLS recipe is `+0x40` (coop), not parking_lot `+0x280`. **34**
/// first-LOAD BLs, **0** jump-table. Do not name RawMutex::lock or
/// standalone `Semaphore::poll_acquire`.
pub const BOSMINER_ACQUIRE_POLL_FN_VA: u64 = 0x011F_2DE4;
pub const BOSMINER_ACQUIRE_POLL_ENTRY_INSN: u32 = 0xD102_C3FF;
pub const BOSMINER_ACQUIRE_POLL_BL_HITS: usize = 34;
pub const BOSMINER_ACQUIRE_POLL_JT_BL_HITS: usize = 0;
pub const BOSMINER_ACQUIRE_POLL_TLS_OFF: u16 = 0x40;
pub const BOSMINER_ACQUIRE_POLL_X1_MOV_VA: u64 = 0x011F_2E0C;
pub const BOSMINER_ACQUIRE_POLL_X1_MOV_INSN: u32 = 0xAA01_03F5;
pub const BOSMINER_ACQUIRE_POLL_TLS_MOVZ_VA: u64 = 0x011F_2E10;
pub const BOSMINER_ACQUIRE_POLL_TLS_MOVZ_INSN: u32 = 0xD2A0_0000;
pub const BOSMINER_ACQUIRE_POLL_TLS_MOVK_VA: u64 = 0x011F_2E14;
pub const BOSMINER_ACQUIRE_POLL_TLS_MOVK_INSN: u32 = 0xF280_0800;
pub const BOSMINER_ACQUIRE_POLL_MRS_VA: u64 = 0x011F_2E20;
pub const BOSMINER_ACQUIRE_POLL_MRS_INSN: u32 = 0xD53B_D058;
pub const BOSMINER_ACQUIRE_POLL_COOP_ADRP_VA: u64 = 0x011F_3020;
pub const BOSMINER_ACQUIRE_POLL_COOP_ADD_VA: u64 = 0x011F_3024;
pub const BOSMINER_ACQUIRE_POLL_COOP_ADD_INSN: u32 = 0x9118_4021;
pub const BOSMINER_ACQUIRE_POLL_RET_VA: u64 = 0x011F_332C;
pub const BOSMINER_ACQUIRE_POLL_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_ACQUIRE_POLL_PAD425_ADD_VA: u64 = 0x011F_333C;
pub const BOSMINER_ACQUIRE_POLL_PAD425_ADD_INSN: u32 = 0x9116_6042;
pub const BOSMINER_ACQUIRE_POLL_PAD493_ADD_VA: u64 = 0x011F_335C;
pub const BOSMINER_ACQUIRE_POLL_PAD493_ADD_INSN: u32 = 0x9116_C084;
pub const BOSMINER_ACQUIRE_POLL_LOC425_VA: u64 = 0x01AC_2598;
pub const BOSMINER_ACQUIRE_POLL_LOC425_LINE: u32 = 425;
pub const BOSMINER_ACQUIRE_POLL_LOC425_COL: u32 = 18;
pub const BOSMINER_ACQUIRE_POLL_LOC493_VA: u64 = 0x01AC_25B0;
pub const BOSMINER_ACQUIRE_POLL_LOC493_LINE: u32 = 493;
pub const BOSMINER_ACQUIRE_POLL_LOC493_COL: u32 = 9;
pub const BOSMINER_ACQUIRE_POLL_COOP_LOC_VA: u64 = 0x01AC_3610;
pub const BOSMINER_ACQUIRE_POLL_COOP_LINE: u32 = 345;
pub const BOSMINER_ACQUIRE_POLL_COOP_COL: u32 = 13;
pub const BOSMINER_BATCH_SEMAPHORE_RS: &str = "tokio-1.45.1/src/sync/batch_semaphore.rs";
pub const BOSMINER_COOP_MOD_RS: &str = "tokio-1.45.1/src/task/coop/mod.rs";
/// Byte offset of that 16-byte Q (first 8 = nonce fn ptr).
pub const BOSMINER_CLONE_Q88_OFF: usize = 136;
/// `bosminer-units` count→log (`FUN_0125fc94`).
pub const BOSMINER_MIDSTATE_COUNT_RS: &str = "open/bosminer/bosminer-units/src/midstate_count.rs";
pub const BOSMINER_MIDSTATE_COUNT_FN_VA: u64 = 0x0125_FC94;
///  encoder-body hunt (first LOAD).
pub const BOSMINER_REV_W0_RET_HITS: usize = 0;
pub const BOSMINER_MUL_W0_W1_RET_HITS: usize = 0;
pub const BOSMINER_LSLV_W0_W0_RET_HITS: usize = 0;
/// Fill `+0x55 = 1` ⇒ [`s19k_braiins_midstate_log_from_count`] = 0.
pub const BOSMINER_FILL_MIDSTATE_LOG: u32 = 0;
/// `FUN_00bf3264`: `(+0x88_low & 0xff) / *param_4` after the nonce BLR.
pub const BOSMINER_WORK_RESP_DIV_FN_VA: u64 = 0x00BF_3264;
/// `LDR X8,[X0]` at [`BOSMINER_WORK_RESP_DIV_FN_VA`].
pub const BOSMINER_WORK_RESP_DIV_LDR_INSN: u32 = 0xF940_0008;
/// Five AM3 factories: 0 `STR`/`LDR` `#0x88`/`#0x90` in the first 0x600.
pub const BOSMINER_AM3_FACTORY_STR_88_90_HITS: usize = 0;
/// UART `FUN_0091c0a0` param_4 = Worker+0x11c0 (`MOVZ W25,#0x11c0; ADD X2,X19,X25`).
pub const BOSMINER_UART_WORK_RESP_DIV_OFF: usize = 0x11C0;
/// FPGA sibling `FUN_008af670` passes object+0x340 into the same divider.
pub const BOSMINER_FPGA_WORK_RESP_DIV_OFF: usize = 0x340;
pub const BOSMINER_FPGA_DIV_CALLER_VA: u64 = 0x008A_F670;
pub const BOSMINER_FPGA_DIV_ADD_VA: u64 = 0x008A_FA64;
/// `ADD X0,X19,#0x340` @ [`BOSMINER_FPGA_DIV_ADD_VA`].
pub const BOSMINER_FPGA_DIV_ADD_INSN: u32 = 0x910D_0260;
/// `MOVZ W25,#0x11c0` in each UART parse caller.
pub const BOSMINER_WORK_RESP_DIV_MOVZ_INSN: u32 = 0x5282_3819;
pub const BOSMINER_WORK_RESP_DIV_MOVZ_VAS: [u64; 5] = [
    0x008F_2950,
    0x008F_3A1C,
    0x008F_4AE8,
    0x008F_5BB4,
    0x008F_6C80,
];
/// `ADD X2,X19,X25` immediately before `BL FUN_0091c0a0`.
pub const BOSMINER_WORK_RESP_ADD_X2_INSN: u32 = 0x8B19_0262;
pub const BOSMINER_WORK_RESP_PARSE_CALLER_COUNT: usize = 5;
pub const BOSMINER_WORK_RESP_PARSE_CALLER_VAS: [u64; 5] = [
    0x008F_29F0,
    0x008F_3ABC,
    0x008F_4B88,
    0x008F_5C54,
    0x008F_6D20,
];
/// `FUN_00900810` `STR X19,[SP,#0x88]` — stack spill, not engine+0x88.
pub const BOSMINER_WORKER_CTOR_STR88_SP_VA: u64 = 0x0090_086C;
pub const BOSMINER_WORKER_CTOR_STR88_SP_INSN: u32 = 0xF900_47F3;
/// `FUN_0086e3f4` memcpy of the RX object from the HashChain wrapper.
pub const BOSMINER_RX_WRAPPER_FN_VA: u64 = 0x0086_E3F4;
pub const BOSMINER_RX_WRAPPER_COPY_OFF: usize = 0x10;
pub const BOSMINER_RX_WRAPPER_COPY_LEN: usize = 0x1390;
/// `ADD X1,X19,#0x10` then `MOVZ W2,#0x1390` @ `0x86e420` / `0x86e424`.
pub const BOSMINER_RX_WRAPPER_ADD_SRC_INSN: u32 = 0x9100_4261;
pub const BOSMINER_RX_WRAPPER_SIZE_INSN: u32 = 0x5282_7202;
pub const BOSMINER_RX_WRAPPER_ADD_SRC_VA: u64 = 0x0086_E420;
pub const BOSMINER_RX_WRAPPER_SIZE_VA: u64 = 0x0086_E424;
/// HashChain run: copy `param_1+0x30` then TLS-drop then RX wrapper.
pub const BOSMINER_HASHCHAIN_RUN_FN_VA: u64 = 0x0089_271C;
/// RX+0x11c0 on the `FUN_0086e3f4` copy = wrapper+0x11d0 (header +0x10).
pub const BOSMINER_WRAPPER_DIV_OFF: usize = 0x11D0;
/// `FUN_0089271c` first memcpy src is HashChain+0x30 (`ADD X1,X19,#0x30`).
pub const BOSMINER_HASHCHAIN_RX_COPY_OFF: usize = 0x30;
/// Parse divisor field on the HashChain object: `+0x30 + 0x11c0`.
pub const BOSMINER_HASHCHAIN_DIV_OFF: usize = 0x11F0;
/// `ADD X1,X19,#0x30` @ `0x8927a8` then `MOVZ W2,#0x1390` @ `0x8927ac`.
pub const BOSMINER_HASHCHAIN_COPY_ADD_VA: u64 = 0x0089_27A8;
pub const BOSMINER_HASHCHAIN_COPY_ADD_INSN: u32 = 0x9100_C261;
pub const BOSMINER_HASHCHAIN_COPY_SIZE_VA: u64 = 0x0089_27AC;
pub const BOSMINER_HASHCHAIN_COPY_SIZE_INSN: u32 = 0x5282_7202;
/// `FUN_0086e3d0`: 4-qword stack copy then `FUN_0128caa4` (TLS drop).
pub const BOSMINER_TLS_DROP_FN_VA: u64 = 0x0086_E3D0;
pub const BOSMINER_TLS_DROP_INNER_FN_VA: u64 = 0x0128_CAA4;
/// `MRS X22,tpidr_el0` @ `0x128cae0` inside `FUN_0128caa4`.
pub const BOSMINER_TLS_DROP_MRS_VA: u64 = 0x0128_CAE0;
pub const BOSMINER_TLS_DROP_MRS_INSN: u32 = 0xD53B_D056;
/// HashChain run `BL FUN_0086e3d0` @ `0x892814`.
pub const BOSMINER_HASHCHAIN_RUN_TLS_DROP_BL_VA: u64 = 0x0089_2814;
pub const BOSMINER_HASHCHAIN_RUN_TLS_DROP_BL_INSN: u32 = 0x97FF_6EEF;
/// `FUN_0086e3d0` `BL FUN_0128caa4` @ `0x86e3e4`.
pub const BOSMINER_TLS_DROP_INNER_BL_VA: u64 = 0x0086_E3E4;
pub const BOSMINER_TLS_DROP_INNER_BL_INSN: u32 = 0x9428_79B0;
/// `FUN_00bf3264` cold path: `CBZ X8` → `FUN_00453bd8` (divide-by-zero panic).
pub const BOSMINER_WORK_RESP_DIV_CBZ_VA: u64 = 0x00BF_3268;
pub const BOSMINER_WORK_RESP_DIV_CBZ_INSN: u32 = 0xB400_00A8;
pub const BOSMINER_WORK_RESP_DIV_AND_VA: u64 = 0x00BF_326C;
pub const BOSMINER_WORK_RESP_DIV_AND_INSN: u32 = 0x9240_1C29;
pub const BOSMINER_WORK_RESP_DIV_UDIV_VA: u64 = 0x00BF_3274;
pub const BOSMINER_WORK_RESP_DIV_UDIV_INSN: u32 = 0x9AC8_0920;
/// `FUN_00749200` `STR X21,[X19,#0x11f0]` — Halt.rs Box, not the UART u64.
pub const BOSMINER_HALT_BOX_STR_11F0_VA: u64 = 0x0074_92B8;
pub const BOSMINER_HALT_BOX_STR_11F0_INSN: u32 = 0xF908_FA75;
pub const BOSMINER_HALT_RS: &str = "open/bosminer/bosminer/src/halt.rs";
/// Five Worker/HashChain inits `STR XZR,[Xn,#0x11f0]` (ctor zero of the slot).
pub const BOSMINER_HASHCHAIN_CTOR_STR_XZR_11F0_VA: u64 = 0x0090_1248;
pub const BOSMINER_HASHCHAIN_CTOR_STR_XZR_11F0_INSN: u32 = 0xF908_FABF;
/// Six non-SP `LDR #0x11f0` — each pairs with `LDR #0x11f8` (Box ptr+vtable).
pub const BOSMINER_LDR_11F0_HITS: usize = 6;
pub const BOSMINER_LDR_11F0_PAIR_11F8_HITS: usize = 6;
pub const BOSMINER_LDR_11F0_VA: u64 = 0x0052_BEF4;
pub const BOSMINER_LDR_11F0_INSN: u32 = 0xF948_FA75;
pub const BOSMINER_LDR_11F8_VA: u64 = 0x0052_BEF0;
pub const BOSMINER_LDR_11F8_INSN: u32 = 0xF948_FE76;
pub const BOSMINER_LDR_11F0_VAS: [u64; 6] = [
    0x0052_BEF4,
    0x0052_E130,
    0x0055_D52C,
    0x0055_F6D0,
    0x005C_3EB0,
    0x005C_60D8,
];
/// `MOVZ W2,#0x11f0` then `FUN_00bc8fe0` — memcpy length, not a field addend.
pub const BOSMINER_MOVZ_11F0_MEMCPY_VA: u64 = 0x006A_9208;
pub const BOSMINER_MOVZ_11F0_MEMCPY_INSN: u32 = 0x5282_3E02;
/// Tracing string only; one ADRP+ADD xref, not a chip_count store.
pub const BOSMINER_ANTMINER_DRIVER_INIT_STR: &str = "AntminerDriver::init";
pub const BOSMINER_ANTMINER_DRIVER_INIT_XREF_VA: u64 = 0x0083_7200;
/// `FUN_008f47c4` calls UART parse at this site (`BL FUN_0091c0a0`).
pub const BOSMINER_RX_WRAPPER_PARSE_BL_VA: u64 = 0x008F_4B88;
/// Future snapshot of HashChain+0x30 is `0x1270` bytes (covers +0x11F0, does not mint it).
pub const BOSMINER_FUTURE_SNAP_SIZE: usize = 0x1270;
pub const BOSMINER_FUTURE_SNAP_SIZE_VA: u64 = 0x0049_0D5C;
pub const BOSMINER_FUTURE_SNAP_SIZE_INSN: u32 = 0x5282_4E02;
/// `FUN_0048e770` `*(self+0x30) = 2` after copying the 0x1270 snapshot out.
pub const BOSMINER_FUTURE_SNAP_FN_VA: u64 = 0x0048_E770;
pub const BOSMINER_FUTURE_TAG2_OFF: usize = 0x30;
pub const BOSMINER_FUTURE_TAG2_VA: u64 = 0x0048_E7B8;
pub const BOSMINER_FUTURE_TAG2_INSN: u32 = 0xB900_3289;
/// Restore-side `MOVZ W8,#2` @ `0x490d3c` before dest=`X19+#0x30` memcpy.
pub const BOSMINER_FUTURE_RESTORE_TAG2_VA: u64 = 0x0049_0D3C;
pub const BOSMINER_FUTURE_RESTORE_TAG2_INSN: u32 = 0x5280_0048;
/// `FUN_0050b9d0` drops the +0x30 state machine (not a count store).
pub const BOSMINER_FUTURE_DROP_FN_VA: u64 = 0x0050_B9D0;
pub const BOSMINER_FUTURE_DROP_INSN: u32 = 0xF81E_0FFE;
/// Object dest `ADD X0,Xn,#0x30` + `MOVZ W2,#0x1270` + memcpy (Xn≠SP).
pub const BOSMINER_OBJECT_30_1270_MEMCPY_HITS: usize = 54;
/// `UBFX Wd,Wn,#17,#8` — DCENT asic_index shape; none are a tiny +0x88 body.
pub const BOSMINER_UBFX_17_8_HITS: usize = 5;
pub const BOSMINER_UBFX_17_8_INSN: u32 = 0x5311_60C6;
pub const BOSMINER_UBFX_17_8_VA: u64 = 0x0058_2B30;
pub const BOSMINER_UBFX_17_8_VAS: [u64; 5] = [
    0x0058_2B30,
    0x0078_D490,
    0x0078_D78C,
    0x0093_6D48,
    0x0093_7064,
];
/// `ADD Xd,Xn,#0x90` then `STR [Xd,#0x88]` with Xd≠SP = 0. Four hits are SP epilogue.
pub const BOSMINER_ADD90_STR88_NONSP_HITS: usize = 0;
pub const BOSMINER_ADD90_STR88_SP_HITS: usize = 4;
pub const BOSMINER_ADD90_STR88_SP_VA: u64 = 0x00A1_E8BC;
pub const BOSMINER_ADD90_STR88_SP_INSN: u32 = 0xF900_47E8;
pub const BOSMINER_ADD90_SP_INSN: u32 = 0x9102_43FF;
pub const BOSMINER_ADD90_SP_VA: u64 = 0x00A1_E89C;
/// `STR Xt,[Xn,Xm,LSL#3]` in first LOAD = 0.
pub const BOSMINER_REG_STR_LSL3_HITS: usize = 0;
/// `FUN_00875f54` clone body `0x875f54..0x87623b` (dest/src MOVs pinned above).
/// BM1366 factory `MOV X24,X1` then `LDR X8,[X24,#0x70]` (engine midstate log).
pub const BOSMINER_FACTORY_X1_SAVE_VA: u64 = 0x0087_6D04;
pub const BOSMINER_FACTORY_X1_SAVE_INSN: u32 = 0xAA01_03F8;
pub const BOSMINER_FACTORY_X1_LDR70_VA: u64 = 0x0087_6D4C;
pub const BOSMINER_FACTORY_X1_LDR70_INSN: u32 = 0xF940_3B08;
/// `FUN_00876398` `STR X8,[X19,#0x88]` — Future waker, not engine nonce fn.
pub const BOSMINER_FUTURE_STR88_VA: u64 = 0x0087_64BC;
pub const BOSMINER_FUTURE_STR88_INSN: u32 = 0xF900_4668;
/// `STR #0x118` of an ADRP `.text` target = 0 (HashChain+0x90+0x88 hypothesis).
pub const BOSMINER_STR118_ADRP_TEXT_HITS: usize = 0;
/// `STR W #0x11c0` / `#0x11f0` non-SP = 0. Object-src split `ADD #0x1000+#0x1c0/#0x1f0` = 0.
pub const BOSMINER_STRW_11C0_NONSP_HITS: usize = 0;
pub const BOSMINER_STRW_11F0_NONSP_HITS: usize = 0;
pub const BOSMINER_SPLIT_11C0_OBJ_HITS: usize = 0;
/// Chip dispatch `FUN_008d6cf0` baud for 0x1366: `0x2faf08` = 3_125_000.
pub const BOSMINER_DISPATCH_BAUD_3125K: u32 = 3_125_000;
pub const BOSMINER_DISPATCH_BAUD_MOVZ_VA: u64 = 0x008D_6D20;
pub const BOSMINER_DISPATCH_BAUD_MOVZ_INSN: u32 = 0x5295_E109;
pub const BOSMINER_DISPATCH_BAUD_MOVK_VA: u64 = 0x008D_6D24;
pub const BOSMINER_DISPATCH_BAUD_MOVK_INSN: u32 = 0x72A0_05E9;
/// BM1366 vtable slot used only as DATA next to the factory; `[17]` is rust hash, not +0x88.
pub const BOSMINER_BM1366_VT_VA: u64 = 0x01AC_DAE8;
pub const BOSMINER_BM1366_VT_HASH_FN_VA: u64 = 0x008B_BFB0;
/// Direct `BL` to the five AM3 factories = 0 (DATA/fn-ptr only).
pub const BOSMINER_AM3_FACTORY_BL_HITS: usize = 0;
/// Sole ADRP+ADD that materializes `FUN_00876ca8` (dispatch **store**, not BLR).
pub const BOSMINER_FACTORY_ADDR_ADRP_VA: u64 = 0x008D_6D0C;
pub const BOSMINER_FACTORY_ADDR_ADRP_INSN: u32 = 0x90FF_FD08;
pub const BOSMINER_FACTORY_ADDR_ADD_VA: u64 = 0x008D_6D10;
pub const BOSMINER_FACTORY_ADDR_ADD_INSN: u32 = 0x9132_A108;
/// BM1366 factory `BL Worker::new` (`FUN_00903534`) with dest = saved X0.
pub const BOSMINER_FACTORY_WORKER_NEW_BL_VA: u64 = 0x0087_6DA0;
pub const BOSMINER_FACTORY_WORKER_NEW_BL_INSN: u32 = 0x9402_31E5;
pub const BOSMINER_FACTORY_WORKER_NEW_DEST_VA: u64 = 0x0087_6D8C;
pub const BOSMINER_FACTORY_WORKER_NEW_DEST_INSN: u32 = 0xAA17_03E0;
/// After Worker::new: `MOVZ W2,#0x15f8` memcpy **stack→stack** (SP+0x40 ← SP+0x1640).
pub const BOSMINER_FACTORY_SNAP_SIZE: usize = 0x15F8;
pub const BOSMINER_FACTORY_SNAP_SIZE_VA: u64 = 0x0087_6DB8;
pub const BOSMINER_FACTORY_SNAP_SIZE_INSN: u32 = 0x5282_BF02;
pub const BOSMINER_FACTORY_SNAP_DEST_ADD_VA: u64 = 0x0087_6DB4;
pub const BOSMINER_FACTORY_SNAP_DEST_ADD_INSN: u32 = 0x9101_03E9;
pub const BOSMINER_FACTORY_SNAP_ORR_DEST_INSN: u32 = 0xB27D_0120;
pub const BOSMINER_FACTORY_SNAP_ORR_SRC_INSN: u32 = 0xB27D_0101;
/// `FUN_008d809c` `LDR X0,[X8,#8]; BLR` is drop/dealloc, not the factory.
pub const BOSMINER_DROP_LDR8_BLR_VA: u64 = 0x008D_8148;
pub const BOSMINER_DROP_LDR8_BLR_FN_VA: u64 = 0x008D_809C;
/// `LDR [Xn,#0]; ADD #0x10; STR [Xm,#0x88]` — rust slice data+16, not .text.
pub const BOSMINER_SLICE10_STR88_HITS: usize = 7;
pub const BOSMINER_SLICE10_STR88_VA: u64 = 0x0086_CADC;
pub const BOSMINER_SLICE10_STR88_INSN: u32 = 0xF900_4668;
pub const BOSMINER_SLICE10_LDR_VA: u64 = 0x0086_CAC4;
pub const BOSMINER_SLICE10_LDR_INSN: u32 = 0xF940_0148;
pub const BOSMINER_SLICE10_ADD_INSN: u32 = 0x9100_4108;
/// `FUN_008787a8` HashMap get; key is `u16` at lookup+0x19c (chip id).
pub const BOSMINER_HASHMAP_GET_FN_VA: u64 = 0x0087_87A8;
pub const BOSMINER_HASHMAP_GET_HASH_BL_VA: u64 = 0x0087_87DC;
pub const BOSMINER_HASHMAP_GET_KEY_OFF: usize = 0x19C;
/// `FUN_00835220`: get then `LDR X23,[X1,#8]; BLR X23` (factory at value+8).
pub const BOSMINER_FACTORY_GET_CALLER_VA: u64 = 0x0083_5220;
pub const BOSMINER_FACTORY_GET_BL_VA: u64 = 0x0083_525C;
pub const BOSMINER_FACTORY_GET_BL_INSN: u32 = 0x9401_0D53;
pub const BOSMINER_FACTORY_LDR8_VA: u64 = 0x0083_52D4;
pub const BOSMINER_FACTORY_LDR8_INSN: u32 = 0xF940_0437;
pub const BOSMINER_FACTORY_BLR_VA: u64 = 0x0083_5308;
pub const BOSMINER_FACTORY_BLR_INSN: u32 = 0xD63F_02E0;
/// `FUN_0083b3a0` builds factory X0 from HashChain `+0x10`/`+0xf0` onto SP+0x10.
pub const BOSMINER_FACTORY_PREP_FN_VA: u64 = 0x0083_B3A0;
pub const BOSMINER_FACTORY_PREP_BL_VA: u64 = 0x0083_52E0;
pub const BOSMINER_FACTORY_PREP_BL_INSN: u32 = 0x9400_1830;
/// `FUN_0087e02c` `BL FUN_00835220` — production get+BLR caller.
pub const BOSMINER_FACTORY_GET_OUTER_BL_VA: u64 = 0x0087_E1CC;
pub const BOSMINER_FACTORY_GET_OUTER_BL_INSN: u32 = 0x97FE_DC15;
/// Factory copies X1 (`X24`) onto SP+0x1640 via `FUN_0087fb4c` (clone + chip_id +0x19c).
pub const BOSMINER_SP1640_CLONE_FN_VA: u64 = 0x0087_FB4C;
pub const BOSMINER_SP1640_CLONE_BL_VA: u64 = 0x0087_6E44;
pub const BOSMINER_SP1640_CLONE_BL_INSN: u32 = 0x9400_2342;
pub const BOSMINER_SP1640_CLONE_SRC_INSN: u32 = 0xAA18_03E1;
pub const BOSMINER_SP1640_CLONE_ADD_INSN: u32 = 0x9119_0000;
/// `FUN_0083b3a0` `ADD X0,X1,#0xf0` then `FUN_012d276c` (String/Vec clone).
pub const BOSMINER_PREP_ADD_F0_VA: u64 = 0x0083_B3CC;
pub const BOSMINER_PREP_ADD_F0_INSN: u32 = 0x9103_C020;
/// `FUN_0083b3a0` `MOV X20,X1` @ [`BOSMINER_PREP_X20_MOV_VA`].
pub const BOSMINER_PREP_X20_MOV_INSN: u32 = 0xAA01_03F4;
pub const BOSMINER_PREP_ADD_10_VA: u64 = 0x0083_B3F0;
pub const BOSMINER_PREP_ADD_10_INSN: u32 = 0x9100_4280;
/// Prep body `0x83b3a0..=0x83b807` has **zero** `STR #0x88`.
pub const BOSMINER_PREP_STR88_HITS: usize = 0;
/// `FUN_012d276c`: `LDR [X0,#0x10]` len, `LDR [X0,#8]` ptr, memcpy.
pub const BOSMINER_VEC_CLONE_FN_VA: u64 = 0x012D_276C;
pub const BOSMINER_VEC_CLONE_LEN_LDR_INSN: u32 = 0xF940_0813;
pub const BOSMINER_VEC_CLONE_PTR_LDR_INSN: u32 = 0xF940_0415;
/// `FUN_0087e02c` saves context in X22; factory dest `[X22,#0x298]`.
pub const BOSMINER_FACTORY_CTX_MOV_INSN: u32 = 0xAA00_03F6;
pub const BOSMINER_FACTORY_DEST_LDR298_INSN: u32 = 0xF941_4ED7;
pub const BOSMINER_FACTORY_DEST_MOV_INSN: u32 = 0xAA17_03E0;
pub const BOSMINER_FACTORY_X1_MOV_INSN: u32 = 0xAA18_03E1;
/// Factory X1 is `[SP,#0x78]` (`local_738` Arc) after spawn `BLR`.
pub const BOSMINER_FACTORY_X1_LDR_SP78_VA: u64 = 0x0087_E168;
pub const BOSMINER_FACTORY_X1_LDR_SP78_INSN: u32 = 0xF940_3FE8;
pub const BOSMINER_FACTORY_SPAWN_BLR_VA: u64 = 0x0087_E15C;
pub const BOSMINER_FACTORY_SPAWN_BLR_INSN: u32 = 0xD63F_02E0;
pub const BOSMINER_FACTORY_SPAWN_DEST_ADD_INSN: u32 = 0x9101_A3E8;
/// `FUN_00835220` prep source is the clone (X19), not factory X1.
pub const BOSMINER_PREP_SRC_MOV_INSN: u32 = 0xAA13_03E1;
pub const BOSMINER_GET_LOOKUP_MOV_INSN: u32 = 0xAA02_03E1;
/// `FUN_0093cc3c` polls `context+0x230`; not the X1 constructor.
pub const BOSMINER_93CC3C_FN_VA: u64 = 0x0093_CC3C;
pub const BOSMINER_93CC3C_SRC_ADD_INSN: u32 = 0x9108_C000;
pub const BOSMINER_93CC3C_BL_INSN: u32 = 0x9402_FAF7;
/// Insert copies value from `&entry|8`; second qword is BM1366 vtable[0].
pub const BOSMINER_INSERT_VALUE_ORR8_INSN: u32 = 0xB27D_02A3;
pub const BOSMINER_DISPATCH_VT0_LDR_INSN: u32 = 0xF945_754A;
pub const BOSMINER_DISPATCH_1366_STP_INSN: u32 = 0xA902_ABE8;
pub const BOSMINER_BM1366_VT0_FN_VA: u64 = 0x008D_BDF4;
pub const BOSMINER_BM1366_VT0_QWORD: u64 = 0x008D_BDF4;
/// `FUN_008dbdf4`: require `*(prep+0x228)==1`, memcpy `0x230`, box `0x250`.
pub const BOSMINER_VT0_TAG_OFF: usize = 0x228;
pub const BOSMINER_VT0_U16_OFF: usize = 0x229;
pub const BOSMINER_VT0_COPY_SIZE: usize = 0x230;
pub const BOSMINER_VT0_BOX_SIZE: usize = 0x250;
pub const BOSMINER_VT0_LDRB_228_VA: u64 = 0x008D_BE04;
pub const BOSMINER_VT0_LDRB_228_INSN: u32 = 0x3948_A008;
pub const BOSMINER_VT0_CMP1_INSN: u32 = 0x7100_051F;
pub const BOSMINER_VT0_ADD_229_INSN: u32 = 0x9108_A668;
pub const BOSMINER_VT0_COPY_230_INSN: u32 = 0x5280_4602;
pub const BOSMINER_VT0_BOX_250_INSN: u32 = 0x5280_4A00;
pub const BOSMINER_VT0_MEMCPY_BL_INSN: u32 = 0x940B_B46B;
pub const BOSMINER_VT0_PANIC_LINE: u16 = 0x23;
pub const BOSMINER_VT0_PANIC_LINE_INSN: u32 = 0x5280_0461;
pub const BOSMINER_VT0_STR88_HITS: usize = 0;
pub const BOSMINER_VT0_BL_HITS: usize = 0;
/// First-LOAD `STRB #0x228`: 32 total, 16 `WZR` (zero-init).
pub const BOSMINER_TAG228_STRB_HITS: usize = 32;
pub const BOSMINER_TAG228_STRB_WZR_HITS: usize = 16;
/// `MOVZ #1` into the same Wt then `STRB #0x228` = **2**.
pub const BOSMINER_TAG1_STRB_HITS: usize = 2;
/// `FUN_006079d4` `MOVZ W10,#1` + `STRB [X19,#0x228]` (0 `BL`).
pub const BOSMINER_TAG1_A_FN_VA: u64 = 0x0060_79D4;
pub const BOSMINER_TAG1_A_BL_HITS: usize = 0;
pub const BOSMINER_TAG1_A_MOVZ_VA: u64 = 0x0060_9E9C;
pub const BOSMINER_TAG1_A_MOVZ_INSN: u32 = 0x5280_002A;
pub const BOSMINER_TAG1_A_STRB_VA: u64 = 0x0060_9EA4;
pub const BOSMINER_TAG1_A_STRB_INSN: u32 = 0x3908_A26A;
/// Second tag=1: `MOVZ W8,#1` + `STRB [X23,#0x228]`.
pub const BOSMINER_TAG1_B_MOVZ_VA: u64 = 0x0074_93DC;
pub const BOSMINER_TAG1_B_MOVZ_INSN: u32 = 0x5280_0028;
pub const BOSMINER_TAG1_B_STRB_VA: u64 = 0x0074_93E4;
pub const BOSMINER_TAG1_B_STRB_INSN: u32 = 0x3908_A2E8;
/// `FUN_005f4a8c` stores **0x7c**, not tag 1.
pub const BOSMINER_TAG7C_MOVZ_INSN: u32 = 0x5280_0F88;
pub const BOSMINER_TAG7C_STRB_VA: u64 = 0x005F_5A20;
pub const BOSMINER_TAG7C_STRB_INSN: u32 = 0x3908_A268;
/// Prep copies source `+0x22c`, not tag `+0x228`.
pub const BOSMINER_PREP_STRB_22C_VA: u64 = 0x0083_B788;
pub const BOSMINER_PREP_STRB_22C_INSN: u32 = 0x3908_B275;
/// `FUN_0083b3a0` snapshots HashChain `+0x228` as **u32** (not the MOVZ#1 STRBs).
pub const BOSMINER_PREP_LDRW_228_VA: u64 = 0x0083_B76C;
pub const BOSMINER_PREP_LDRW_228_INSN: u32 = 0xB942_2A9C;
pub const BOSMINER_PREP_STRW_228_VA: u64 = 0x0083_B7A8;
pub const BOSMINER_PREP_STRW_228_INSN: u32 = 0xB902_2A7C;
/// `FUN_00749200` `ADD X23,X0,#0x1000` then STRB #0x228 = Halt **`+0x1228`**.
pub const BOSMINER_HALT_SPLIT_ADD_VA: u64 = 0x0074_9220;
pub const BOSMINER_HALT_SPLIT_ADD_INSN: u32 = 0x9140_0417;
/// `FUN_006079d4` `MOV X19,X0` — true `+0x228` on a **0x250** object, not HashChain.
pub const BOSMINER_TAG1_A_X19_MOV_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_TAG1_A_ADD250_INSN: u32 = 0x9109_4276;
pub const BOSMINER_TAG1_A_OFF_19C_HITS: usize = 0;
pub const BOSMINER_TAG1_A_OFF_11F0_HITS: usize = 0;
/// `FUN_00825568` instantiate: `MOVZ W2,#0x2a0` memcpy of `FUN_00878950` result.
pub const BOSMINER_INSTANTIATE_FN_VA: u64 = 0x0082_5568;
pub const BOSMINER_INSTANTIATE_BL_HITS: usize = 1;
pub const BOSMINER_INSTANTIATE_SNAP_SIZE: usize = 0x2A0;
pub const BOSMINER_INSTANTIATE_SNAP_VA: u64 = 0x0082_5694;
pub const BOSMINER_INSTANTIATE_SNAP_INSN: u32 = 0x5280_5402;
pub const BOSMINER_INSTANTIATE_MEMCPY_BL_INSN: u32 = 0x940E_8E52;
/// `FUN_00878950` copies prep `0x230` (includes `+0x228`) then stores at `+0x230`.
pub const BOSMINER_INSTANTIATE_BUILD_FN_VA: u64 = 0x0087_8950;
pub const BOSMINER_INSTANTIATE_BUILD_230_VA: u64 = 0x0087_8C64;
pub const BOSMINER_INSTANTIATE_BUILD_230_INSN: u32 = 0x5280_4602;
pub const BOSMINER_INSTANTIATE_BUILD_MEMCPY_BL_INSN: u32 = 0x940D_40DE;
pub const BOSMINER_INSTANTIATE_BUILD_STR230_INSN: u32 = 0xF901_1AFC;
/// `FUN_006079d4` `MOVZ W8,#0x100,LSL#16` + `STR W #0x228` = `0x0100_0000`.
pub const BOSMINER_TAG228_W1000000_MOVZ_INSN: u32 = 0x52A0_2008;
pub const BOSMINER_TAG228_W1000000_STR_VA: u64 = 0x0060_9A60;
pub const BOSMINER_TAG228_W1000000_STR_INSN: u32 = 0xB902_2A68;
/// `FUN_00835220` post-BLR memcpy of clone is also `0x230`.
pub const BOSMINER_FACTORY_COPY_230_VA: u64 = 0x0083_5320;
pub const BOSMINER_FACTORY_COPY_230_INSN: u32 = 0x5280_4602;
/// Five AM3 HashChain inits: 0 `STR W`/`STRB` `#0x228` and 0 `memcpy` size `>=0x80`.
pub const BOSMINER_AM3_HC_INIT_STR228_HITS: usize = 0;
pub const BOSMINER_AM3_HC_INIT_MEMCPY_GE80_HITS: usize = 0;
pub const BOSMINER_AM3_HC_INIT_FNS: [(u64, u64); 5] = [
    (0x008C_FAD0, 0x008D_0188),
    (0x008D_0944, 0x008D_0FFC),
    (0x008D_11FC, 0x008D_18B4),
    (0x008D_1AB4, 0x008D_216C),
    (0x008D_236C, 0x008D_2A24),
];
/// First-LOAD `MOVZ #1` + `STR W #0x228` with `Xn != SP` = 0.
pub const BOSMINER_TAG1_STRW_NONSP_HITS: usize = 0;
/// `ADD #0x200` then `STRB #0x28` within 32 insns (split `+0x228`) = 0.
pub const BOSMINER_SPLIT_200_STRB28_HITS: usize = 0;
/// `ADD #0x228` then `STRB [Xd,#0]` within 8 insns = 0.
pub const BOSMINER_ADD228_STRB0_HITS: usize = 0;
/// Five AM3 inits: `ADD X2,X2,#0x228`; `MOVZ W1,#0x22`; `BL` panic (10 sites).
pub const BOSMINER_AM3_HC_INIT_ADD228_PANIC_HITS: usize = 10;
pub const BOSMINER_AM3_HC_INIT_ADD228_VA: u64 = 0x008D_0160;
pub const BOSMINER_AM3_HC_INIT_ADD228_INSN: u32 = 0x9108_A042;
pub const BOSMINER_AM3_HC_INIT_PANIC_LINE: u16 = 0x22;
pub const BOSMINER_AM3_HC_INIT_PANIC_LINE_INSN: u32 = 0x5280_0441;
pub const BOSMINER_AM3_HC_INIT_PANIC_BL_INSN: u32 = 0x97EE_0D52;
/// All 10 AM3 `ADD X2,#0x228` are `ADRP X2` + page off forming loc `0x19c6228`.
pub const BOSMINER_AM3_ADD228_ADRP_HITS: usize = 10;
pub const BOSMINER_AM3_ADD228_ADRP_VA: u64 = 0x008D_015C;
pub const BOSMINER_AM3_ADD228_ADRP_INSN: u32 = 0xD000_87A2;
pub const BOSMINER_AM3_ADD228_LOC_VA: u64 = 0x019C_6228;
/// AM3 "inits" are Future poll: `LDRB [X0,#0x80]` tag (5 bodies).
pub const BOSMINER_AM3_INIT_TAG80_HITS: usize = 5;
pub const BOSMINER_AM3_INIT_TAG80_VA: u64 = 0x008C_FAEC;
pub const BOSMINER_AM3_INIT_TAG80_INSN: u32 = 0x3942_0008;
/// `MOVZ #0x228` then `STRB [Xn, Xm]` register-offset = 0.
pub const BOSMINER_MOVZ228_STRB_REGOFF_HITS: usize = 0;
/// `ADD #0x228` `BL` callees with early `STRB [X0,#0]` = 0 (no visit store-through).
pub const BOSMINER_ADD228_BL_STRB_X0_0_HITS: usize = 0;
/// Covering `memcpy` dest=`Xn+#0x228` in first LOAD = 5 (2 clone, 2 stack, 1 non-HC).
pub const BOSMINER_DEST228_MEMCPY_HITS: usize = 5;
pub const BOSMINER_DEST228_MEMCPY_FN_VA: u64 = 0x0094_FC6C;
pub const BOSMINER_DEST228_MEMCPY_ADD_VA: u64 = 0x0095_14C8;
pub const BOSMINER_DEST228_MEMCPY_ADD_INSN: u32 = 0x9108_A2A0;
pub const BOSMINER_DEST228_MEMCPY_SIZE: usize = 0x200;
pub const BOSMINER_DEST228_MEMCPY_SIZE_INSN: u32 = 0x5280_4002;
pub const BOSMINER_DEST228_MEMCPY_BL_INSN: u32 = 0x9409_DEC3;
pub const BOSMINER_DEST228_OFF_19C_HITS: usize = 0;
pub const BOSMINER_DEST228_OFF_11F0_HITS: usize = 0;
/// Field-to-field clone at `+0x228` is size `0x1f0` (`0xad9f50`).
pub const BOSMINER_CLONE228_MEMCPY_VA: u64 = 0x00AD_9F50;
pub const BOSMINER_CLONE228_MEMCPY_SIZE: usize = 0x1F0;
pub const BOSMINER_CLONE228_MEMCPY_SIZE_INSN: u32 = 0x5280_3E02;
/// `STP XZR,XZR [Xn,#0x210/#0x220/#0x228]` with `Xn!=SP` = 0. `STUR XZR #0x228` = 0.
pub const BOSMINER_STP_XZR_220_228_NONSP_HITS: usize = 0;
pub const BOSMINER_STUR_XZR_228_HITS: usize = 0;
/// `STR XZR [Xn,#0x228]` non-SP = 7; none have HashChain `+0x19c`/`+0x11F0` nearby.
pub const BOSMINER_STR_XZR_228_NONSP_HITS: usize = 7;
pub const BOSMINER_STR_XZR_228_HC_HITS: usize = 0;
pub const BOSMINER_STR_XZR_228_VA: u64 = 0x0064_C9BC;
pub const BOSMINER_STR_XZR_228_INSN: u32 = 0xF901_167F;
/// Sole `STR WZR [Xn,#0x228]` zeros a `0x2a0`-class tail, not HashChain.
pub const BOSMINER_STR_WZR_228_HITS: usize = 1;
pub const BOSMINER_STR_WZR_228_VA: u64 = 0x0098_7604;
pub const BOSMINER_STR_WZR_228_INSN: u32 = 0xB902_2ADF;
/// `STRB WZR #0x228` non-SP = 16; 0 HashChain-neighbor windows.
pub const BOSMINER_STRB_WZR_228_NONSP_HITS: usize = 16;
pub const BOSMINER_STRB_WZR_228_HC_HITS: usize = 0;
/// `FUN_01200524` is a slot setter (drop old, store new), not memset. 358 `BL`.
pub const BOSMINER_SLOT_SET_FN_VA: u64 = 0x0120_0524;
pub const BOSMINER_SLOT_SET_BL_HITS: usize = 358;
pub const BOSMINER_SLOT_SET_ENTRY_INSN: u32 = 0xA9BE_57FE;
/// `FUN_00836934` ticket-mask-future `STRB WZR [X10,#0x228]`.
pub const BOSMINER_TICKET_MASK_STRB_228_VA: u64 = 0x0083_6C20;
pub const BOSMINER_TICKET_MASK_STRB_228_INSN: u32 = 0x3908_A15F;
pub const BOSMINER_TICKET_MASK_STRB_FN_VA: u64 = 0x0083_6934;
/// `BL FUN_005f4a78` then `STR X/W/B #0x228` (`Xn!=SP`) before `RET` = 3; 0 HashChain.
pub const BOSMINER_POST_ALLOC_STR228_NONSP_HITS: usize = 3;
pub const BOSMINER_POST_ALLOC_STR228_HC_HITS: usize = 0;
pub const BOSMINER_POST_ALLOC_STR228_ALLOC_VA: u64 = 0x0058_19D0;
pub const BOSMINER_POST_ALLOC_STR228_VA: u64 = 0x0058_1A00;
pub const BOSMINER_POST_ALLOC_STR228_INSN: u32 = 0xF901_1728;
/// BTree node: `STR [Xn,#0x220]` then `STR [same,#0x228]` = 17 (child/next).
pub const BOSMINER_BTREE_STR220_228_HITS: usize = 17;
pub const BOSMINER_BTREE_STR220_VA: u64 = 0x0081_4A44;
pub const BOSMINER_BTREE_STR220_INSN: u32 = 0xF901_1015;
pub const BOSMINER_BTREE_STR228_VA: u64 = 0x0081_4A78;
pub const BOSMINER_BTREE_STR228_INSN: u32 = 0xF901_1419;
pub const BOSMINER_BTREE_NODE_LEN_OFF: usize = 0x21A;
pub const BOSMINER_BTREE_ALLOC2_STR228_VA: u64 = 0x0127_CA2C;
pub const BOSMINER_BTREE_ALLOC2_STR228_INSN: u32 = 0xF901_1418;
/// dest=`MOV X0,Xn` (`Xn!=SP`) `memcpy` size `>=0x229` with `+0x19c`/`+0x11F0` window = 0.
pub const BOSMINER_MOV_DEST_MEMCPY_HC_HITS: usize = 0;
pub const BOSMINER_MOV_DEST_228WIN_HITS: usize = 7;
/// dest=`ADD #0` (object base) `memcpy` size `>=0x229` = 0.
pub const BOSMINER_BASE_ADD0_MEMCPY_GE229_HITS: usize = 0;
/// Future-poll `FUN_00742f30` dest=`MOV` `memcpy` `0x860`; `ADD #0x228` is after `RET`.
pub const BOSMINER_FUTURE_POLL_MEMCPY_860_VA: u64 = 0x0074_2FB0;
pub const BOSMINER_FUTURE_POLL_MEMCPY_860_INSN: u32 = 0x5281_0C02;
/// `FUN_00c6c594` dest=`MOV` `memcpy` `0x2b0` then `STR +0x2b0`; 0 HashChain neighbors.
pub const BOSMINER_C6C594_MEMCPY_2B0_VA: u64 = 0x00C6_C9AC;
pub const BOSMINER_C6C594_MEMCPY_2B0_INSN: u32 = 0x5280_5602;
/// `FUN_0083b3a0` prep has exactly 3 `BL` callers (instantiate, AM2 sibling, factory).
pub const BOSMINER_PREP_BL_HITS: usize = 3;
pub const BOSMINER_PREP_BL_VAS: [u64; 3] = [0x0082_55DC, 0x0082_5934, 0x0083_52E0];
pub const BOSMINER_PREP_BL_A_INSN: u32 = 0x9400_5771;
pub const BOSMINER_PREP_BL_B_INSN: u32 = 0x9400_569B;
pub const BOSMINER_PREP_BL_C_INSN: u32 = 0x9400_1830;
/// `FUN_008258c0` is the AM2 instantiate sibling (`0x2a0` / hashchain string).
pub const BOSMINER_PREP_SIB_FN_VA: u64 = 0x0082_58C0;
pub const BOSMINER_PREP_SIB_BL_VA: u64 = 0x0082_5934;
/// Five AM3 wrappers: Future poll `LDR W [X0,#0x10]` then init(`self+0x18`).
pub const BOSMINER_AM3_WRAP_HITS: usize = 5;
pub const BOSMINER_AM3_WRAP_LDR10_INSN: u32 = 0xB940_1008;
pub const BOSMINER_AM3_WRAP_ADD18_INSN: u32 = 0x9100_6260;
pub const BOSMINER_AM3_WRAP_FNS: [(u64, u64); 5] = [
    (0x008C_CE14, 0x008C_FAD0),
    (0x008C_C92C, 0x008D_0944),
    (0x008C_CEC4, 0x008D_11FC),
    (0x008C_CF74, 0x008D_1AB4),
    (0x008C_CC3C, 0x008D_236C),
];
pub const BOSMINER_AM3_WRAP0_BL_VA: u64 = 0x008C_CE44;
pub const BOSMINER_AM3_WRAP0_BL_INSN: u32 = 0x9400_0B23;
/// Unaligned `STUR` `#0x228` in first LOAD = 0.
pub const BOSMINER_STUR_228_ANY_HITS: usize = 0;
/// Each of 5 AM3 wrappers has 2 `BL` callers (10). All `ADD X0,X19,#0x20` then wrap.
pub const BOSMINER_AM3_WRAP_BL_HITS: usize = 10;
pub const BOSMINER_AM3_WRAP_CALLER_ADD20_INSN: u32 = 0x9100_8260;
pub const BOSMINER_AM3_WRAP_CALLER_BL_VA: u64 = 0x008E_749C;
pub const BOSMINER_AM3_WRAP_CALLER_BL_INSN: u32 = 0x97FF_965E;
pub const BOSMINER_AM3_WRAP_CALLER_FN_VA: u64 = 0x008E_7454;
pub const BOSMINER_AM3_WRAP_CALLER_STR228_HITS: usize = 0;
/// `FUN_008cb778` boxes the outer Future: alloc/memcpy `0x180`, vtable `0x19c6b50`.
pub const BOSMINER_OUTER_BOX_FN_VA: u64 = 0x008C_B778;
pub const BOSMINER_OUTER_BOX_SIZE: usize = 0x180;
pub const BOSMINER_OUTER_BOX_SIZE_INSN: u32 = 0x5280_3000;
pub const BOSMINER_OUTER_BOX_ALLOC_BL_VA: u64 = 0x008C_B820;
pub const BOSMINER_OUTER_BOX_ALLOC_BL_INSN: u32 = 0x97F4_A496;
pub const BOSMINER_OUTER_BOX_MEMCPY_180_INSN: u32 = 0x5280_3002;
pub const BOSMINER_OUTER_BOX_STR228_HITS: usize = 0;
pub const BOSMINER_OUTER_BOX_180_HITS: usize = 4;
pub const BOSMINER_OUTER_BOX_FNS: [u64; 4] = [0x008C_B778, 0x008C_B8B4, 0x008C_B9F0, 0x008C_BB2C];
/// Vtable `PTR_thunk_FUN_008e7454` at `0x19c6b50` = thunk `0x84ca74`.
pub const BOSMINER_OUTER_VT_VA: u64 = 0x019C_6B50;
pub const BOSMINER_OUTER_VT_THUNK: u64 = 0x0084_CA74;
pub const BOSMINER_OUTER_VT_ADD_VA: u64 = 0x008C_B7D4;
pub const BOSMINER_OUTER_VT_ADD_INSN: u32 = 0x912D_4108;
pub const BOSMINER_OUTER_VT_ADRP_HITS: usize = 5;
pub const BOSMINER_OUTER_BOX_CALLER_VA: u64 = 0x008C_E9DC;
/// `FUN_008ce99c` Arc-bumps, boxes with tag `0xcc`, schedules at Arc+0x160.
pub const BOSMINER_BOX_SCHED_FN_VA: u64 = 0x008C_E99C;
pub const BOSMINER_BOX_SCHED_ENTRY_INSN: u32 = 0xD101_03FF;
pub const BOSMINER_BOX_SCHED_TAG: u16 = 0xCC;
pub const BOSMINER_BOX_SCHED_TAG_INSN: u32 = 0x5280_1982;
pub const BOSMINER_BOX_SCHED_BL_INSN: u32 = 0x97FF_F367;
pub const BOSMINER_BOX_SCHED_ADD160_INSN: u32 = 0x9105_82C0;
pub const BOSMINER_BOX_SCHED_SPAWN_BL_INSN: u32 = 0x97FF_AAC5;
pub const BOSMINER_BOX_SCHED_ADD200_INSN: u32 = 0x9108_02C0;
pub const BOSMINER_BOX_SCHED_STR228_HITS: usize = 0;
pub const BOSMINER_BOX_SCHED_PARENT_VA: u64 = 0x0085_19B8;
/// `FUN_008b9504` run-queue insert writes `box+0x18` (not wrap+0x18).
pub const BOSMINER_RUNQ_FN_VA: u64 = 0x008B_9504;
pub const BOSMINER_RUNQ_STR18_VA: u64 = 0x008B_952C;
pub const BOSMINER_RUNQ_STR18_INSN: u32 = 0xF900_0C29;
pub const BOSMINER_RUNQ_STR228_HITS: usize = 0;
/// Four `BL` to the `0x180` boxers.
pub const BOSMINER_BOXER_BL_HITS: usize = 4;
/// AM3 init dest = wrap+0x18 = box+0x20+0x18 = box+0x38; remain `0x148`.
pub const BOSMINER_AM3_INIT_DEST_BOX_OFF: usize = 0x38;
pub const BOSMINER_AM3_INIT_DEST_REMAIN: usize = 0x148;
/// `FUN_008518d0` builds a `0x108` stack image at `SP+#0x1a0` and dispatches on bit0.
pub const BOSMINER_PARENT_FN_VA: u64 = 0x0085_18D0;
pub const BOSMINER_PARENT_ENTRY_INSN: u32 = 0xA9BE_7BFD;
pub const BOSMINER_PARENT_LDRW0_INSN: u32 = 0xB940_0009;
pub const BOSMINER_PARENT_P2_LDR50_INSN: u32 = 0xF940_2829;
pub const BOSMINER_PARENT_IMAGE_SP_OFF: usize = 0x1A0;
pub const BOSMINER_PARENT_IMAGE_ADD_INSN: u32 = 0x9106_83E1;
pub const BOSMINER_PARENT_IMAGE_SIZE: usize = 0x108;
pub const BOSMINER_PARENT_CE99C_BL_INSN: u32 = 0x9401_F3F9;
pub const BOSMINER_PARENT_ALT_BL_INSN: u32 = 0x9401_1B48;
pub const BOSMINER_PARENT_ALT_FN_VA: u64 = 0x0089_86C8;
pub const BOSMINER_PARENT_STR228_HITS: usize = 0;
pub const BOSMINER_PARENT_BL_HITS: usize = 1;
pub const BOSMINER_PARENT_CALLER_VA: u64 = 0x0087_965C;
/// Bit0 alternate boxes via `FUN_008cc148` (`0x180`, vtable `FUN_008e7638`).
pub const BOSMINER_ALT_BOX_FN_VA: u64 = 0x008C_C148;
pub const BOSMINER_ALT_BOX_VT_VA: u64 = 0x019C_6D80;
/// `FUN_008790dc` is AM2 S17 `hashchainmessageevent` poll; stages 0x108 at `SP+#0x2cc0`.
pub const BOSMINER_MSG_EVT_FN_VA: u64 = 0x0087_90DC;
pub const BOSMINER_MSG_EVT_ENTRY_INSN: u32 = 0xA9BA_7BFD;
pub const BOSMINER_MSG_EVT_P1_ADD_HI_INSN: u32 = 0x9140_13E0;
pub const BOSMINER_MSG_EVT_P1_ADD_LO_INSN: u32 = 0x910E_0000;
pub const BOSMINER_MSG_EVT_P2_ADD_HI_INSN: u32 = 0x9140_0BE1;
pub const BOSMINER_MSG_EVT_P2_ADD_LO_INSN: u32 = 0x9133_0021;
pub const BOSMINER_MSG_EVT_BL_INSN: u32 = 0x97FF_609D;
pub const BOSMINER_MSG_EVT_SRC_OFF: usize = 0x2C70;
pub const BOSMINER_MSG_EVT_SRC_LDR_INSN: u32 = 0xF956_3A6A;
pub const BOSMINER_MSG_EVT_SRC_CB8_INSN: u32 = 0xF956_5E69;
pub const BOSMINER_MSG_EVT_STAGE_SP_OFF: usize = 0x2CC0;
pub const BOSMINER_MSG_EVT_P1_SP_OFF: usize = 0x4380;
pub const BOSMINER_MSG_EVT_STR228_HITS: usize = 0;
pub const BOSMINER_MSG_EVT_BL_HITS: usize = 0;
pub const BOSMINER_MSG_EVT_VT_VA: u64 = 0x019C_0F90;
pub const BOSMINER_MSG_EVT_WORKER_BL_INSN: u32 = 0x9401_E449;
/// Instantiate prep X1 = `*param_1[2]` (`LDR X1,[X26,#0]`); HashChain Arc at `+0x2f0`.
pub const BOSMINER_INST_X1_LDR_VA: u64 = 0x0082_55C8;
pub const BOSMINER_INST_X1_LDR_INSN: u32 = 0xF940_0341;
pub const BOSMINER_INST_ARC_OFF: usize = 0x2F0;
pub const BOSMINER_INST_ARC_LDR_INSN: u32 = 0xF941_7909;
pub const BOSMINER_INST_STR228_HITS: usize = 0;
/// `FUN_00842bb8` wraps instantiate; does not alloc HashChain.
pub const BOSMINER_WRAP42_FN_VA: u64 = 0x0084_2BB8;
pub const BOSMINER_WRAP42_BL_INSN: u32 = 0x97FF_8A43;
pub const BOSMINER_WRAP42_STR228_HITS: usize = 0;
/// `FUN_0085c78c` loads HashChain* from `self+0x260` then calls wrap42.
pub const BOSMINER_SRC5C_FN_VA: u64 = 0x0085_C78C;
pub const BOSMINER_SRC5C_LDR260_VA: u64 = 0x0085_C828;
pub const BOSMINER_SRC5C_LDR260_INSN: u32 = 0xF941_32A9;
pub const BOSMINER_SRC5C_BL_VA: u64 = 0x0085_CAC0;
pub const BOSMINER_SRC5C_BL_INSN: u32 = 0x97FF_983E;
pub const BOSMINER_SRC5C_STR228_HITS: usize = 0;
/// Factory prep X1 = `MOV X1,X19` (`param_4`).
pub const BOSMINER_FAC_X1_MOV_INSN: u32 = 0xAA13_03E1;
pub const BOSMINER_FAC_STR228_HITS: usize = 0;
/// `FUN_00681c88` `STR X23,[X19,#0x228]` is a Vec slot (cap 8 at +0x218/+0x220).
pub const BOSMINER_VEC228_VA: u64 = 0x0068_2090;
pub const BOSMINER_VEC228_INSN: u32 = 0xF901_1677;
pub const BOSMINER_VEC218_INSN: u32 = 0xF901_0E60;
/// `FUN_0085c78c` `self` is a **0x300-byte** type (not the HashChain).
pub const BOSMINER_SRC5C_VT_VA: u64 = 0x019A_CE88;
pub const BOSMINER_SRC5C_VT_HDR_VA: u64 = 0x019A_CE70;
pub const BOSMINER_SRC5C_DROP_FN_VA: u64 = 0x006F_4F2C;
pub const BOSMINER_SRC5C_TYPE_SIZE: usize = 0x300;
pub const BOSMINER_SRC5C_TYPE_ALIGN: usize = 0x10;
/// Sole `ADRP+ADD` former of vtable header `0x19ace70`.
pub const BOSMINER_SRC5C_VT_ADRP_VA: u64 = 0x0070_596C;
pub const BOSMINER_SRC5C_VT_ADRP_INSN: u32 = 0xF000_9521;
pub const BOSMINER_SRC5C_VT_ADD_INSN: u32 = 0x9139_C021;
/// `FUN_00705800` boxes the 0x300 image (`memcpy` covers `+0x260`).
pub const BOSMINER_BOX300_FN_VA: u64 = 0x0070_5800;
pub const BOSMINER_BOX300_ENTRY_INSN: u32 = 0xA9BA_7BFD;
pub const BOSMINER_BOX300_SRC_LDR_VA: u64 = 0x0070_5890;
pub const BOSMINER_BOX300_SRC_LDR_INSN: u32 = 0xF941_3298;
pub const BOSMINER_BOX300_PARENT_OFF: usize = 0x3B0;
pub const BOSMINER_BOX300_PARENT_LDR_INSN: u32 = 0xF941_D814;
pub const BOSMINER_BOX300_MOVZ_VA: u64 = 0x0070_58DC;
pub const BOSMINER_BOX300_MOVZ_INSN: u32 = 0x5280_6000;
pub const BOSMINER_BOX300_MEMCPY_SIZE_INSN: u32 = 0x5280_6002;
pub const BOSMINER_BOX300_BL_HITS: usize = 0;
/// `FUN_008679ac` clones the 0x300 container (1 `BL` from `FUN_00705464`).
pub const BOSMINER_CLONE300_FN_VA: u64 = 0x0086_79AC;
pub const BOSMINER_CLONE300_BL_VA: u64 = 0x0070_55C0;
pub const BOSMINER_CLONE300_BL_INSN: u32 = 0x9405_88FB;
pub const BOSMINER_CLONE300_BL_HITS: usize = 1;
/// `STR X/W #0x260` census (`Xn!=SP`) in the first LOAD.
pub const BOSMINER_STR260_HITS: usize = 52;
pub const BOSMINER_STR260_XZR_HITS: usize = 8;
pub const BOSMINER_STR260_CLONE_HITS: usize = 9;
pub const BOSMINER_STR260_MOVZ300_NEAR_HITS: usize = 0;
/// `FUN_00836934` ticket-mask future stores fn-ptr `FUN_0089b720` at `+0x260`.
pub const BOSMINER_TICKET_MASK260_VA: u64 = 0x0083_6C34;
pub const BOSMINER_TICKET_MASK260_INSN: u32 = 0xF901_3148;
pub const BOSMINER_TICKET_MASK260_FN_VA: u64 = 0x0089_B720;
pub const BOSMINER_TICKET_MASK260_ADRP_INSN: u32 = 0xB000_0328;
pub const BOSMINER_TICKET_MASK260_ADD_INSN: u32 = 0x911C_8108;
/// `FUN_00705464` builds the 0x3c0 parent: `+0x3b0` = source*, `+0x2e0` = HashChain*.
pub const BOSMINER_PARENT3C0_FN_VA: u64 = 0x0070_5464;
pub const BOSMINER_PARENT3C0_ENTRY_INSN: u32 = 0xA9BA_7BFD;
pub const BOSMINER_PARENT3C0_MOV_SRC_INSN: u32 = 0xAA00_03F7;
pub const BOSMINER_PARENT3C0_MOV_DST_INSN: u32 = 0xAA08_03F6;
pub const BOSMINER_PARENT3C0_LDR260_INSN: u32 = 0xF941_32FB;
pub const BOSMINER_PARENT3C0_STR2A0_INSN: u32 = 0xF901_52D7;
pub const BOSMINER_PARENT3C0_STR2E0_INSN: u32 = 0xF901_72DB;
pub const BOSMINER_PARENT3C0_STR3B0_VA: u64 = 0x0070_567C;
pub const BOSMINER_PARENT3C0_STR3B0_INSN: u32 = 0xF901_DAD7;
pub const BOSMINER_PARENT3C0_STR3B8_INSN: u32 = 0xF901_DED4;
pub const BOSMINER_PARENT3C0_STR228_HITS: usize = 0;
pub const BOSMINER_PARENT3C0_BL_HITS: usize = 3;
pub const BOSMINER_PARENT3C0_TYPE_SIZE: usize = 0x3C0;
pub const BOSMINER_PARENT3C0_VT_VA: u64 = 0x019A_C9D8;
pub const BOSMINER_STR3B0_HITS: usize = 20;
/// Three `FUN_00705464` callers load X0 from ELF-initialized statics.
pub const BOSMINER_CALL3C0_A_FN_VA: u64 = 0x006F_23A8;
pub const BOSMINER_CALL3C0_B_FN_VA: u64 = 0x006F_270C;
pub const BOSMINER_CALL3C0_C_FN_VA: u64 = 0x006F_2C14;
pub const BOSMINER_CALL3C0_MOV_DST_INSN: u32 = 0xAA08_03F3;
pub const BOSMINER_CALL3C0_A_ADRP_INSN: u32 = 0x9000_9EE0;
pub const BOSMINER_CALL3C0_A_LDR_INSN: u32 = 0xF947_6800;
pub const BOSMINER_CALL3C0_A_BL_INSN: u32 = 0x9400_4BD7;
pub const BOSMINER_CALL3C0_B_ADRP_INSN: u32 = 0xB000_9EE0;
pub const BOSMINER_CALL3C0_B_LDR_INSN: u32 = 0xF946_9C00;
pub const BOSMINER_CALL3C0_B_BL_INSN: u32 = 0x9400_4AFE;
pub const BOSMINER_CALL3C0_C_ADRP_INSN: u32 = 0xF000_9EC0;
pub const BOSMINER_CALL3C0_C_LDR_INSN: u32 = 0xF945_0400;
pub const BOSMINER_CALL3C0_C_BL_INSN: u32 = 0x9400_49BC;
pub const BOSMINER_CALL3C0_MOV_X8_INSN: u32 = 0xAA13_03E8;
pub const BOSMINER_CALL3C0_MOVZ6_INSN: u32 = 0x5280_0026;
pub const BOSMINER_CALL3C0_SLOT_A_VA: u64 = 0x01AC_EED0;
pub const BOSMINER_CALL3C0_SLOT_B_VA: u64 = 0x01AC_FD38;
pub const BOSMINER_CALL3C0_SLOT_C_VA: u64 = 0x01AC_DA08;
pub const BOSMINER_CALL3C0_OBJ_A_VA: u64 = 0x01AE_01C0;
pub const BOSMINER_CALL3C0_OBJ_B_VA: u64 = 0x01AD_FBC0;
pub const BOSMINER_CALL3C0_OBJ_C_VA: u64 = 0x01AD_FEC0;
pub const BOSMINER_CALL3C0_VPTR_A: u64 = 0x0086_33A0;
pub const BOSMINER_CALL3C0_VPTR_B: u64 = 0x0086_2C84;
pub const BOSMINER_CALL3C0_VPTR_C: u64 = 0x0086_26A8;
pub const BOSMINER_CALL3C0_STR228_HITS: usize = 0;
pub const BOSMINER_CALL3C0_STR260_HITS: usize = 0;
pub const BOSMINER_CALL3C0_BL_HITS: usize = 0;
pub const BOSMINER_CALL3C0_VPTR_STR260_HITS: usize = 0;
pub const BOSMINER_CALL3C0_VPTR_BL_HITS: usize = 0;
/// `FUN_00867740` inits the static object; first `+0x260` write is `STP.Q [X19,#0x250]`.
pub const BOSMINER_INIT677_FN_VA: u64 = 0x0086_7740;
pub const BOSMINER_INIT677_ENTRY_INSN: u32 = 0xD102_43FF;
pub const BOSMINER_INIT677_MOV_DST_INSN: u32 = 0xAA08_03F3;
pub const BOSMINER_INIT677_STRH228_VA: u64 = 0x0086_78DC;
pub const BOSMINER_INIT677_STRH228_INSN: u32 = 0x7904_5268;
pub const BOSMINER_INIT677_STR2E0_INSN: u32 = 0xF901_726B;
pub const BOSMINER_INIT677_SIMD260_VA: u64 = 0x0086_7914;
pub const BOSMINER_INIT677_SIMD260_INSN: u32 = 0xAD12_8660;
pub const BOSMINER_INIT677_LDP_SRC_INSN: u32 = 0xAD40_0520;
pub const BOSMINER_INIT677_STR260_HITS: usize = 0;
pub const BOSMINER_INIT677_BL_HITS: usize = 3;
pub const BOSMINER_INIT677_BL_A_INSN: u32 = 0x9400_0FF0;
pub const BOSMINER_INIT677_BL_B_INSN: u32 = 0x9400_11BD;
pub const BOSMINER_INIT677_BL_C_INSN: u32 = 0x9400_1334;
/// : X9 is `&local_120` (caller `SP+#0x170`); `+0x260` = `*(0x1adfb28+0x10)`.
pub const BOSMINER_X9_LDR_SP_B8_VA: u64 = 0x0086_78C0;
pub const BOSMINER_X9_LDR_SP_B8_INSN: u32 = 0xF940_5FE9;
pub const BOSMINER_X9_CALLER_ADD170_INSN: u32 = 0x9105_C3E8;
pub const BOSMINER_X9_CALLER_ADD160_INSN: u32 = 0x9105_83E9;
pub const BOSMINER_X9_CALLER_STP20_INSN: u32 = 0xA902_23E9;
pub const BOSMINER_X9_SLOT_VA: u64 = 0x01AC_DF20;
pub const BOSMINER_X9_SLOT_LDR_INSN: u32 = 0xF947_92B5;
pub const BOSMINER_X9_SLOT_ADRP_INSN: u32 = 0xD000_9355;
pub const BOSMINER_X9_OBJ_VA: u64 = 0x01AD_FB28;
pub const BOSMINER_X9_OBJ_VPTR: u64 = 0x0086_31F0;
pub const BOSMINER_X9_OBJ_LDR10_INSN: u32 = 0xF940_0AA9;
pub const BOSMINER_X9_LOCAL110_STR_INSN: u32 = 0xF900_C3E9;
pub const BOSMINER_X9_SLOT_LDR_HITS: usize = 3;
/// : no later overwrite of `0x1ae01c0+0x260` after the SIMD zero copy.
pub const BOSMINER_OW260_ABS_STR_HITS: usize = 0;
pub const BOSMINER_OW260_SLOT_STR_HITS: usize = 0;
pub const BOSMINER_TRUE_SLOT_LDR_HITS: usize = 6;
pub const BOSMINER_TRUE_SLOT_A_ONCE_VA: u64 = 0x006F_2434;
pub const BOSMINER_TRUE_SLOT_A_ONCE_INSN: u32 = 0xF947_6AB5;
pub const BOSMINER_INIT633_POST_BL_ADD_INSN: u32 = 0x9108_83FF;
pub const BOSMINER_INIT633_RET_VA: u64 = 0x0086_37A4;
pub const BOSMINER_INIT633_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_FAKE_SLOT_A25760_VA: u64 = 0x01AC_DED0;
pub const BOSMINER_FAKE_SLOT_A25760_ADRP_INSN: u32 = 0x9000_854A;
/// : `FUN_008631f0` is an X8-sret PSU-config Default, not a HashChain ctor.
pub const BOSMINER_INIT631_FN_VA: u64 = 0x0086_31F0;
pub const BOSMINER_INIT631_RET_VA: u64 = 0x0086_325C;
pub const BOSMINER_INIT631_ENTRY_INSN: u32 = 0xB000_5429;
pub const BOSMINER_INIT631_MOVZ2_INSN: u32 = 0x5280_004A;
pub const BOSMINER_INIT631_MOVZ1_INSN: u32 = 0x5280_002A;
pub const BOSMINER_INIT631_STR88_VA: u64 = 0x0086_3228;
pub const BOSMINER_INIT631_STR88_INSN: u32 = 0xB900_891F;
pub const BOSMINER_INIT631_STR10_VA: u64 = 0x0086_3244;
pub const BOSMINER_INIT631_STR10_INSN: u32 = 0xF900_090A;
pub const BOSMINER_INIT631_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_INIT631_BL_HITS: usize = 0;
pub const BOSMINER_INIT631_MAX_STR_OFF: usize = 0x88;
pub const BOSMINER_SIBLING_SIZE: usize = 0x98;
pub const BOSMINER_SIBLING_NEXT_VA: u64 = 0x01AD_FBC0;
pub const BOSMINER_SIBLING_228_VA: u64 = 0x01AD_FD50;
pub const BOSMINER_SIBLING_228_XREF_HITS: usize = 0;
pub const BOSMINER_INIT631_BL_CALLERS: usize = 0;
pub const BOSMINER_PSU_F64_0_VA: u64 = 0x012E_80F0;
pub const BOSMINER_PSU_F64_0_BITS: u64 = 0x3FB9_9999_9999_999A;
pub const BOSMINER_SIBLING_SIMD_LDR_VA: u64 = 0x0086_36C4;
pub const BOSMINER_SIBLING_SIMD_LDR_INSN: u32 = 0x3DC0_02A0;
/// : `FUN_00bf2478` is MidstateCount→log; UART parse uses that log as version width.
pub const BOSMINER_VERWIDTH_FN_VA: u64 = 0x00BF_2478;
pub const BOSMINER_VERWIDTH_LDRB20_INSN: u32 = 0x3940_8008;
pub const BOSMINER_VERWIDTH_LDR18_INSN: u32 = 0xF940_0C00;
pub const BOSMINER_VERWIDTH_B_LOG_INSN: u32 = 0x1419_B603;
pub const BOSMINER_VERWIDTH_LDR10_INSN: u32 = 0xF940_0800;
pub const BOSMINER_VERWIDTH_RET_INSN: u32 = 0xD65F_03C0;
/// Relative to `engine+0x60` (the `FUN_00bf2478` self).
pub const BOSMINER_VERWIDTH_TAG_OFF: usize = 0x20;
pub const BOSMINER_ENGINE_MIDSTATE_COUNT_OFF: usize = 0x78;
/// : parse saves `X21=X1` then `ADD X0,X21,#0x60` into verwidth.
pub const BOSMINER_ENGINE_VERWIDTH_SELF_OFF: usize = 0x60;
pub const BOSMINER_WORK_RESP_MOV_X21_ENGINE_VA: u64 = 0x0091_C0D4;
pub const BOSMINER_WORK_RESP_MOV_X21_ENGINE_INSN: u32 = 0xAA01_03F5;
pub const BOSMINER_WORK_RESP_ADD60_VA: u64 = 0x0091_C0F8;
pub const BOSMINER_WORK_RESP_ADD60_INSN: u32 = 0x9101_82A0;
/// `CMP #1` is the **second** insn of `FUN_00bf2478` (`entry+4`).
/// Parse `BL 0x940B58DD` targets the **entry** `0xbf2478` (LDRB), not this
/// CMP.  mid-entry claim is **FALSE** (A64 BL is from the insn VA).
pub const BOSMINER_VERWIDTH_CMP_VA: u64 = 0x00BF_247C;
pub const BOSMINER_VERWIDTH_CMP_INSN: u32 = 0x7100_051F;
pub const BOSMINER_VERWIDTH_PARSE_BL_TARGET_VA: u64 = 0x00BF_2478;
/// : `FUN_00bf6c2c` consumes Ok WorkResponse; no BIP320 `<<13` re-expand.
pub const BOSMINER_RESP_CONSUMER_FN_VA: u64 = 0x00BF_6C2C;
pub const BOSMINER_RESP_CONSUMER_ENTRY_INSN: u32 = 0xA9BA_7BFD;
pub const BOSMINER_RESP_CONSUMER_MOV_X26_INSN: u32 = 0xAA01_03FA;
pub const BOSMINER_RESP_CONSUMER_LDR68_INSN: u32 = 0xF940_3409;
pub const BOSMINER_RESP_CONSUMER_MOVZ78_VA: u64 = 0x00BF_6FA0;
pub const BOSMINER_RESP_CONSUMER_MOVZ78_INSN: u32 = 0x5280_0F08;
pub const BOSMINER_UART_WRAP_HITS: usize = 5;
pub const BOSMINER_UART_WRAP_SIZE: usize = 0x101C;
pub const BOSMINER_UART_WRAP_A_FN_VA: u64 = 0x008F_262C;
pub const BOSMINER_UART_WRAP_B_FN_VA: u64 = 0x008F_36F8;
pub const BOSMINER_UART_WRAP_C_FN_VA: u64 = 0x008F_47C4;
pub const BOSMINER_UART_WRAP_D_FN_VA: u64 = 0x008F_5890;
pub const BOSMINER_UART_WRAP_E_FN_VA: u64 = 0x008F_695C;
pub const BOSMINER_UART_PARSE_BL_OFF: usize = 0x3C4;
pub const BOSMINER_UART_PARSE_BL_A_INSN: u32 = 0x9400_A5AC;
pub const BOSMINER_UART_OK_LDR_INSN: u32 = 0xB941_A3E8;
pub const BOSMINER_UART_OK_TBZ_INSN: u32 = 0x3600_1088;
pub const BOSMINER_UART_CONS_BL_OFF: usize = 0x5FC;
pub const BOSMINER_UART_CONS_BL_A_INSN: u32 = 0x940C_1001;
pub const BOSMINER_UART_CONS_MOVZ11D0_INSN: u32 = 0x5282_3A08;
pub const BOSMINER_UART_CONS_ADD_X0_INSN: u32 = 0x8B08_0260;
pub const BOSMINER_UART_WRAP_LSL13_HITS: usize = 0;
pub const BOSMINER_BF6C_LSL13_HITS: usize = 0;
pub const BOSMINER_BIP320_MOVP_HITS: usize = 0;
pub const BOSMINER_FPGA_RESP_CONSUMER_BL_VA: u64 = 0x008A_FA8C;
/// : first-LOAD `STRB #0x228` (Xn!=SP) census; engine-absolute log helper.
pub const BOSMINER_STRB228_NONSP_HITS: usize = 24;
pub const BOSMINER_STRB228_WZR_HITS: usize = 16;
pub const BOSMINER_STRB228_WZR_INSN: u32 = 0x3908_A27F;
pub const BOSMINER_STRB228_7C_HITS: usize = 3;
pub const BOSMINER_STRB228_7C_VA: u64 = 0x005F_5A20;
pub const BOSMINER_STRB228_7C_MOVZ_INSN: u32 = 0x5280_0F88;
pub const BOSMINER_STRB228_7C_STRB_INSN: u32 = 0x3908_A268;
pub const BOSMINER_STRB228_C906_VA: u64 = 0x00C9_07D0;
pub const BOSMINER_STRB228_C906_INSN: u32 = 0x3908_A288;
pub const BOSMINER_STRB228_CD67_VA: u64 = 0x00CD_6798;
pub const BOSMINER_LOG_ABS_FN_VA: u64 = 0x00BF_26D0;
pub const BOSMINER_LOG_ABS_LDRB80_INSN: u32 = 0x3942_0008;
pub const BOSMINER_LOG_ABS_LDR78_INSN: u32 = 0xF940_3C00;
pub const BOSMINER_LOG_ABS_B_INSN: u32 = 0x1419_B56D;
pub const BOSMINER_LOG_ABS_LDR70_INSN: u32 = 0xF940_3800;
pub const BOSMINER_WORKER_NEW_STR88_HITS: usize = 0;
pub const BOSMINER_FACTORY_STR88_HITS: usize = 0;
/// : `FUN_00bf26d0` first-LOAD `BL` callers (FPGA + 5 Worker + `1>>log` tail).
pub const BOSMINER_LOG_ABS_BL_CALLERS: usize = 7;
pub const BOSMINER_LOG_REL_BL_CALLERS: usize = 1;
pub const BOSMINER_LOG_ABS_WORKER_BL_HITS: usize = 5;
pub const BOSMINER_LOG_ABS_FPGA_BL_VA: u64 = 0x008A_EA7C;
pub const BOSMINER_LOG_ABS_FPGA_BL_INSN: u32 = 0x940D_0F15;
pub const BOSMINER_LOG_ABS_FPGA_MOV_X0_INSN: u32 = 0xAA01_03E0;
pub const BOSMINER_FPGA_LOG_VALIDATE_FN_VA: u64 = 0x0092_F240;
pub const BOSMINER_FPGA_LOG_VALIDATE_BL_INSN: u32 = 0x9402_01EB;
/// Same order as [`BOSMINER_AM3_WORKER_CTOR_VAS`].
pub const BOSMINER_LOG_ABS_WORKER_BL_VAS: [u64; 5] = [
    0x0090_0A00,
    0x0090_3634,
    0x0090_190C,
    0x0090_2818,
    0x0090_462C,
];
pub const BOSMINER_LOG_ABS_WORKER_A_BL_INSN: u32 = 0x940B_C734;
pub const BOSMINER_LOG_ABS_WORKER_NEW_BL_INSN: u32 = 0x940B_BC27;
pub const BOSMINER_LOG_ABS_WORKER_MOV_X0_INSN: u32 = 0xAA18_03E0;
pub const BOSMINER_LOG_ABS_WORKER_NEW_MOV_X0_INSN: u32 = 0xAA19_03E0;
pub const BOSMINER_LOG_ABS_WORKER_MOV_X3_INSN: u32 = 0xAA00_03E3;
pub const BOSMINER_LOG_ABS_WORKER_NEW_REG_BL_INSN: u32 = 0x940B_D047;
pub const BOSMINER_LOG_ABS_ONESHR_BL_VA: u64 = 0x00B2_639C;
pub const BOSMINER_LOG_ABS_ONESHR_BL_INSN: u32 = 0x9403_30CD;
pub const BOSMINER_ONESHR_FN_VA: u64 = 0x00B2_6398;
pub const BOSMINER_ONESHR_PROLOGUE_INSN: u32 = 0xF81F_0FFE;
pub const BOSMINER_ONESHR_EPILOGUE_INSN: u32 = 0xF841_07FE;
pub const BOSMINER_ONESHR_MOVZ_INSN: u32 = 0x5280_0028;
pub const BOSMINER_ONESHR_LSRV_INSN: u32 = 0x9AC0_2100;
pub const BOSMINER_ONESHR_RET_INSN: u32 = 0xD65F_03C0;
pub const BOSMINER_ONESHR_BL_CALLERS: usize = 9;
pub const BOSMINER_ONESHR_CALLER_A_VA: u64 = 0x0047_C294;
pub const BOSMINER_ONESHR_CALLER_A_INSN: u32 = 0x941A_A841;
/// First-LOAD `BL FUN_00b26398` sites (3 clone triples: store-3280, store-2a70, discard).
pub const BOSMINER_ONESHR_CALLER_VAS: [u64; 9] = [
    0x0047_C294,
    0x0047_C44C,
    0x0047_C528,
    0x004C_CA04,
    0x004C_CBBC,
    0x004C_CC8C,
    0x004F_A250,
    0x004F_A408,
    0x004F_A4D8,
];
/// CBZ/CBNZ/TBZ/TBNZ with Rt=X0 in the 0x80 bytes after each BL: **0**.
pub const BOSMINER_ONESHR_X0_COND_HITS: usize = 0;
/// LDR [SP,#0x3280] in first LOAD: 3, all **after** the X8 overwrite, next insn LDR X1.
pub const BOSMINER_ONESHR_3280_LDR_HITS: usize = 3;
pub const BOSMINER_ONESHR_3280_LDR_VA: u64 = 0x0047_C76C;
pub const BOSMINER_ONESHR_3280_LDR_INSN: u32 = 0xF959_43E0;
pub const BOSMINER_ONESHR_3280_LDR_NEXT_INSN: u32 = 0xF959_63E1;
/// LDR [SP,#0x2a70]: 3 before the oneshr STR (X6) + 3 after RET (X8). None consume 0/1.
pub const BOSMINER_ONESHR_2A70_LDR_HITS: usize = 6;
pub const BOSMINER_ONESHR_2A70_EARLY_LDR_VA: u64 = 0x0047_B8DC;
pub const BOSMINER_ONESHR_2A70_EARLY_LDR_INSN: u32 = 0xF955_3BE6;
/// : 6 callers `STR X0` the 1>>log result; 3 discard it.
pub const BOSMINER_ONESHR_STACK_STORE_HITS: usize = 6;
pub const BOSMINER_ONESHR_DISCARD_HITS: usize = 3;
pub const BOSMINER_ONESHR_STR_3280_INSN: u32 = 0xF919_43E0;
pub const BOSMINER_ONESHR_STR_2A70_INSN: u32 = 0xF915_3BE0;
pub const BOSMINER_ONESHR_STR_3280_OFF: usize = 0x3280;
pub const BOSMINER_ONESHR_STR_2A70_OFF: usize = 0x2A70;
pub const BOSMINER_ONESHR_STR_3280_VA: u64 = 0x0047_C29C;
pub const BOSMINER_ONESHR_STR_2A70_VA: u64 = 0x0047_C454;
pub const BOSMINER_ONESHR_DISCARD_SIMD_INSN: u32 = 0x3DC7_4BE0;
pub const BOSMINER_ONESHR_SIB_FN_VA: u64 = 0x00B2_63F4;
pub const BOSMINER_ONESHR_SIB_ADD400_INSN: u32 = 0x9110_0001;
pub const BOSMINER_ONESHR_SIB_BL_HITS: usize = 3;
pub const BOSMINER_ONESHR_FLAG2_SET_INSN: u32 = 0x3900_0AC8;
pub const BOSMINER_ONESHR_FLAG2_CLR_INSN: u32 = 0x3900_0ADF;
pub const BOSMINER_ONESHR_PRE_ADD_A_INSN: u32 = 0x8B14_0320;
/// : oneshr STR to #0x3280 is overwritten before any LDR in the same fn.
pub const BOSMINER_ONESHR_3280_MID_LDST: usize = 0;
pub const BOSMINER_ONESHR_3280_OVERWRITE_VA: u64 = 0x0047_C68C;
pub const BOSMINER_ONESHR_3280_OVERWRITE_INSN: u32 = 0xF919_43E8;
pub const BOSMINER_ONESHR_2A70_LDR_VA: u64 = 0x0047_DE88;
pub const BOSMINER_ONESHR_2A70_LDR_INSN: u32 = 0xF955_3BE8;
pub const BOSMINER_ONESHR_2A70_LDXR_INSN: u32 = 0xC85F_7D09;
pub const BOSMINER_ONESHR_2A70_RET_BETWEEN: usize = 1;
pub const BOSMINER_LOG_REL_PARSE_BL_VA: u64 = 0x0091_C104;
pub const BOSMINER_LOG_REL_PARSE_BL_INSN: u32 = 0x940B_58DD;
pub const BOSMINER_AM3_HC_INIT_ADD228_VAS: [u64; 10] = [
    0x008D_0160,
    0x008D_017C,
    0x008D_0FD4,
    0x008D_0FF0,
    0x008D_188C,
    0x008D_18A8,
    0x008D_2144,
    0x008D_2160,
    0x008D_29FC,
    0x008D_2A18,
];
/// Five HashChain inits: `ADD X20,X19,#0x90` then `STR X20,[X19,#0x88]`.
pub const BOSMINER_HASHCHAIN_STR88_SELF_PTR_HITS: usize = 5;
pub const BOSMINER_HASHCHAIN_STR88_SELF_PTR_VA: u64 = 0x008C_FC14;
pub const BOSMINER_HASHCHAIN_STR88_SELF_PTR_INSN: u32 = 0xF900_4674;
pub const BOSMINER_HASHCHAIN_ADD90_INSN: u32 = 0x9102_4274;
pub const BOSMINER_HASHCHAIN_STR88_SELF_PTR_VAS: [u64; 5] = [
    0x008C_FC14,
    0x008D_0A88,
    0x008D_1340,
    0x008D_1BF8,
    0x008D_24B0,
];
/// : six engine inits `MOVZ W9,#4`; `STR X9,[X19,#0x80]`; `STR X0,[X19,#0x88]`.
/// `X0` is the Result of a packed-tag helper (`FUN_008d9984` on the bm1366 site).
pub const BOSMINER_ENGINE88_PRODUCER_HITS: usize = 6;
pub const BOSMINER_ENGINE88_MOVZ4_INSN: u32 = 0x5280_0089;
pub const BOSMINER_ENGINE88_STR80_INSN: u32 = 0xF900_4269;
pub const BOSMINER_ENGINE88_STR88_INSN: u32 = 0xF900_4660;
pub const BOSMINER_ENGINE88_WORK_TYPE: u32 = 4;
pub const BOSMINER_ENGINE88_MOVZ_TO_STR80: u64 = 0x1C;
pub const BOSMINER_ENGINE88_STR80_TO_STR88: u64 = 0x20;
pub const BOSMINER_ENGINE88_MOVZ4_VA: [u64; 6] = [
    0x0084_3B80,
    0x0084_5FA0,
    0x0086_89E8,
    0x0086_8ECC,
    0x0088_B5FC,
    0x008D_C920,
];
/// Helper used by the bm1366.rs site. Head `LDRB [X0,#0x70]` (packed tag).
pub const BOSMINER_ENGINE88_PRODUCER_FN_VA: u64 = 0x008D_9984;
pub const BOSMINER_ENGINE88_PRODUCER_LDRB_VA: u64 = 0x008D_9998;
pub const BOSMINER_ENGINE88_PRODUCER_LDRB_INSN: u32 = 0x3941_C008;
/// Serde/deserializer `STR #0x11c0` — not UART bring-up.
pub const BOSMINER_SERDE_STR_11C0_VA: u64 = 0x00B2_8344;
/// Worker object memcpy size (`FUN_008f253c` / `FUN_0086ebac`).
pub const BOSMINER_WORKER_SIZE: usize = 0x1C8;
///  ELF hunt: `ADRP+ADD` then `STR Xt,[Xn,#0x90]` into a `.text` fn = 0.
pub const BOSMINER_JOB_ID_FN_ADRP_STR_HITS: usize = 0;
/// `UBFM` `LSL Wd,Wn,#3` immediately followed by `RET` = 0 in first LOAD.
pub const BOSMINER_LSL3_RET_HITS: usize = 0;
/// Sole `AND W0,W0,#0xFF; RET` is VA `0x010af790` with **zero** Ghidra xrefs.
pub const BOSMINER_AND_FF_RET_VA: u64 = 0x010A_F790;
pub const BOSMINER_AND_FF_RET_XREFS: usize = 0;
/// Worker ctor `mov w,#0x20; movk #0xe000,lsl#16` = tracing mask, not size 32.
pub const BOSMINER_WORKER_CTOR_TRACE_MASK: u32 = 0xE000_0020;
pub const BOSMINER_WORKER_NEW_FN_VA: u64 = 0x0090_3534;
pub const BOSMINER_WORKER_INIT_SPAN_FN_VA: u64 = 0x008F_8018;
/// ESP-Miner `sizeof(BM1366_job)` after type+len. Same 82 B Braiins copies.
pub const ESP_BM1366_JOB_PAYLOAD: usize = 82;
pub const BOSMINER_GHIDRA_PREFIX: [u8; 4] = [0x55, 0xAA, 0x21, 0x36];
/// `FUN_00938f50` returns this raw state; finalize yields ITU-T `0xFFFF` init.
pub const BOSMINER_CRC_INIT_FN_VA: u64 = 0x0093_8F50;
pub const BOSMINER_CRC_UPDATE_FN_VA: u64 = 0x0093_8F58;
pub const BOSMINER_CRC_FINAL_FN_VA: u64 = 0x0093_8F84;
pub const BOSMINER_CRC_TABLE_VA: u64 = 0x0132_8F60;
pub const BOSMINER_CRC_INIT_RAW: u16 = 0x84CF;
/// LE u16 table[0..3] at `DAT_01328f60` — CRC-16/CCITT poly `0x1021`.
pub const BOSMINER_CRC_TABLE_HEAD: [u16; 4] = [0x0000, 0x1021, 0x2042, 0x3063];
/// `packed_struct-0.10.1/src/packing.rs` adjacent to antminer `bm136x.rs`.
///  Ghidra-free: this is the job-builder crate, not a length-field literal.
pub const BOSMINER_BM136X_PACKED_STRUCT_OFF: u64 = 0x00F2_56E0;
/// `BUG: Unexpected size` lives in `bm1398_6x.rs` (FPGA midstate), not `bm136x.rs`.
pub const BOSMINER_UNEXPECTED_SIZE_OFF: u64 = 0x00F2_5468;
/// Unique ELF ADRP+ADD xref to `bosminer-antminer/src/bm136x.rs`.
/// : this is `FUN_009208cc` (Location `bm136x.rs:36:26`), **not**
/// `0x9208F8`. That later stub is `bm13xx.rs:200` + string length `0x2E`.
pub const BOSMINER_BM136X_XREF_VA: u64 = 0x0092_08CC;
pub const BOSMINER_BM136X_XREF_ADRP_INSN: u32 = 0xD000_8540;
pub const BOSMINER_BM136X_XREF_ADD_INSN: u32 = 0x9119_8000;
pub const BOSMINER_BM136X_LOC_VA: u64 = 0x019C_A660;
pub const BOSMINER_BM136X_LOC_LINE: u16 = 36;
pub const BOSMINER_BM136X_LOC_COL: u16 = 26;
pub const BOSMINER_ANTMINER_BM136X_RS: &str = "open/bosminer/bosminer-antminer/src/bm136x.rs";
///  false ident: `MOVZ W1,#0x2E` at `0x920908` is the panic-string
/// **length**, not rustc line 46.
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_FN_VA: u64 = 0x0092_08F8;
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_LEN: u16 = 0x2E;
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_MOVZ_INSN: u32 = 0x5280_05C1;
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_MSG: &str =
    "assertion failed: !chip_address.is_broadcast()";
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_MSG_VA: u64 = 0x0132_575D;
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_LOC_VA: u64 = 0x019C_A678;
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_LINE: u16 = 200;
pub const BOSMINER_BM13XX_BROADCAST_ASSERT_COL: u16 = 9;
pub const BOSMINER_BM13XX_RS: &str = "open/bosminer/bosminer-antminer/src/bm13xx.rs";
/// : no AArch64 `BL` in `.text` targets the bm136x.rs:36 stub.
pub const BOSMINER_BM136X_PANIC_BL_CALLERS: usize = 0;
/// Unique first-LOAD `MOVZ W0,#0x56` + `BL 0x5f4a84` (alloc 0x56 / align 1).
pub const BOSMINER_PACK_ALLOC_BL_VA: u64 = 0x0091_BEDC;
pub const BOSMINER_PACK_ALLOC_BL_INSN: u32 = 0x97F3_62EA;
pub const BOSMINER_PACK_ALLOC_BL_TGT: u64 = 0x005F_4A84;
pub const BOSMINER_PACK_ALLOC56_SITES: usize = 1;
/// Caller `FUN_0091bfe8` `BL FUN_0091beb4`.
pub const BOSMINER_PACK_CALLER_BL_VA: u64 = 0x0091_C04C;
/// : second-LOAD rustc TypeInfo `{drop_in_place, size, align}`
/// with `size==0x56` and `align∈{1,2,4,8,16}` = **0**. The 0x56 job
/// packed type is not published as a rustc TypeId/size-class record.
pub const BOSMINER_TYPEINFO_SIZE56_HITS: usize = 0;
/// Count of unique `bosminer[a-z0-9_]*::` tracing/type path prefixes
/// in first LOAD. None names a 0x56 UART job packed struct.
pub const BOSMINER_RUSTC_TYPE_PATH_HITS: usize = 84;
pub const BOSMINER_HAL_COMMAND_TYPE: &str = "bosminer_hal::command";
pub const BOSMINER_HAL_WORKPAIR_TYPE: &str = "bosminer_hal::workpair";
pub const BOSMINER_HAL_IO_TYPE: &str = "bosminer_hal::io";
pub const BOSMINER_BACKEND_WORKER_TYPE: &str = "bosminer_backend::worker";
pub const BOSMINER_HAL_WORKPAIR_FIELDS: &str = "nonceversion_idxsolution_idxtarget";
pub const BOSMINER_HAL_COMMAND_CHIPPARAMS: &str = "ChipParams";
/// HashMap `V` is 0x18, not 0x56.
pub const BOSMINER_HASHMAP_V_SIZE: usize = 0x18;
/// factory4 prefix box is 0x98, not 0x56.
pub const BOSMINER_FACTORY4_PREFIX_BOX: usize = 0x98;
/// : HashMap `V` rust identity is the **per-chip factory tuple**
/// painted by `FUN_00862458` (frame `0x130`) into unique 7-insert
/// wrapper `FUN_008d4a10`. `K` is `u16` chip id (`STRH` at slot+0,
/// stride `0x20`). `V` is the `0x18` at slot+8 (`ORR #8`).
/// Slot order: `1362 1366 1368 1370 1398 1396 1397`.
/// No rustc type-path / `OccupiedEntry` / `VacantEntry` string names `V`.
/// `hashbrown-0.14.5/src/raw/mod.rs:86` Location `0x19972b8` has **1**
/// first-LOAD xref at `0x403294` — not this constructor.
/// Sibling wrapper `FUN_008d4b30` unrolls the AM3 **4**-id subset.
/// `factory4` is painted at `V+0` for the 1366 slot (`STP` `0x8624d4`)
/// but is **not** the rust type name of `V` and is **not** the spawn
/// `BLR` site (`BOSMINER_HASHMAP_V0_IS_FACTORY4` stays false).
pub const BOSMINER_HASHMAP_V_CTOR_VA: u64 = 0x0086_2458;
pub const BOSMINER_HASHMAP_V_CTOR_PROLOGUE_INSN: u32 = 0xD104_C3FF;
pub const BOSMINER_HASHMAP_V_CTOR_FRAME: u16 = 0x130;
pub const BOSMINER_HASHMAP_V_WRAPPER_VA: u64 = 0x008D_4A10;
pub const BOSMINER_HASHMAP_V_WRAPPER_BL_HITS: usize = 1;
pub const BOSMINER_HASHMAP_V_INSERT_UNROLL: usize = 7;
pub const BOSMINER_HASHMAP_V_SLOT_STRIDE: u16 = 0x20;
pub const BOSMINER_HASHMAP_V_KEY_OFF: u16 = 0;
pub const BOSMINER_HASHMAP_V_VALUE_OFF: u16 = 8;
pub const BOSMINER_HASHMAP_V_KEYS: [u16; 7] =
    [0x1362, 0x1366, 0x1368, 0x1370, 0x1398, 0x1396, 0x1397];
pub const BOSMINER_HASHMAP_V_1366_MOVZ_VA: u64 = 0x0086_2498;
pub const BOSMINER_HASHMAP_V_1366_MOVZ_INSN: u32 = 0x5282_6CCA;
pub const BOSMINER_HASHMAP_V_1366_STRH_VA: u64 = 0x0086_24B4;
pub const BOSMINER_HASHMAP_V_1366_STRH_INSN: u32 = 0x7900_A3EA;
pub const BOSMINER_HASHMAP_V_1362_STRH_VA: u64 = 0x0086_248C;
pub const BOSMINER_HASHMAP_V_1362_STRH_INSN: u32 = 0x7900_63E9;
pub const BOSMINER_HASHMAP_V_WRAPPER_LAST_INSERT_BL_VA: u64 = 0x008D_4B04;
pub const BOSMINER_HASHMAP_V_WRAPPER_LAST_INSERT_BL_INSN: u32 = 0x9400_1683;
pub const BOSMINER_HASHMAP_V_SIBLING_WRAPPER_VA: u64 = 0x008D_4B30;
pub const BOSMINER_HASHMAP_V_SIBLING_UNROLL: usize = 4;
pub const BOSMINER_HASHMAP_V_INSERT_BL_HITS: usize = 13;
pub const BOSMINER_HASHMAP_V_TYPE_PATH_HITS: usize = 0;
pub const BOSMINER_HASHMAP_OCCUPIED_ENTRY_STR_HITS: usize = 0;
pub const BOSMINER_HASHMAP_VACANT_ENTRY_STR_HITS: usize = 0;
pub const BOSMINER_HASHBROWN_0145_MOD86_LOC_VA: u64 = 0x0199_72B8;
pub const BOSMINER_HASHBROWN_0145_MOD86_XREF_HITS: usize = 1;
pub const BOSMINER_HASHBROWN_0145_MOD86_XREF_VA: u64 = 0x0040_3294;
pub const BOSMINER_HASHMAP_V_TYPE_NAMED: bool = false;
pub const BOSMINER_HASHMAP_V_IS_OCCUPIED_ENTRY: bool = false;

/// : table-driven CRC with raw init `0x84CF` + finalize == ITU-T.
pub fn admit_bosminer_ghidra_crc_is_itu_t() -> Result<(), &'static str> {
    if BOSMINER_CRC_TABLE_HEAD != [0x0000, 0x1021, 0x2042, 0x3063] {
        return Err("bosminer CRC table head is not CCITT poly 0x1021");
    }
    if BOSMINER_CRC_INIT_RAW != 0x84CF {
        return Err("bosminer CRC init fn is not 0x84CF");
    }
    // Empty payload: finalize(0x84CF) == 0xFFFF == ITU-T(empty).
    if crc16_itu_t(&[]) != 0xFFFF {
        return Err("ITU-T empty must be 0xFFFF");
    }
    Ok(())
}

/// `FUN_00c41e5c(work, 0)`: `((vbits_base + index) & 0xffff) << 13 | base`.
pub fn s19k_braiins_midstate0_version(base_version: u32, version_bits_base: u16) -> u32 {
    ((u32::from(version_bits_base)) << 13) | base_version
}

/// BIP320 reconstruct strips bits 13..28 from packed ver0. Fill must not.
pub fn refuse_bip320_strip_as_braiins_fill_ver0(base_version: u32, uart_vbits: u16) -> u32 {
    let stripped = base_version & !0x1FFF_E000;
    stripped | ((u32::from(uart_vbits) << 13) & 0x1FFF_E000)
}

/// Production `serial_rolled_version` must OR packed ver0 before BIP320 strip.
///
/// The pinned fact is the helper CALL with exactly `(entry.version,
/// version_bits_raw)` — never the source's line wrapping. Rustfmt may keep
/// the call on one line or wrap it with a trailing comma, so both sides are
/// whitespace-squashed before matching and a pure formatting pass on
/// `serial_mining.rs` can never break this pin. This is the root cause of
/// the 2026-08-17..19 "unchanged dirty S19k failure": the pin matched the
/// exact single-line byte string `s19k_braiins_midstate0_version(
/// entry.version, version_bits_raw)` and broke when the dirty worktree
/// wrapped the identical call across lines. The closing paren stays tight
/// in both accepted spellings, so a third argument or a substituted input
/// is still refused.
pub fn admit_s19k_production_rolled_version_is_midstate0_or(src: &str) -> Result<(), &'static str> {
    let Some(fn_start) = src.find("fn serial_rolled_version(") else {
        return Err("serial_rolled_version missing");
    };
    let rolled = src[fn_start..]
        .split("fn serial_build_header(")
        .next()
        .ok_or("serial_rolled_version window missing")?;
    let squashed: String = rolled.split_whitespace().collect();
    let call_one_line = "s19k_braiins_midstate0_version(entry.version,version_bits_raw)";
    let call_wrapped = "s19k_braiins_midstate0_version(entry.version,version_bits_raw,)";
    let or_at = squashed
        .find(call_one_line)
        .or_else(|| squashed.find(call_wrapped));
    let Some(or_at) = or_at else {
        if squashed.contains("s19k_braiins_midstate0_version") {
            return Err("midstate0 OR call must take exactly (entry.version, version_bits_raw)");
        }
        return Err("BM1366 serial_rolled_version must call midstate0 OR");
    };
    if let Some(recon_at) = squashed.find("bip320_reconstruct_rolled_version") {
        if or_at > recon_at {
            return Err("midstate0 OR must run before BIP320 reconstruct");
        }
    }
    if !squashed.contains("ifis_bm1366") {
        return Err("BM1366 packed-ver0 arm missing");
    }
    Ok(())
}

/// Fill+pack layout from `FUN_0091ba88` / `FUN_0091beb4`.
pub fn admit_bosminer_ghidra_fill_pack_map() -> Result<(), &'static str> {
    if BOSMINER_FILL_PREFIX_OFF != 0x50 {
        return Err("fill writes DAT_012ec448 at +0x50");
    }
    if BOSMINER_FILL_JOB_ID_OFF != 0x54 || BOSMINER_FILL_MIDSTATES_OFF != 0x55 {
        return Err("fill job_id at +0x54, midstates=1 at +0x55");
    }
    if BOSMINER_FILL_NONCE_OFF != 0x40 {
        return Err("fill starting_nonce at +0x40 is 0");
    }
    if BOSMINER_PACK_ALLOC != 0x56 || BOSMINER_PACK_CRC_OFF != 2 || BOSMINER_PACK_CRC_LEN != 0x54 {
        return Err("pack alloc 0x56, CRC dest+2 len 0x54, grow to 0x58");
    }
    if ESP_BM1366_JOB_PAYLOAD != 82 {
        return Err("ESP BM1366_job is 82 bytes");
    }
    Ok(())
}

/// `FUN_0091beb4` dest field offsets after the SIMD reorder.
/// Mining-on body is dest[2..] (`55 AA` stays on the wire only).
pub fn admit_bosminer_91beb4_dest_layout() -> Result<(), &'static str> {
    if BOSMINER_PACK_DEST_PREFIX_OFF != 0 || BOSMINER_PACK_DEST_TYPE_OFF != 2 {
        return Err("packer dest[0:4] is 55 AA 21 36");
    }
    if BOSMINER_PACK_DEST_JOB_ID_OFF != 4 || BOSMINER_PACK_DEST_MIDSTATES_OFF != 5 {
        return Err("packer dest[4]=job_id dest[5]=midstates");
    }
    if BOSMINER_PACK_DEST_NONCE_OFF != 6 || BOSMINER_PACK_DEST_NBITS_OFF != 10 {
        return Err("packer dest nonce@6 nbits@10");
    }
    if BOSMINER_PACK_DEST_NTIME_OFF != 14 || BOSMINER_PACK_DEST_MERKLE_OFF != 0x12 {
        return Err("packer dest ntime@14 merkle@0x12");
    }
    if BOSMINER_PACK_DEST_PREV_OFF != 0x32 || BOSMINER_PACK_DEST_VERSION_OFF != 0x52 {
        return Err("packer dest prev@0x32 version@0x52 (STUR #0x52)");
    }
    if BOSMINER_PACK_DEST_TYPE_OFF != BOSMINER_PACK_CRC_OFF {
        return Err("CRC cover dest+2 is the 0x21 type byte");
    }
    Ok(())
}

/// Production `pack_s19k_braiins_ghidra_job_body` is dest[2..] of `FUN_0091beb4`.
pub fn admit_s19k_ghidra_pack_body_matches_production() -> Result<(), &'static str> {
    admit_bosminer_91beb4_dest_layout()?;
    if BOSMINER_PACK_DEST_JOB_ID_OFF - 2 != 2 {
        return Err("production body[2] must be dest job_id");
    }
    if BOSMINER_PACK_DEST_NONCE_OFF - 2 != 4 {
        return Err("production body[4:8] must be dest nonce");
    }
    if BOSMINER_PACK_DEST_NBITS_OFF - 2 != 8 {
        return Err("production body[8:12] must be dest nbits");
    }
    if BOSMINER_PACK_DEST_NTIME_OFF - 2 != 12 {
        return Err("production body[12:16] must be dest ntime");
    }
    if BOSMINER_PACK_DEST_MERKLE_OFF - 2 != 16 {
        return Err("production body[16:48] must be dest merkle");
    }
    if BOSMINER_PACK_DEST_PREV_OFF - 2 != 48 {
        return Err("production body[48:80] must be dest prev");
    }
    if BOSMINER_PACK_DEST_VERSION_OFF - 2 != 80 {
        return Err("production body[80:84] must be dest version");
    }
    let nbits = 0x1707_A30A;
    let ntime = 0x5F5E_1000;
    let ver = 0x2000_0000;
    let mut prev = [0u8; 32];
    prev[0] = 0x11;
    prev[31] = 0x22;
    let mut merkle = [0u8; 32];
    merkle[0] = 0x33;
    merkle[31] = 0x44;
    let body = pack_s19k_braiins_ghidra_job_body(2, ver, prev, merkle, ntime, nbits);
    if body[0] != JOB_CMD_TYPE || body[1] != JOB_LEN_FIELD {
        return Err("production body must start 21 36");
    }
    if body[2] != 2 || body[3] != JOB_RSVD2 {
        return Err("production body job_id/midstates must match dest[4:6]");
    }
    if body[4..8] != [0, 0, 0, 0] {
        return Err("fill starting_nonce dest[6:10] is 0");
    }
    if body[8..12] != nbits.to_le_bytes() {
        return Err("production nbits must be dest[10:14] LE");
    }
    if body[12..16] != ntime.to_le_bytes() {
        return Err("production ntime must be dest[14:18] LE");
    }
    if body[80..84] != s19k_braiins_midstate0_version(ver, 0).to_le_bytes() {
        return Err("production ver0 must be dest[0x52:0x56] LE");
    }
    Ok(())
}

/// First-LOAD paint of `FUN_0091beb4`. Does not name a rust method.
pub fn admit_bosminer_91beb4_pack_body_elf(blob: &[u8]) -> Result<(), &'static str> {
    let word = |va: u64| engine88_le_u32(blob, va);
    if word(BOSMINER_PACK_FN_VA).ok_or("bosminer shorter than packer SUB")?
        != BOSMINER_PACK_FN_SUB_INSN
    {
        return Err("FUN_0091beb4 entry is not SUB SP,#0x40");
    }
    if word(BOSMINER_PACK_FN_MOVZ56_VA).ok_or("bosminer shorter than packer MOVZ #0x56")?
        != BOSMINER_PACK_FN_MOVZ56_INSN
    {
        return Err("FUN_0091beb4 must MOVZ W0,#0x56");
    }
    if word(BOSMINER_PACK_FN_ADD54_VA).ok_or("bosminer shorter than packer ADD #0x54")?
        != BOSMINER_PACK_FN_ADD54_INSN
    {
        return Err("FUN_0091beb4 must ADD X8,X21,#0x54 (fill job_id)");
    }
    if word(BOSMINER_PACK_FN_ADD50_VA).ok_or("bosminer shorter than packer ADD #0x50")?
        != BOSMINER_PACK_FN_ADD50_INSN
    {
        return Err("FUN_0091beb4 must ADD X8,X21,#0x50 (fill prefix)");
    }
    if word(BOSMINER_PACK_FN_STRQ0_VA).ok_or("bosminer shorter than packer STR Q0")?
        != BOSMINER_PACK_FN_STRQ0_INSN
    {
        return Err("FUN_0091beb4 must STR Q0,[X0] dest[0:16]");
    }
    if word(BOSMINER_PACK_FN_STUR52_VA).ok_or("bosminer shorter than packer STUR #0x52")?
        != BOSMINER_PACK_FN_STUR52_INSN
    {
        return Err("FUN_0091beb4 must STUR W9,[X0,#0x52] version");
    }
    if word(BOSMINER_PACK_FN_CRC_INIT_BL_VA).ok_or("bosminer shorter than CRC init BL")?
        != BOSMINER_PACK_FN_CRC_INIT_BL_INSN
    {
        return Err("FUN_0091beb4 must BL FUN_00938f50");
    }
    if word(BOSMINER_PACK_FN_ADD2_VA).ok_or("bosminer shorter than ADD dest+2")?
        != BOSMINER_PACK_FN_ADD2_INSN
    {
        return Err("FUN_0091beb4 must ADD X1,X20,#2 (CRC dest+2)");
    }
    if word(BOSMINER_PACK_FN_MOVZ54_VA).ok_or("bosminer shorter than MOVZ #0x54")?
        != BOSMINER_PACK_FN_MOVZ54_INSN
    {
        return Err("FUN_0091beb4 must MOVZ W2,#0x54 (CRC len)");
    }
    if word(BOSMINER_PACK_FN_CRC_UPD_BL_VA).ok_or("bosminer shorter than CRC update BL")?
        != BOSMINER_PACK_FN_CRC_UPD_BL_INSN
    {
        return Err("FUN_0091beb4 must BL FUN_00938f58");
    }
    if word(BOSMINER_PACK_FN_CRC_FIN_BL_VA).ok_or("bosminer shorter than CRC finalize BL")?
        != BOSMINER_PACK_FN_CRC_FIN_BL_INSN
    {
        return Err("FUN_0091beb4 must BL FUN_00938f84");
    }
    if word(BOSMINER_PACK_FN_RET_VA).ok_or("bosminer shorter than packer RET")?
        != BOSMINER_PACK_FN_RET_INSN
    {
        return Err("FUN_0091beb4 must RET at 0x91bfb0");
    }
    if BOSMINER_PACK_FN_SUCCESS_RUSTC_LOCS != 0 {
        return Err("success path rustc Location census drifted");
    }
    Ok(())
}

/// Alloc-fail Location is `packing.rs:40:23`. That is not the packer rust ident.
pub fn refuse_91beb4_alloc_fail_packing40_as_pack_ident() -> Result<(), &'static str> {
    Err(
        "FUN_0091beb4 alloc-fail Location is packing.rs:40:23; success path has 0 rustc Locations; do not name PackedStruct::pack",
    )
}

/// : FUN_0091beb4 is the unique 0x56 packed_struct alloc. No rust name.
pub fn admit_bosminer_91beb4_unique_alloc56() -> Result<(), &'static str> {
    if BOSMINER_PACK_ALLOC56_SITES != 1 {
        return Err("first LOAD must have exactly one MOVZ #0x56 + BL 0x5f4a84");
    }
    if BOSMINER_PACK_ALLOC_BL_VA != 0x0091_BEDC {
        return Err("unique 0x56 alloc BL is not inside FUN_0091beb4");
    }
    if BOSMINER_PACK_ALLOC_BL_TGT != 0x005F_4A84 {
        return Err("0x56 alloc target drifted from 0x5f4a84");
    }
    if BOSMINER_PACK_FN_MOVZ56_VA != 0x0091_BEC8 {
        return Err("MOVZ W0,#0x56 must sit in FUN_0091beb4");
    }
    if BOSMINER_PACK_CALLER_BL_VA != 0x0091_C04C {
        return Err("worker.rs:482 helper must BL FUN_0091beb4 at 0x91c04c");
    }
    if BOSMINER_PACK_FN_SUCCESS_RUSTC_LOCS != 0 {
        return Err("success path still has 0 rustc Locations; do not invent a fn name");
    }
    Ok(())
}

pub fn admit_bosminer_91beb4_unique_alloc56_elf(blob: &[u8]) -> Result<(), &'static str> {
    admit_bosminer_91beb4_pack_body_elf(blob)?;
    let word = |va: u64| -> Option<u32> {
        let off = usize::try_from(va.checked_sub(0x400_000)?).ok()?;
        if off + 4 > blob.len() {
            return None;
        }
        Some(u32::from_le_bytes(blob[off..off + 4].try_into().ok()?))
    };
    if word(BOSMINER_PACK_ALLOC_BL_VA).ok_or("bosminer shorter than alloc BL")?
        != BOSMINER_PACK_ALLOC_BL_INSN
    {
        return Err("FUN_0091beb4 must BL 0x5f4a84 after MOVZ #0x56");
    }
    Ok(())
}

/// `0x9208F8` `MOVZ #0x2E` is the broadcast-assert string length, not line 46.
pub fn refuse_9208f8_movz2e_as_bm136x_line46() -> Result<(), &'static str> {
    Err(
        "0x920908 MOVZ #0x2E is len(assertion failed: !chip_address.is_broadcast()); Location is bm13xx.rs:200:9, not bm136x.rs:46",
    )
}

/// Unique antminer `bm136x.rs` Location is the 0x9208cc unwrap stub, not the packer.
pub fn admit_bosminer_bm136x_rs_36_is_not_pack() -> Result<(), &'static str> {
    if BOSMINER_BM136X_XREF_VA != 0x0092_08CC {
        return Err("unique bm136x.rs ADRP is FUN_009208cc");
    }
    if BOSMINER_BM136X_LOC_LINE != 36 || BOSMINER_BM136X_LOC_COL != 26 {
        return Err("bm136x.rs Location is 36:26");
    }
    if BOSMINER_BM136X_XREF_VA == BOSMINER_PACK_FN_VA {
        return Err("bm136x.rs:36 stub is not FUN_0091beb4");
    }
    Ok(())
}

pub fn admit_bosminer_bm13xx_broadcast_assert() -> Result<(), &'static str> {
    if BOSMINER_BM13XX_BROADCAST_ASSERT_MSG.len()
        != usize::from(BOSMINER_BM13XX_BROADCAST_ASSERT_LEN)
    {
        return Err("broadcast assert message length is not 0x2E");
    }
    if BOSMINER_BM13XX_BROADCAST_ASSERT_LINE != 200 {
        return Err("0x9208F8 Location is bm13xx.rs:200:9");
    }
    if !BOSMINER_BM13XX_BROADCAST_ASSERT_MSG.contains("chip_address.is_broadcast") {
        return Err("0x9208F8 string is the chip_address broadcast assert");
    }
    Ok(())
}

/// : rustc TypeInfo / HashMap V / factory / HAL type paths do not
/// name the 0x56 packed job type.
pub fn admit_bosminer_pack56_type_unnamed_in_rustc_metadata() -> Result<(), &'static str> {
    if BOSMINER_TYPEINFO_SIZE56_HITS != 0 {
        return Err("TypeInfo size=0x56 census drifted");
    }
    if BOSMINER_RUSTC_TYPE_PATH_HITS != 84 {
        return Err("bosminer::* type-path census drifted");
    }
    if BOSMINER_PACK_ALLOC != 0x56 {
        return Err("pack alloc must stay 0x56");
    }
    if BOSMINER_HASHMAP_V_SIZE == BOSMINER_PACK_ALLOC {
        return Err("HashMap V size must not equal pack alloc");
    }
    if BOSMINER_FACTORY4_PREFIX_BOX == BOSMINER_PACK_ALLOC {
        return Err("factory4 prefix box must not equal pack alloc");
    }
    Ok(())
}

pub fn refuse_hashmap_v_as_pack56_type() -> Result<(), &'static str> {
    Err(
        "HashMap V is 0x18 {spawn@+0, factory@+8, extra@+0x10}; not the 0x56 packed_struct job type",
    )
}

pub fn refuse_factory4_as_pack56_type() -> Result<(), &'static str> {
    Err(
        "factory4 FUN_00877d40 prefix box is 0x98 / Registry wrap 0x1a8; not the 0x56 packed job type",
    )
}

pub fn refuse_workpair_as_pack56_type() -> Result<(), &'static str> {
    Err(
        "bosminer_hal::workpair fields are nonce/version_idx/solution_idx/target (RX share); not the TX 0x56 job",
    )
}

pub fn refuse_chipparams_as_pack56_type() -> Result<(), &'static str> {
    Err("bosminer_hal::command ChipParams is command.rs:594 tracing; not FUN_0091beb4 0x56 pack")
}

pub fn refuse_hal_io_as_pack56_type() -> Result<(), &'static str> {
    Err("bosminer_hal::io is Queue/build_hasher tracing; not the 0x56 packed job type")
}

/// work+0x38 is ntime (ESP slot after nbits). Not nbits.
pub fn admit_bosminer_work_ntime_off(off: usize) -> Result<(), &'static str> {
    if off != BOSMINER_WORK_NTIME_OFF {
        return Err("FUN_0091ba88 loads ntime from work+0x38");
    }
    Ok(())
}

pub fn refuse_bosminer_work_plus_0x38_as_nbits(off: usize) -> Result<(), &'static str> {
    if off == BOSMINER_WORK_NTIME_OFF {
        return Err("work+0x38 is ntime; nbits is Job dyn vtable+0x90 → *(job+0x78) → fill+0x44");
    }
    Ok(())
}

/// : both `stratum_v2.rs` Job impls return `*(self+0x78)` from vtable+0x90.
pub fn admit_bosminer_job_nbits_is_self_plus_0x78() -> Result<(), &'static str> {
    if BOSMINER_JOB_NBITS_GETTER_INSN != 0xB940_7800 {
        return Err("nbits getter is not ldr w0,[x0,#0x78]");
    }
    if BOSMINER_JOB_NBITS_OFF != 0x78 || BOSMINER_JOB_SIZE != 0x80 {
        return Err("Job object is 0x80 bytes with nbits at +0x78");
    }
    if BOSMINER_JOB_PREVHASH_OFF != 0x08 || BOSMINER_JOB_MERKLE_OFF != 0x28 {
        return Err("FUN_00d1372c prevhash +8 / merkle +0x28");
    }
    if BOSMINER_JOB_NBITS_VTABLE_HITS != 2 {
        return Err("exactly two rust vtables hold the nbits getters");
    }
    if BOSMINER_WORK_JOB_VTABLE_OFF != 0x20 {
        return Err("fill x22 is work+0x20 Job vtable");
    }
    if BOSMINER_NBITS_BUG_WORK_RS_LINE != 307 {
        return Err("nbits BUG rustc Location is work.rs:307");
    }
    if !BOSMINER_STRATUM_V2_RS.ends_with("stratum_v2.rs") {
        return Err("Job vtables are stratum_v2.rs, not a unique engine type");
    }
    Ok(())
}

/// Pack-caller `FUN_0091bfe8` also does `blr [engine+0x90]`, but that
/// result is **job_id** (fill+0x54), not nbits.
pub fn refuse_bosminer_pack_caller_engine_plus_0x90_as_nbits() -> Result<(), &'static str> {
    Err("FUN_0091bfe8 engine+0x90 (worker.rs fn ptr) returns job_id for fill+0x54; nbits is work+0x20 Job vtable+0x90 → *(job+0x78)")
}

/// `1 << log` midstates. Log 0..=3 only (`FUN_0092f200`).
pub fn s19k_braiins_midstate_count_from_log(log: u32) -> Result<u32, &'static str> {
    if log > BOSMINER_MIDSTATE_LOG_MAX {
        return Err("invalid midstate count logarithm (FUN_0092f200, log>=4)");
    }
    Ok(1u32 << log)
}

/// FPGA `get_work_id_count` = `0x10000 >> log`. Not the UART job_id space.
pub fn s19k_braiins_fpga_work_id_count(log: u32) -> Result<u32, &'static str> {
    let _ = s19k_braiins_midstate_count_from_log(log)?;
    Ok(BOSMINER_FPGA_WORK_ID_COUNT_BASE >> log)
}

pub fn admit_bosminer_engine_midstate_log(off: usize) -> Result<(), &'static str> {
    if off != BOSMINER_ENGINE_MIDSTATE_LOG_OFF {
        return Err("FUN_0091bfe8 loads midstate log from engine+0x70");
    }
    if BOSMINER_PACK_CALLER_WORKER_RS_LINE != 482 {
        return Err("pack caller is worker.rs:482");
    }
    if BOSMINER_FILL_MIDSTATES != 1 {
        return Err("fill hardcodes midstates=1");
    }
    Ok(())
}

/// FPGA `ExtWorkId::to_hw` = `work_id << log`. That is work-tx FIFO W0, not ttyS.
pub fn refuse_ext_work_id_to_hw_as_s19k_uart_job_id() -> Result<(), &'static str> {
    Err("ext_work_id.rs to_hw is Zynq FPGA FIFO W0; UART job_id is worker.rs engine+0x90(*(work+0x40), 1<<log)")
}

/// Stock uart_trans / MS8 still use `slot<<3`. That equals Braiins UART
/// `work_id<<log` **only** when log=3. Fill midstates=1 ⇒ log=0 ⇒ identity,
/// and the shipped fill builders now encode that way.
pub fn refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id() -> Result<(), &'static str> {
    Err("slot<<3 is stock/MS8; Braiins UART job_id is work_id<<log (RX inverse). log=0 on fill midstates=1")
}

/// `FUN_00bf5414` stores registry insert return at work+0x40.
pub fn admit_bosminer_work_plus_0x40_is_registry_work_id(off: usize) -> Result<(), &'static str> {
    if off != BOSMINER_WORK_ID_OFF {
        return Err("FUN_00bf5414 stp places registry work_id at work+0x40");
    }
    if BOSMINER_REGISTRY_SLOT_STRIDE != 0x78 {
        return Err("registry slot stride is 0x78");
    }
    if BOSMINER_REGISTRY_ASSERT_LINE != 148 {
        return Err("work_id < registry_size rustc Location is registry.rs:148");
    }
    Ok(())
}

/// A bare 32/128/256 without the log formula is not a unique constant.
pub fn refuse_invented_registry_size_as_uart_job_id_space(size: u32) -> Result<(), &'static str> {
    if matches!(size, 32 | 64 | 128 | 256) && !BOSMINER_REGISTRY_SIZE_KNOWN {
        return Err("UART registry_size is 0x100>>log (256/128/64/32); do not pin one constant");
    }
    Ok(())
}

/// UART `Registry::new` count from am3.rs Worker factories.
pub fn s19k_braiins_uart_registry_size_from_log(log: u32) -> Result<u32, &'static str> {
    let _ = s19k_braiins_midstate_count_from_log(log)?;
    Ok(BOSMINER_UART_REGISTRY_SIZE_BASE >> log)
}

/// Tail at `FUN_00b2639c`: `MOVZ W8,#1; LSRV X0,X8,X0` after `BL FUN_00bf26d0`.
/// Fill log=0 ⇒ 1. Midstate-8 log=3 ⇒ 0. Not `0x100>>log`.
pub fn s19k_braiins_one_shr_log(log: u32) -> Result<u64, &'static str> {
    let _ = s19k_braiins_midstate_count_from_log(log)?;
    Ok(1u64 >> log)
}

/// FPGA `FUN_008aea30` is `0x10000 >> log`. Not the UART factory.
pub fn refuse_fpga_0x10000_shr_log_as_uart_registry_size(base: u32) -> Result<(), &'static str> {
    if base == BOSMINER_FPGA_WORK_ID_COUNT_BASE {
        return Err("0x10000>>log is FUN_008aea30 FPGA get_work_id_count; UART am3 factories use 0x100>>log");
    }
    Ok(())
}

/// Five AM3 factories + five Worker monomorphizations share `0x100>>log`.
pub fn admit_bosminer_uart_registry_size_is_0x100_shr_log() -> Result<(), &'static str> {
    if BOSMINER_AM3_FACTORY_0X100_SHR_HITS != 5 {
        return Err("expected five AM3 0x100>>log factories");
    }
    if BOSMINER_AM3_FACTORY_MOVZ_INSN != 0x5280_200A {
        return Err("AM3 factory MOVZ is not W10,#0x100");
    }
    if BOSMINER_AM3_FACTORY_LSRV_INSN != 0x9AC8_2546 {
        return Err("AM3 factory LSRV is not X6,X10,X8");
    }
    if BOSMINER_WORKER_NEW_SAVES_X6_INSN != 0xAA06_03FA {
        return Err("Worker::new does not save x6 (count) to x26");
    }
    if !BOSMINER_AM3_RS.ends_with("hardware/am3.rs") {
        return Err("UART factories are am3.rs, not a unique AML crate");
    }
    if BOSMINER_FILL_MIDSTATES != 1 {
        return Err("fill hardcodes midstates=1 so UART size is 256 on that path");
    }
    Ok(())
}

/// `aml.rs` is the Antminer AML *control board*. Registry size is am3.rs.
pub fn refuse_aml_ctrl_rs_as_uart_registry_factory() -> Result<(), &'static str> {
    if BOSMINER_AML_CTRL_RS.contains("controlboard/aml.rs") {
        return Err(
            "aml.rs is antminer controlboard; UART Registry::new count is am3.rs 0x100>>log",
        );
    }
    Ok(())
}

/// `a lab unit` bosminer `FUN_008d6cf0` maps chip 0x1366 onto factory `FUN_00876ca8`.
pub fn admit_bosminer_bm1366_uses_am3_uart_registry_factory() -> Result<(), &'static str> {
    if BOSMINER_BM1366_CHIP_ID != 0x1366 {
        return Err("S19k chip id is 0x1366");
    }
    if !BOSMINER_AM3_CHIP_DISPATCH_IDS.contains(&0x1366) {
        return Err("dispatcher table must include 0x1366");
    }
    if BOSMINER_AM3_CHIP_DISPATCH_IDS != [0x1362, 0x1366, 0x1368, 0x1370] {
        return Err("FUN_008d6cf0 table is 1362/1366/1368/1370");
    }
    if BOSMINER_AM3_CHIP_DISPATCH_1366_MOVZ_INSN != 0x5282_6CCA {
        return Err("dispatcher MOVZ W10,#0x1366 pin drifted");
    }
    if BOSMINER_AM3_WORKER_FACTORY_VA != 0x0087_6CA8 {
        return Err("0x1366 slot is factory FUN_00876ca8");
    }
    if !BOSMINER_BM1366_RS.ends_with("hashchain/bm1366.rs") {
        return Err("Bm1366 HashChain driver rustc path missing");
    }
    Ok(())
}

/// Do not invent a BM1366-only registry_size. Same AM3 factory as 1362/1368/1370.
pub fn refuse_bm1366_exclusive_uart_registry_size() -> Result<(), &'static str> {
    Err("FUN_008d6cf0 binds 0x1366 to the same 0x100>>log AM3 factory as 0x1362/0x1368/0x1370")
}

/// UART job_id inputs. Encoder body at engine+0x90 is still unnamed.
pub fn s19k_braiins_uart_job_id_inputs(
    work_id: u64,
    midstate_log: u32,
) -> Result<(u64, u32), &'static str> {
    let n = s19k_braiins_midstate_count_from_log(midstate_log)?;
    Ok((work_id, n))
}

/// Braiins ttyS job_id byte. RX parse does `payload[5] >> log` = work_id,
/// so TX is `work_id << log`. Fits the 8-bit field iff
/// `work_id < 0x100>>log`.
pub fn s19k_braiins_uart_job_id(work_id: u64, midstate_log: u32) -> Result<u8, &'static str> {
    let size = u64::from(s19k_braiins_uart_registry_size_from_log(midstate_log)?);
    if work_id >= size {
        return Err("work_id >= UART registry_size (0x100>>log)");
    }
    Ok(((work_id as u32) << midstate_log) as u8)
}

/// Inverse of [`s19k_braiins_uart_job_id`]: `FUN_0091c0a0` `(u64>>0x28)>>log`.
pub fn s19k_braiins_uart_work_id_from_rx_job_byte(
    job_byte: u8,
    midstate_log: u32,
) -> Result<u64, &'static str> {
    let _ = s19k_braiins_midstate_count_from_log(midstate_log)?;
    Ok(u64::from(job_byte) >> midstate_log)
}

/// Fill `+0x55 = 1` ⇒ [`BOSMINER_FILL_MIDSTATE_LOG`] = 0.
pub fn s19k_braiins_fill_midstate_log() -> u32 {
    match s19k_braiins_midstate_log_from_count(u32::from(BOSMINER_FILL_MIDSTATES)) {
        Ok(log) => log,
        Err(_) => BOSMINER_FILL_MIDSTATE_LOG,
    }
}

/// On-wire fill-path job_id: `work_id << fill_log`. Log 0 ⇒ identity.
pub fn s19k_braiins_fill_job_id(work_id: u8) -> u8 {
    s19k_braiins_uart_job_id(u64::from(work_id), s19k_braiins_fill_midstate_log())
        .expect("fill midstates=1 ⇒ log 0 ⇒ every u8 work_id fits the 256-slot UART registry")
}

/// ESP-Miner `bm1366.c` command/job opcodes. There is no work-abort /
/// invalidate command. The only job UART is `TYPE_JOB | CMD_WRITE` (0x21).
pub const S19K_ESP_BM1366_CMD_SETADDRESS: u8 = 0x00;
pub const S19K_ESP_BM1366_CMD_WRITE: u8 = 0x01;
pub const S19K_ESP_BM1366_CMD_READ: u8 = 0x02;
pub const S19K_ESP_BM1366_CMD_INACTIVE: u8 = 0x03;
pub const S19K_ESP_BM1366_TYPE_JOB: u8 = 0x20;
pub const S19K_ESP_BM1366_TYPE_CMD: u8 = 0x40;
pub const S19K_ESP_BM1366_JOB_WRITE: u8 = S19K_ESP_BM1366_TYPE_JOB | S19K_ESP_BM1366_CMD_WRITE;
pub const S19K_ESP_BM1366_JOB_ID_STEP: u8 = 8;
pub const S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP: u8 = 0x80;
pub const S19K_EXPERIMENTAL_POST_CLEAN_JOB_ENV: &str =
    "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP";

/// Held ESP + Braiins census: no leftover-safe abort opcode exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kWorkReplaceCensus {
    pub esp_has_abort_opcode: bool,
    pub esp_replace_is_type_job: bool,
    pub bosminer_clean_is_uart_abort: bool,
    pub live414_same_id_resumed_shares: bool,
    pub getaddress_is_safe_midrun: bool,
}

pub fn s19k_work_replace_census() -> S19kWorkReplaceCensus {
    S19kWorkReplaceCensus {
        esp_has_abort_opcode: false,
        esp_replace_is_type_job: true,
        bosminer_clean_is_uart_abort: false,
        live414_same_id_resumed_shares: false,
        getaddress_is_safe_midrun: false,
    }
}

pub fn admit_s19k_no_held_uart_abort_opcode() -> Result<(), &'static str> {
    let c = s19k_work_replace_census();
    if c.esp_has_abort_opcode {
        return Err("ESP BM1366 command list has no abort/invalidate opcode");
    }
    if !c.esp_replace_is_type_job {
        return Err("ESP replace is a new TYPE_JOB write, not a distinct opcode");
    }
    if c.bosminer_clean_is_uart_abort {
        return Err("Ghidra has_been_cleaned is software template reuse, not UART abort");
    }
    if c.live414_same_id_resumed_shares {
        return Err("live414 same-ID 21 36 resend did not resume SHARE");
    }
    if c.getaddress_is_safe_midrun {
        return Err("mid-run GetAddress is refused (live415)");
    }
    if S19K_ESP_BM1366_JOB_WRITE != JOB_CMD_TYPE {
        return Err("ESP TYPE_JOB|CMD_WRITE must be the shipped 0x21 job type");
    }
    Ok(())
}

/// Pin the held ESP-Miner BM1366 C: four CMD_* values, TYPE_JOB, no abort
/// string, `send_work` emits only TYPE_JOB, job_id steps by 8.
pub fn admit_s19k_esp_bm1366_has_no_work_abort_opcode(
    src: &str,
    jobs: &str,
) -> Result<(), &'static str> {
    let lower = src.to_ascii_lowercase();
    if lower.contains("abort") || src.contains("invalidate") {
        return Err("ESP bm1366.c must not name a work-abort/invalidate opcode");
    }
    if !src.contains("#define CMD_SETADDRESS 0x00") {
        return Err("ESP BM1366 CMD_SETADDRESS must stay 0x00");
    }
    if !src.contains("#define CMD_WRITE 0x01") {
        return Err("ESP BM1366 CMD_WRITE must stay 0x01");
    }
    if !src.contains("#define CMD_READ 0x02") {
        return Err("ESP BM1366 CMD_READ must stay 0x02");
    }
    if !src.contains("#define CMD_INACTIVE 0x03") {
        return Err("ESP BM1366 CMD_INACTIVE must stay 0x03");
    }
    if !src.contains("#define TYPE_JOB 0x20") {
        return Err("ESP BM1366 TYPE_JOB must stay 0x20");
    }
    if !src.contains("id = (id + 8) % 128") {
        return Err("ESP BM1366_send_work must step job_id by 8");
    }
    let start = src
        .find("void BM1366_send_work")
        .ok_or("missing BM1366_send_work")?;
    let send = src.get(start..start.saturating_add(1800)).unwrap_or("");
    if !send.contains("_send_BM1366((TYPE_JOB | GROUP_SINGLE | CMD_WRITE)") {
        return Err("BM1366_send_work must emit TYPE_JOB|CMD_WRITE only");
    }
    if send.contains("CMD_INACTIVE") || send.contains("CMD_SETADDRESS") {
        return Err("BM1366_send_work must not emit INACTIVE/GetAddress");
    }
    if jobs.to_ascii_lowercase().contains("abort") {
        return Err("ESP create_jobs_task must not abort ASIC work on clean_jobs");
    }
    if !jobs.contains("if (!current_mining_notification->clean_jobs)") {
        return Err("ESP clean_jobs only gates immediate generate_work");
    }
    Ok(())
}

pub fn refuse_s19k_cmd_inactive_as_midrun_work_replace() -> Result<(), &'static str> {
    Err("CMD_INACTIVE is ESP enum/init, not a leftover-safe mid-run work-replace")
}

pub fn refuse_s19k_esp_job_step8_as_track1_fill() -> Result<(), &'static str> {
    Err("ESP job_id += 8 is not Braiins fill job_id = work_id; Track-1 first-load shares are sequential")
}

/// Leftover-safe experimental job_id after a mid-run clean: XOR 0x80 so
/// leftover RX bytes miss the new tickets. Generation 0 (no mid-run clean)
/// stays fill identity. Not `slot<<3`. Not GetAddress.
pub fn s19k_experimental_post_clean_job_id(work_id: u8, midrun_clean_generation: u32) -> u8 {
    let fill = s19k_braiins_fill_job_id(work_id);
    if midrun_clean_generation == 0 {
        fill
    } else {
        fill ^ S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP
    }
}

/// Production default is fill identity. The flip is env-gated and experimental.
pub fn s19k_track1_fill_job_id(
    work_id: u8,
    midrun_clean_generation: u32,
    experimental_flip: bool,
) -> u8 {
    if experimental_flip {
        s19k_experimental_post_clean_job_id(work_id, midrun_clean_generation)
    } else {
        s19k_braiins_fill_job_id(work_id)
    }
}

pub fn s19k_experimental_post_clean_flip_enabled_from_env(raw: Option<&str>) -> bool {
    raw == Some("1")
}

///  RE: BM1366 `TYPE=2 (command) / GROUP_ALL / CMD=3` Chain Inactive
/// broadcast body (preamble + CRC5 are added by the HAL at send time).
/// Evidence:  ("CMD = 3:
/// chain Inactive", no response) and ESP-Miner `_send_chain_inactive()`
/// which builds exactly this command.
pub const S19K_BM1366_CHAIN_INACTIVE_BODY: [u8; 4] = [0x53, 0x05, 0x00, 0x00];

/// ESP-Miner evidence wire for [`S19K_BM1366_CHAIN_INACTIVE_BODY`]:
/// `55 AA 53 05 00 00 03` (CRC5 = 0x03). ESP-Miner sends this once during
/// init, before chip addressing; it is the only documented chip-side work
/// invalidation in the BM1366 protocol.
pub const S19K_BM1366_CHAIN_INACTIVE_WIRE: [u8; 7] = [0x55, 0xAA, 0x53, 0x05, 0x00, 0x00, 0x03];

pub fn admit_s19k_bm1366_chain_inactive_wire_evidence(
    body: &[u8; 4],
    wire: &[u8; 7],
) -> Result<(), &'static str> {
    if body != &S19K_BM1366_CHAIN_INACTIVE_BODY {
        return Err("chain-inactive body must be 53 05 00 00");
    }
    if wire != &S19K_BM1366_CHAIN_INACTIVE_WIRE {
        return Err("chain-inactive evidence wire must be 55 AA 53 05 00 00 03");
    }
    if &wire[2..6] != body {
        return Err("evidence wire must embed the body between preamble and CRC5");
    }
    Ok(())
}

pub fn s19k_experimental_post_clean_chain_inactive_enabled_from_env(raw: Option<&str>) -> bool {
    raw == Some("1")
}

/// live431: leftover_hit=4 on a retired 21 36 wire, leftover_header=0,
/// meets=0. That is the only evidence that admits the experimental
/// Chain Inactive env on the next soak. Production refill stays identity.
pub const S19K_LIVE431_LEFTOVER_HIT: u32 = 4;
pub const S19K_LIVE431_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE431_MEETS: u32 = 0;
pub const S19K_LIVE431_LEFTOVER_NONCE: u32 = 0x3C6C_D199;

/// live436 wrap-retire leftover BEFORE the first mid-run clean.
/// leftover_hit=3 leftover_header=0 at wrap_rx=4 with funnel unarmed.
/// Session-start NEW BLOCK is not a clean. First mid-run clean admits
/// leftover-admitted Chain Inactive (env ON). Not occupied-slot replace.
pub const S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT: u32 = 3;
pub const S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HEADER: u32 = 0;
pub const S19K_LIVE436_WRAP_RETIRE_MEETS: u32 = 0;
pub const S19K_LIVE436_WRAP_RETIRE_CLEANS: u32 = 0;

pub fn s19k_leftover_hit_admits_experimental_inactive(
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
) -> bool {
    // live439 leftover_hit=216 leftover_header=1: leftover_header is
    // remapped leftover and must not veto 21 36 wire leftover. leftover_
    // header-only (leftover_hit=0) still refuses (live438 leftover_header=3).
    let _ = leftover_header;
    leftover_hit > 0 && meets == 0
}

/// Occupied-slot replace is proven only after leftover-admitted inactive
/// ran and new-target meets outnumber leftover 21 36 hits.
/// live431 leftover_hit=4 meets=0 is admit-for-inactive, not replace.
/// live433 leftover_hit=0 meets=0 inactive=0 is measurement, not replace.
pub fn s19k_leftover_hit_vs_meets_replace_proven(
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
    leftover_admitted_inactive_queued: bool,
) -> bool {
    leftover_admitted_inactive_queued && leftover_header == 0 && meets > leftover_hit
}

/// Replace bar after leftover-admitted inactive. Pre-flush leftover_hit
/// (live431=4) only admits the flush. Post-flush leftover/meets must be
/// a new measurement — mixing them is not replace proof.
pub fn s19k_post_inactive_replace_proven(
    leftover_at_inactive: Option<u32>,
    leftover_hit_after: u32,
    leftover_header_after: u32,
    meets_after: u32,
) -> bool {
    matches!(leftover_at_inactive, Some(hit) if hit > 0)
        && leftover_header_after == 0
        && meets_after > leftover_hit_after
}

/// live438: leftover-admitted CMD=3 reset leftover_hit. leftover_hit=0
/// after that reset with meets=0 is the flush measurement, not replace.
/// leftover_header after flush is remapped leftover, not 21 36 leftover_hit.
pub fn s19k_post_inactive_flush_measured_not_replace(
    leftover_at_inactive: Option<u32>,
    leftover_hit_after: u32,
    leftover_header_after: u32,
    meets_after: u32,
) -> bool {
    let _ = leftover_header_after;
    matches!(leftover_at_inactive, Some(hit) if hit > 0)
        && leftover_hit_after == 0
        && meets_after == 0
}

/// leftover-admit flush measurement and occupied-slot replace cannot
/// both be true. live438 leftover_hit=0 meets=0 is flush only.
pub fn s19k_flush_measured_is_not_replace(flush_measured: bool, replace_proven: bool) -> bool {
    !(flush_measured && replace_proven)
}

/// leftover_header is remapped leftover that did **not** hash a retired
/// 21 36 wire. live438 leftover_header=3 leftover_hit=0 after leftover-
/// admit. It must not increment leftover_hit and must not leftover-admit
/// a second Chain Inactive.
pub fn s19k_leftover_header_is_not_tx_leftover(
    retired_header_meets: bool,
    retired_tx_meets: bool,
) -> bool {
    retired_header_meets && !retired_tx_meets
}

/// After leftover-admit leftover_at Some, leftover_hit hunts wrap-4 leftover
/// `55 AA 21 36` across every fill job_id. live448 leftover_hit=0 leftover_
/// header=8: remapped leftover_header climbed while wrap-4 leftover TX sat
/// on other job_ids than the remapped retry_slots. leftover_header-only
/// still refuses a second CMD=3.
pub fn s19k_leftover_hit_slots_after_leftover_admit(
    leftover_at: Option<u32>,
    retry_slots: &[u8],
) -> Vec<u8> {
    if leftover_at.is_some_and(|hit| hit > 0) {
        (0u8..=255).collect()
    } else {
        retry_slots.to_vec()
    }
}

pub fn s19k_append_unique_share_targets(dst: &mut Vec<[u8; 32]>, src: &[[u8; 32]]) {
    for t in src {
        if !dst.iter().any(|x| x == t) {
            dst.push(*t);
        }
    }
}

/// leftover_header-only after leftover-admit cannot leftover-admit again.
/// leftover_hit wire leftover still admits even if leftover_header>0.
pub fn s19k_leftover_header_admits_second_cmd3(
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
) -> bool {
    leftover_header > 0
        && leftover_hit == 0
        && s19k_leftover_hit_admits_experimental_inactive(leftover_hit, leftover_header, meets)
}

pub fn refuse_s19k_live438_header_leftover_as_second_cmd3() -> Result<(), &'static str> {
    if s19k_leftover_header_admits_second_cmd3(0, 3, 0) {
        return Err("live438 leftover_header=3 leftover_hit=0 must not leftover-admit again");
    }
    let plan = s19k_plan_post_clean_uart_replace(true, true, true, 0, 3, 0);
    if plan.chain_inactive || plan.job_flip {
        return Err("post-flush leftover_header must not queue a second CMD=3 or job flip");
    }
    if s19k_leftover_header_is_not_tx_leftover(true, true) {
        return Err("header leftover requires retired_tx_meets=false");
    }
    if !s19k_leftover_header_is_not_tx_leftover(true, false) {
        return Err("retired_header_meets && !retired_tx_meets is leftover_header");
    }
    Err("live438 leftover_header after leftover-admit is remapped leftover, not a second CMD=3")
}

pub fn refuse_s19k_live438_post_flush_leftover0_as_replace() -> Result<(), &'static str> {
    if s19k_post_inactive_replace_proven(
        Some(crate::s19k_braiins_chain_discover::S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HIT),
        crate::s19k_braiins_chain_discover::S19K_LIVE438_POST_FLUSH_LEFTOVER_HIT,
        3,
        crate::s19k_braiins_chain_discover::S19K_LIVE438_POST_FLUSH_MEETS,
    ) {
        return Err("live438 leftover_hit=0 leftover_header=3 meets=0 must not be replace");
    }
    if !s19k_post_inactive_flush_measured_not_replace(
        Some(crate::s19k_braiins_chain_discover::S19K_LIVE438_WRAP4_ADMIT_LEFTOVER_HIT),
        crate::s19k_braiins_chain_discover::S19K_LIVE438_POST_FLUSH_LEFTOVER_HIT,
        3,
        crate::s19k_braiins_chain_discover::S19K_LIVE438_POST_FLUSH_MEETS,
    ) {
        return Err("live438 leftover_hit=0 after leftover-admit is flush measurement");
    }
    if !s19k_flush_measured_is_not_replace(true, false) {
        return Err("flush measurement must not count as replace");
    }
    Err(
        "live438 leftover_hit=0 after leftover-admitted CMD=3 is flush measurement, not meets>leftover replace",
    )
}

pub fn admit_s19k_second_clean_plans_from_pre_reset_leftover() -> Result<(), &'static str> {
    let mut funnel = crate::S19kCleanFunnel::default();
    funnel.on_clean();
    funnel.leftover_hit = S19K_LIVE431_LEFTOVER_HIT;
    funnel.leftover_header = S19K_LIVE431_LEFTOVER_HEADER;
    funnel.meets = S19K_LIVE431_MEETS;
    let (hit, header, meets) = funnel.snapshot_for_post_clean_plan();
    funnel.on_clean();
    if funnel.leftover_hit != 0 || funnel.meets != 0 {
        return Err("on_clean must wipe leftover/meets before the new generation");
    }
    let plan = s19k_plan_post_clean_uart_replace(true, true, true, hit, header, meets);
    if !plan.chain_inactive || !plan.job_flip {
        return Err("second clean must plan from pre-reset leftover_hit=4, not post-reset 0");
    }
    funnel.on_leftover_admitted_inactive();
    if funnel.leftover_hit != 0 || funnel.meets != 0 || funnel.cleans != 2 {
        return Err("post-inactive reset must wipe leftover/meets and not increment cleans");
    }
    if s19k_leftover_hit_vs_meets_replace_proven(hit, header, meets, true) {
        return Err("pre-flush leftover_hit=4 / meets=0 is not the post-inactive replace bar");
    }
    if !s19k_post_inactive_replace_proven(Some(hit), 0, 0, 5) {
        return Err("post-inactive meets>leftover is the occupied-slot replace bar");
    }
    if s19k_post_inactive_replace_proven(None, 0, 0, 5) {
        return Err("meets without leftover-admitted inactive is not replace");
    }
    Ok(())
}

pub fn admit_s19k_live431_leftover_vs_meets_unproven() -> Result<(), &'static str> {
    if s19k_leftover_hit_vs_meets_replace_proven(
        S19K_LIVE431_LEFTOVER_HIT,
        S19K_LIVE431_LEFTOVER_HEADER,
        S19K_LIVE431_MEETS,
        false,
    ) {
        return Err(
            "live431 leftover_hit=4 meets=0 without leftover-admitted inactive is not replace",
        );
    }
    if s19k_leftover_hit_vs_meets_replace_proven(4, 0, 0, true) {
        return Err("live431 meets=0 stays unproven even if inactive had queued");
    }
    if !s19k_leftover_hit_vs_meets_replace_proven(1, 0, 4, true) {
        return Err("meets>leftover after leftover-admitted inactive is the replace bar");
    }
    Ok(())
}

pub fn admit_s19k_live433_leftover_vs_meets_unproven() -> Result<(), &'static str> {
    if s19k_leftover_hit_vs_meets_replace_proven(0, 0, 0, false) {
        return Err("live433 leftover_hit=0 meets=0 inactive=0 is not occupied-slot replace");
    }
    Ok(())
}

/// live436 wrap-retire leftover_hit=3 / header=0 / meets=0 is the same
/// leftover-admit bar as live431 leftover_hit=4, but it is measured
/// **before** the first pool clean (funnel unarmed). Session-start
/// clean still stays identity (midrun_clean=false).
pub fn admit_s19k_live436_wrap_retire_leftover_admits_first_clean_inactive(
) -> Result<(), &'static str> {
    if S19K_LIVE436_WRAP_RETIRE_CLEANS != 0 {
        return Err("live436 wrap-retire leftover is before the first mid-run clean");
    }
    if S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT != 3 {
        return Err("live436 wrap-retire leftover_hit must stay 3");
    }
    if S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HEADER != 0 {
        return Err("live436 leftover_header must stay 0 (21 36 wire, not header)");
    }
    if S19K_LIVE436_WRAP_RETIRE_MEETS != 0 {
        return Err("live436 first-fill meets stay funnel-only so leftover-admit is not blocked");
    }
    if !s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT,
        S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HEADER,
        S19K_LIVE436_WRAP_RETIRE_MEETS,
    ) {
        return Err(
            "live436 wrap-retire leftover_hit=3 / header=0 / meets=0 admits experimental inactive",
        );
    }
    let session = s19k_plan_post_clean_uart_replace(false, true, true, 3, 0, 0);
    if session.chain_inactive || session.job_flip {
        return Err("session-start leftover_hit=3 must not queue inactive (live432 class)");
    }
    let first = s19k_plan_post_clean_uart_replace(true, true, true, 3, 0, 0);
    if !first.chain_inactive || !first.job_flip {
        return Err(
            "first mid-run clean with wrap-retire leftover_hit=3 must leftover-admit flip+inactive",
        );
    }
    let production = s19k_plan_post_clean_uart_replace(true, false, false, 3, 0, 0);
    if production.chain_inactive || production.job_flip {
        return Err("production first clean stays identity refill");
    }
    if s19k_leftover_hit_vs_meets_replace_proven(3, 0, 0, first.chain_inactive) {
        return Err("wrap-retire leftover-admitted inactive is not occupied-slot replace");
    }
    Ok(())
}

pub fn admit_s19k_live431_leftover_admits_experimental_inactive() -> Result<(), &'static str> {
    if S19K_LIVE431_LEFTOVER_HIT != 4 {
        return Err("live431 leftover_hit must stay 4");
    }
    if S19K_LIVE431_LEFTOVER_HEADER != 0 {
        return Err("live431 leftover_header must stay 0 (21 36 wire, not header)");
    }
    if S19K_LIVE431_MEETS != 0 {
        return Err("live431 meets must stay 0 (occupied-slot replace unproven)");
    }
    if S19K_LIVE431_LEFTOVER_NONCE != 0x3C6C_D199 {
        return Err("live431 leftover dump nonce must stay 0x3C6CD199");
    }
    if !s19k_leftover_hit_admits_experimental_inactive(
        S19K_LIVE431_LEFTOVER_HIT,
        S19K_LIVE431_LEFTOVER_HEADER,
        S19K_LIVE431_MEETS,
    ) {
        return Err("live431 leftover_hit=4 / header=0 / meets=0 admits experimental inactive");
    }
    Ok(())
}

/// One leftover-safe UART step after a mid-run clean. There is no held
/// job-abort opcode; Chain Inactive is the only documented chip-side flush.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kPostCleanUartOp {
    ChainInactive,
    IdentityRefill,
}

/// Ordered leftover-safe UART replace plan. Production is identity 21 36
/// refill only. Chain Inactive / job-id XOR stay experimental default-OFF.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kPostCleanUartReplacePlan {
    pub chain_inactive: bool,
    pub job_flip: bool,
    pub refill: bool,
}

impl S19kPostCleanUartReplacePlan {
    pub fn ops(self) -> impl Iterator<Item = S19kPostCleanUartOp> {
        [
            self.chain_inactive
                .then_some(S19kPostCleanUartOp::ChainInactive),
            self.refill.then_some(S19kPostCleanUartOp::IdentityRefill),
        ]
        .into_iter()
        .flatten()
    }
}

/// Plan leftover-safe UART after a mid-run clean.
///
/// Held ESP + `bm1366_protocol.md`: TYPE_JOB + four CMD_* only. CMD=3 is
/// Chain Inactive (`55 AA 53 05 00 00 03`). No abort/invalidate opcode.
/// `midrun_clean == false` emits no extra UART (session-start first-fill).
/// live431 leftover_hit is measured **after** the first mid-run clean;
/// env-ON alone must not queue inactive **or XOR 0x80** on leftover_hit=0
/// (live432 first-clean inactive class).
pub fn s19k_plan_post_clean_uart_replace(
    midrun_clean: bool,
    experimental_chain_inactive: bool,
    experimental_job_flip: bool,
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
) -> S19kPostCleanUartReplacePlan {
    if !midrun_clean {
        return S19kPostCleanUartReplacePlan {
            chain_inactive: false,
            job_flip: false,
            refill: false,
        };
    }
    let leftover_admitted =
        s19k_leftover_hit_admits_experimental_inactive(leftover_hit, leftover_header, meets);
    S19kPostCleanUartReplacePlan {
        chain_inactive: experimental_chain_inactive && leftover_admitted,
        job_flip: experimental_job_flip && leftover_admitted,
        refill: true,
    }
}

/// live432 first-clean inactive at leftover_hit=0. XOR 0x80 is the same
/// class: leftover-safe host mapping only after leftover_hit admits.
pub fn admit_s19k_job_flip_is_leftover_admitted() -> Result<(), &'static str> {
    let first = s19k_plan_post_clean_uart_replace(true, true, true, 0, 0, 0);
    if first.job_flip || first.chain_inactive {
        return Err("first clean leftover_hit=0 must not flip or inactive (live432 class)");
    }
    if !first.refill {
        return Err("first clean still identity-refills");
    }
    let admitted = s19k_plan_post_clean_uart_replace(true, true, true, 4, 0, 0);
    if !admitted.job_flip || !admitted.chain_inactive {
        return Err("live431 leftover_hit=4 / header=0 / meets=0 admits flip+inactive");
    }
    let production = s19k_plan_post_clean_uart_replace(true, false, false, 4, 0, 0);
    if production.job_flip || production.chain_inactive {
        return Err("production post-clean stays identity refill");
    }
    if s19k_leftover_hit_vs_meets_replace_proven(4, 0, 0, admitted.chain_inactive) {
        return Err("leftover-admitted flip+inactive is not occupied-slot replace proof");
    }
    Ok(())
}

/// live428/430/434 MULTI died wrap-4 before a live leftover measurement.
/// Production does nothing extra (fill identity continues). Experimental
/// wrap-4 early leftover-safe is due only while RX is still live and
/// leftover-admit has not set leftover_at. Session-start funnel `cleans=1`
/// is not leftover-admit (live446 leftover_hit=20 leftover_at=None).
pub const S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN_ENV: &str =
    "DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN";

pub fn s19k_experimental_wrap4_early_clean_enabled_from_env(raw: Option<&str>) -> bool {
    raw == Some("1")
}

pub fn s19k_wrap4_early_leftover_safe_due(
    wrap_rx: u64,
    leftover_at: Option<u32>,
    rx_dead: bool,
) -> bool {
    wrap_rx >= 4 && leftover_at.is_none() && !rx_dead
}

/// IMPLEMENTED_EXPERIMENTAL wrap-4 leftover-safe step.
/// Production (`experimental=false`) is empty — fill identity continues.
/// First due snapshot/arm is `refill=true` (no extra abort opcode).
/// Chain Inactive only after leftover_hit admits (same bar as post-clean).
pub fn s19k_plan_wrap4_early_leftover_safe(
    wrap_rx: u64,
    leftover_at: Option<u32>,
    rx_dead: bool,
    experimental: bool,
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
    already_snapshotted: bool,
) -> S19kPostCleanUartReplacePlan {
    if !experimental || !s19k_wrap4_early_leftover_safe_due(wrap_rx, leftover_at, rx_dead) {
        return S19kPostCleanUartReplacePlan {
            chain_inactive: false,
            job_flip: false,
            refill: false,
        };
    }
    if !already_snapshotted {
        // live437: leftover_hit=4 leftover_header=0 at snapshot. Waiting a
        // second tick let leftover_header climb (retired history after
        // on_clean) and blocked leftover-admit. Same-tick admit uses the
        // wrap-retire leftover bar, not the post-arm header leftover.
        let leftover_admitted =
            s19k_leftover_hit_admits_experimental_inactive(leftover_hit, leftover_header, meets);
        return S19kPostCleanUartReplacePlan {
            chain_inactive: leftover_admitted,
            job_flip: false,
            refill: true,
        };
    }
    s19k_plan_post_clean_uart_replace(true, true, false, leftover_hit, leftover_header, meets)
}

pub fn admit_s19k_live434_wrap4_early_clean_was_due() -> Result<(), &'static str> {
    if !s19k_wrap4_early_leftover_safe_due(4, None, false) {
        return Err("live434 wrap_rx=4 leftover_at=None with RX live admits wrap-4 early clean");
    }
    if s19k_wrap4_early_leftover_safe_due(4, None, true) {
        return Err("wrap-4 early clean must not fire after RX death");
    }
    if s19k_wrap4_early_leftover_safe_due(3, None, false) {
        return Err("wrap-3 is not wrap-4 early clean");
    }
    if s19k_wrap4_early_leftover_safe_due(4, Some(1), false) {
        return Err("wrap-4 early must not fire after leftover-admit leftover_at");
    }
    let production = s19k_plan_wrap4_early_leftover_safe(4, None, false, false, 0, 0, 0, false);
    if production.refill || production.chain_inactive {
        return Err("production wrap-4 stays fill-identity (no extra UART)");
    }
    let first = s19k_plan_wrap4_early_leftover_safe(4, None, false, true, 0, 0, 0, false);
    if !first.refill || first.chain_inactive {
        return Err("experimental first wrap-4 step is identity snapshot, not inactive");
    }
    let after = s19k_plan_wrap4_early_leftover_safe(4, None, false, true, 4, 0, 0, true);
    if !after.chain_inactive {
        return Err("leftover-admitted wrap-4 may queue experimental inactive");
    }
    let header_only = s19k_plan_wrap4_early_leftover_safe(4, None, false, true, 0, 5, 0, true);
    if header_only.chain_inactive {
        return Err("leftover_header-only after snapshot must not leftover-admit");
    }
    let live439_wire = s19k_plan_wrap4_early_leftover_safe(4, None, false, true, 4, 5, 0, true);
    if !live439_wire.chain_inactive {
        return Err("leftover_hit wire leftover must leftover-admit even if leftover_header>0");
    }
    Ok(())
}

/// live436 leftover_hit=3 leftover_header=0 at wrap_rx=4 with RX live.
/// Experimental wrap-4 first tick is snapshot only. Second tick leftover-
/// admits Chain Inactive. Production (`experimental=false`) stays empty.
pub fn admit_s19k_live436_leftover3_wrap4_early_admits_inactive() -> Result<(), &'static str> {
    if !s19k_experimental_wrap4_early_clean_enabled_from_env(Some("1")) {
        return Err("wrap-4 early env 1 must enable the experimental path");
    }
    if s19k_experimental_wrap4_early_clean_enabled_from_env(None) {
        return Err("production wrap-4 early stays default OFF");
    }
    if s19k_experimental_wrap4_early_clean_enabled_from_env(Some("0")) {
        return Err("wrap-4 early env 0 is off");
    }
    let first = s19k_plan_wrap4_early_leftover_safe(
        4,
        None,
        false,
        true,
        S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT,
        S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HEADER,
        S19K_LIVE436_WRAP_RETIRE_MEETS,
        false,
    );
    if !first.refill || !first.chain_inactive {
        return Err("live436 leftover_hit=3 wrap-4 first tick leftover-admits same tick (live437 header climb)");
    }
    let after = s19k_plan_wrap4_early_leftover_safe(
        4,
        None,
        false,
        true,
        S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HIT,
        S19K_LIVE436_WRAP_RETIRE_LEFTOVER_HEADER,
        S19K_LIVE436_WRAP_RETIRE_MEETS,
        true,
    );
    if !after.chain_inactive || after.job_flip {
        return Err("live436 leftover_hit=3 at wrap-4 leftover-admits inactive only (no flip)");
    }
    let production = s19k_plan_wrap4_early_leftover_safe(4, None, false, false, 3, 0, 0, true);
    if production.refill || production.chain_inactive {
        return Err("production wrap-4 stays fill-identity even with leftover_hit=3");
    }
    if s19k_leftover_hit_vs_meets_replace_proven(3, 0, 0, after.chain_inactive) {
        return Err("wrap-4 leftover-admitted inactive is not occupied-slot replace");
    }
    Ok(())
}

/// live437 wrap-4 snapshot leftover_hit=4 leftover_header=0. Waiting for
/// the next tick let leftover_header climb to 5 and refused leftover-admit.
pub fn admit_s19k_live437_wrap4_same_tick_admits_before_header_climb() -> Result<(), &'static str> {
    let snap = s19k_plan_wrap4_early_leftover_safe(4, None, false, true, 4, 0, 0, false);
    if !snap.refill || !snap.chain_inactive {
        return Err(
            "live437 leftover_hit=4 leftover_header=0 must leftover-admit on the snapshot tick",
        );
    }
    let header_only = s19k_plan_wrap4_early_leftover_safe(4, None, false, true, 0, 5, 0, true);
    if header_only.chain_inactive {
        return Err("leftover_header-only after funnel arm must not leftover-admit");
    }
    let later = s19k_plan_wrap4_early_leftover_safe(4, None, false, true, 4, 5, 0, true);
    if !later.chain_inactive {
        return Err("live439 leftover_hit=4 leftover_header=5 must leftover-admit (wire leftover)");
    }
    Ok(())
}

/// Production wrap-4 leftover-admit must log the snapshot leftover_hit
/// (`admit_hit`) before `on_leftover_admitted_inactive` wipes it to 0.
pub fn admit_s19k_production_wrap4_logs_snapshot_leftover(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("if wrap4_plan.chain_inactive {")
        .ok_or("production must keep the wrap-4 chain-inactive planner arm")?;
    let tail = &src[start..];
    let end = tail
        .find("if s19k_wrap5_leftover_snapshot_due(")
        .ok_or("wrap-4 chain-inactive planner arm must precede the wrap-5 snapshot arm")?;
    let arm: String = tail[..end]
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect();

    let snapshot = arm
        .find("letadmit_hit=clean_funnel.leftover_hit;")
        .ok_or("wrap-4 leftover-admit must snapshot leftover_hit before the post-flush wipe")?;
    let wipe = arm
        .find("clean_funnel.on_leftover_admitted_inactive();")
        .ok_or("wrap-4 leftover-admit must mark the funnel after snapshotting leftover_hit")?;
    if snapshot > wipe {
        return Err("wrap-4 leftover-admit must snapshot leftover_hit before the post-flush wipe");
    }

    let queue = arm
        .find("push_front(SerialQueuedTx::control(S19K_BM1366_CHAIN_INACTIVE_BODY.to_vec()")
        .ok_or(
            "wrap-4 leftover-admit must queue typed control 53 05 00 00 after the funnel wipe",
        )?;
    if queue < wipe {
        return Err("wrap-4 leftover-admit must queue 53 05 00 00 after the funnel wipe");
    }

    let log = arm
        .find("S19kwrap-4leftover-admittedchain-inactive(experimental)")
        .ok_or("wrap-4 leftover-admit must log the experimental CMD=3 queue")?;
    if log < queue {
        return Err("wrap-4 leftover-admit must log only after queuing 53 05 00 00");
    }
    if !arm[..log].contains("leftover_hit=admit_hit,") {
        return Err("wrap-4 leftover-admit log must print admit_hit, not the wiped 0");
    }
    Ok(())
}

/// live441 leftover-admit leftover_hit=4 leftover_at=4 leftover_header=0;
/// MULTI died wrap_rx=6 leftover_hit=0 leftover_header=4 before wrap-7
/// snapshot was due. Snapshot POST-admit outstanding 21 36 at wrap_rx>=5
/// so leftover_hit can re-accumulate during wrap 5 while still hashing.
/// leftover-readmit still requires leftover_hit>0 (leftover_header-only refuses).
pub fn s19k_wrap5_leftover_snapshot_due(
    wrap_rx: u64,
    leftover_at_inactive: Option<u32>,
    already_snapshotted: bool,
    rx_dead: bool,
    experimental: bool,
) -> bool {
    experimental
        && !already_snapshotted
        && !rx_dead
        && wrap_rx >= 5
        && matches!(leftover_at_inactive, Some(hit) if hit > 0)
}

/// live441 wrap-6 death after leftover-admit left leftover-readmit at
/// wrap_rx>=7 unqueued. After wrap-5 POST-admit snapshot, leftover-readmit
/// as soon as leftover_hit admits (wrap_rx>=5) so the second CMD=3 can
/// fire before wrap-6 MULTI death. leftover_header-only still refuses.
pub fn s19k_wrap5_leftover_readmit_due(
    wrap_rx: u64,
    leftover_at_inactive: Option<u32>,
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
    already_readmitted: bool,
    rx_dead: bool,
    experimental: bool,
) -> bool {
    experimental
        && !already_readmitted
        && !rx_dead
        && wrap_rx >= 5
        && matches!(leftover_at_inactive, Some(hit) if hit > 0)
        && s19k_leftover_hit_admits_experimental_inactive(leftover_hit, leftover_header, meets)
}

/// live441 wrap_rx=6 leftover_at=4 leftover_hit=0 leftover_header=4:
/// wrap-5 would have snapshotted POST-admit 21 36; leftover-readmit
/// still refuses header-only until leftover_hit re-accumulates.
pub fn admit_s19k_live441_wrap5_snapshots_before_wrap6_death() -> Result<(), &'static str> {
    if s19k_wrap5_leftover_snapshot_due(5, Some(4), false, false, false) {
        return Err("production wrap-5 leftover snapshot stays default OFF");
    }
    if s19k_wrap5_leftover_snapshot_due(4, Some(4), false, false, true) {
        return Err("wrap-4 is leftover-admit, not wrap-5 leftover snapshot");
    }
    if s19k_wrap5_leftover_snapshot_due(5, None, false, false, true) {
        return Err("wrap-5 leftover snapshot requires a prior leftover-admit");
    }
    if !s19k_wrap5_leftover_snapshot_due(5, Some(4), false, false, true) {
        return Err("live441 wrap_rx=5 leftover_at=4 must snapshot POST-admit 21 36");
    }
    if s19k_wrap5_leftover_readmit_due(5, Some(4), 0, 4, 0, false, false, true) {
        return Err("live441 leftover_hit=0 leftover_header=4 must not leftover-readmit");
    }
    if !s19k_wrap5_leftover_readmit_due(5, Some(4), 4, 0, 0, false, false, true) {
        return Err("after wrap-5 snapshot leftover_hit re-accumulation leftover-readmits");
    }
    if s19k_wrap7_leftover_snapshot_due(6, Some(4), false, false, true) {
        return Err("wrap-6 is still not wrap-7 leftover snapshot");
    }
    Ok(())
}

/// Production wrap-5 leftover snapshot must log and queue leftover-readmit.
pub fn admit_s19k_production_wrap5_snapshot_logs_and_queues(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_wrap5_leftover_snapshot_due(") {
        return Err("production must call wrap-5 leftover snapshot due");
    }
    if !src.contains("S19k wrap-5 leftover snapshot (experimental)") {
        return Err("wrap-5 leftover snapshot must log the POST-admit retired store");
    }
    if !src.contains("s19k_wrap5_leftover_readmit_due(") {
        return Err("production must call wrap-5 leftover-readmit due");
    }
    if !src.contains("S19k wrap-5 leftover-readmit chain-inactive (experimental)") {
        return Err("wrap-5 leftover-readmit must log the experimental CMD=3 queue");
    }
    if !src.contains("wrap5_leftover_readmitted") {
        return Err("wrap-5 leftover-readmit must not consume wrap-7 leftover-readmit");
    }
    if src
        .matches("retired_s19k_history.merge_from(&work_history)")
        .count()
        < 2
    {
        return Err("wrap-5 leftover snapshot must merge POST-admit history into wrap-4 leftover share_targets (live448 leftover_hit=0 leftover_header=8)");
    }
    if src
        .matches("retired_s19k_tx.merge_from(&outstanding_s19k_tx)")
        .count()
        < 2
    {
        return Err("wrap-4/wrap-5 leftover snapshot must merge outstanding into retired generations (live443 clone() leftover_hit=0)");
    }
    if !src.contains("s19k_retired_generation_tx_meets_any_share_target") {
        return Err("leftover_hit must compact-TX-meet wrap-4 leftover 21 36 against retired share_target (live444 leftover_header=4 leftover_hit=0)");
    }
    Ok(())
}

/// live440 leftover_hit=0 leftover_header=3 wrap_rx=7 leftover-readmit refuse.
/// leftover_hit wire leftover still leftover-readmits.
pub fn admit_s19k_live440_header_only_refuses_leftover_hit_still_admits() -> Result<(), &'static str>
{
    if s19k_leftover_header_admits_second_cmd3(0, 3, 0) {
        return Err("live440 leftover_header=3 leftover_hit=0 must not leftover-admit again");
    }
    if s19k_wrap7_leftover_readmit_due(7, Some(1), 0, 3, 0, false, false, true) {
        return Err("live440 leftover_header-only must not wrap-7 leftover-readmit");
    }
    if !s19k_leftover_hit_admits_experimental_inactive(4, 3, 0) {
        return Err("leftover_hit wire leftover still admits even if leftover_header>0");
    }
    if !s19k_wrap5_leftover_readmit_due(5, Some(3), 4, 4, 0, false, false, true) {
        return Err("after leftover-admit leftover_hit re-accumulation leftover-readmits");
    }
    if s19k_wrap5_leftover_readmit_due(5, Some(3), 0, 4, 0, false, false, true) {
        return Err("live444 leftover_header=4 leftover_hit=0 must not wrap-5 leftover-readmit");
    }
    if s19k_leftover_hit_slots_after_leftover_admit(None, &[7]).as_slice() != [7] {
        return Err("before leftover-admit leftover_hit hunts retry_slots only");
    }
    if s19k_leftover_hit_slots_after_leftover_admit(Some(1), &[7]).len() != 256 {
        return Err(
            "after leftover-admit leftover_hit hunts wrap-4 leftover 21 36 on every job_id",
        );
    }
    Ok(())
}

/// live440 leftover-admit flushed leftover_hit. wrap-7 leftover-readmit
/// hunted the **pre-admit** retired 21 36 store, so leftover_hit stayed 0
/// leftover_header=3. Snapshot POST-admit outstanding 21 36 into retired
/// at wrap_rx>=7 so leftover_hit can re-accumulate from wrap-retire leftover.
/// leftover-readmit still requires leftover_hit>0 (leftover_header-only refuses).
pub fn s19k_wrap7_leftover_snapshot_due(
    wrap_rx: u64,
    leftover_at_inactive: Option<u32>,
    already_snapshotted: bool,
    rx_dead: bool,
    experimental: bool,
) -> bool {
    experimental
        && !already_snapshotted
        && !rx_dead
        && wrap_rx >= 7
        && matches!(leftover_at_inactive, Some(hit) if hit > 0)
}

/// live447 wrap-5 leftover-readmit leftover_hit=1 leftover_header=0 wrap_rx=5;
/// leftover_hit re-accumulated to 185 leftover_header=2 leftover_at=9 wrap_rx=6
/// before MULTI death. wrap-7 leftover-readmit requires wrap_rx>=7 so it never
/// queued. wrap-6 leftover-readmit is the leftover-safe second CMD=3 while RX
/// is still in the wrap-6 window. leftover_header-only still refuses.
pub fn s19k_wrap6_leftover_readmit_due(
    wrap_rx: u64,
    leftover_at_inactive: Option<u32>,
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
    already_readmitted: bool,
    rx_dead: bool,
    experimental: bool,
) -> bool {
    experimental
        && !already_readmitted
        && !rx_dead
        && wrap_rx >= 6
        && matches!(leftover_at_inactive, Some(hit) if hit > 0)
        && s19k_leftover_hit_admits_experimental_inactive(leftover_hit, leftover_header, meets)
}

/// live439 wrap-7 still hashed after leftover-admit, then leftover_hit
/// re-accumulated (216) with leftover_header=1 after a second identity
/// clean. wrap-4 due requires leftover_at=None so it cannot leftover-admit
/// again. Experimental wrap-7 leftover-readmit is the leftover-safe second
/// flush at wrap_rx>=7.
pub fn s19k_wrap7_leftover_readmit_due(
    wrap_rx: u64,
    leftover_at_inactive: Option<u32>,
    leftover_hit: u32,
    leftover_header: u32,
    meets: u32,
    already_readmitted: bool,
    rx_dead: bool,
    experimental: bool,
) -> bool {
    experimental
        && !already_readmitted
        && !rx_dead
        && wrap_rx >= 7
        && matches!(leftover_at_inactive, Some(hit) if hit > 0)
        && s19k_leftover_hit_admits_experimental_inactive(leftover_hit, leftover_header, meets)
}

/// live439 leftover_hit=216 leftover_header=1 at wrap_rx=7 after
/// leftover-admit leftover_at=2. leftover_header must not veto.
pub fn admit_s19k_live439_wrap7_leftover_readmit() -> Result<(), &'static str> {
    if s19k_wrap7_leftover_readmit_due(7, Some(2), 216, 1, 0, false, false, false) {
        return Err("production wrap-7 leftover-readmit stays default OFF");
    }
    if s19k_wrap7_leftover_readmit_due(6, Some(2), 216, 1, 0, false, false, true) {
        return Err("wrap-6 is not wrap-7 leftover-readmit");
    }
    if s19k_wrap7_leftover_readmit_due(7, None, 216, 1, 0, false, false, true) {
        return Err("wrap-7 leftover-readmit requires a prior leftover-admit flush");
    }
    if s19k_wrap7_leftover_readmit_due(7, Some(2), 0, 3, 0, false, false, true) {
        return Err("live438 leftover_header-only after flush must not wrap-7 leftover-readmit");
    }
    if s19k_wrap7_leftover_readmit_due(7, Some(2), 216, 1, 0, true, false, true) {
        return Err("wrap-7 leftover-readmit is once per soak");
    }
    if s19k_wrap7_leftover_readmit_due(7, Some(2), 216, 1, 0, false, true, true) {
        return Err("wrap-7 leftover-readmit must not fire after RX death");
    }
    if !s19k_wrap7_leftover_readmit_due(7, Some(2), 216, 1, 0, false, false, true) {
        return Err("live439 leftover_hit=216 leftover_header=1 at wrap_rx=7 leftover-readmits");
    }
    if s19k_leftover_hit_vs_meets_replace_proven(216, 1, 0, true) {
        return Err("wrap-7 leftover-readmit is not occupied-slot replace");
    }
    Ok(())
}

/// live440 wrap_rx=7 leftover_at=1 leftover_hit=0 leftover_header=3:
/// snapshot POST-admit 21 36; leftover-readmit still refuses header-only.
pub fn admit_s19k_live440_wrap7_snapshots_post_admit_store() -> Result<(), &'static str> {
    if s19k_wrap7_leftover_snapshot_due(7, Some(1), false, false, false) {
        return Err("production wrap-7 leftover snapshot stays default OFF");
    }
    if s19k_wrap7_leftover_snapshot_due(6, Some(1), false, false, true) {
        return Err("wrap-6 is not wrap-7 leftover snapshot");
    }
    if s19k_wrap7_leftover_snapshot_due(7, None, false, false, true) {
        return Err("wrap-7 leftover snapshot requires a prior leftover-admit");
    }
    if !s19k_wrap7_leftover_snapshot_due(7, Some(1), false, false, true) {
        return Err("live440 wrap_rx=7 leftover_at=1 must snapshot POST-admit 21 36");
    }
    if s19k_wrap7_leftover_readmit_due(7, Some(1), 0, 3, 0, false, false, true) {
        return Err("live440 leftover_hit=0 leftover_header=3 must not leftover-readmit");
    }
    if !s19k_wrap7_leftover_readmit_due(7, Some(1), 4, 0, 0, false, false, true) {
        return Err("after wrap-7 snapshot leftover_hit re-accumulation leftover-readmits");
    }
    Ok(())
}

/// Production wrap-7 leftover-readmit must log admit_hit and queue CMD=3.
pub fn admit_s19k_production_wrap7_readmit_logs_and_queues(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_wrap7_leftover_readmit_due(") {
        return Err("production must call wrap-7 leftover-readmit due");
    }
    if !src.contains("S19k wrap-7 leftover-readmit chain-inactive (experimental)") {
        return Err("wrap-7 leftover-readmit must log the experimental CMD=3 queue");
    }
    if !src.contains("wrap7_leftover_readmitted") {
        return Err("wrap-7 leftover-readmit must be once per soak");
    }
    if !src.contains("s19k_wrap7_leftover_snapshot_due(") {
        return Err("wrap-7 leftover-readmit must snapshot POST-admit 21 36 first");
    }
    if !src.contains("S19k wrap-7 leftover snapshot (experimental)") {
        return Err("wrap-7 leftover snapshot must log the POST-admit retired store");
    }
    Ok(())
}

/// Held `.88` bosminer.unpacked: first `53 05 00 00` sits between
/// `52 05 00 00` and `54 05 00 00`. Sequential words, not `55 AA 53 05`.
pub const S19K_BOSMINER_53050000_NEIGHBOR: &[u8] = &[
    0x52, 0x05, 0x00, 0x00, 0x53, 0x05, 0x00, 0x00, 0x54, 0x05, 0x00, 0x00,
];

pub fn refuse_s19k_bosminer_53050000_as_chain_inactive_template() -> Result<(), &'static str> {
    if S19K_BOSMINER_53050000_NEIGHBOR
        .windows(6)
        .any(|w| w == [0x55, 0xAA, 0x53, 0x05, 0x00, 0x00])
    {
        return Err("neighbor slice must not contain a framed CMD=3");
    }
    if S19K_BOSMINER_53050000_NEIGHBOR[4] != 0x53 || S19K_BOSMINER_53050000_NEIGHBOR[0] != 0x52 {
        return Err("held neighbor is the incrementing 0x52/0x53/0x54 word table");
    }
    Err("bosminer 53 05 00 00 is a sequential table, not Chain Inactive UART")
}

/// AMTC S19k jig logs "Set chain inactive" then "Set asic address" — init
/// set-address, same as ESP. Not a mid-run leftover-safe abort.
pub fn refuse_s19k_jig_chain_inactive_log_as_midrun_abort() -> Result<(), &'static str> {
    Err("jig Set chain inactive is init/set-address; no 55 AA 21 36 job abort")
}

pub fn admit_s19k_live437_launch_wrap4_early_is_experimental(
    src: &str,
) -> Result<(), &'static str> {
    let active = src
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    if !active.contains("DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN=1") {
        return Err("live437 must export WRAP4_EARLY_CLEAN=1");
    }
    if !active.contains("DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE=1") {
        return Err("live437 leftover-admit still needs the inactive env");
    }
    if !src.contains("kill \"$OWNED\"") {
        return Err("live437 must kill only its owned pid");
    }
    Ok(())
}

/// Pin held protocol.md: CMD=3 chain Inactive is the only chip-side flush;
/// the document does not name a job abort.
pub fn admit_s19k_held_protocol_has_no_job_abort_opcode(src: &str) -> Result<(), &'static str> {
    let lower = src.to_ascii_lowercase();
    if lower.contains("abort") || lower.contains("invalidate") {
        return Err("held bm1366_protocol.md must not name a job abort/invalidate opcode");
    }
    if !src.contains("CMD = 3: chain Inactive") {
        return Err("held protocol.md must keep CMD = 3: chain Inactive");
    }
    if !src.contains("CMD = 0: set Chip Address")
        || !src.contains("CMD = 1: write Register")
        || !src.contains("CMD = 2: read Register")
    {
        return Err("held protocol.md must keep the four TYPE=2 CMD values");
    }
    if !src.contains("CMD = 1: send Job") {
        return Err("held protocol.md must keep TYPE=1 CMD=1 send Job");
    }
    Ok(())
}

/// Production default stays fill-identity re-fill. The post-clean
/// chain-inactive broadcast is a live-discriminator tool: only a dominant
/// `leftover_hit` funnel result (chips still hashing pre-clean generations)
/// justifies flushing chip work state on a mid-run clean.
pub fn refuse_s19k_post_clean_chain_inactive_as_production() -> Result<(), &'static str> {
    Err(
        "DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE is experimental; \
         CMD=3 is init/set-address (ESP/Bitmain), not a proven leftover-safe \
         mid-run abort; production re-fill stays fill identity",
    )
}

pub fn refuse_s19k_experimental_job_flip_as_chip_work_replace() -> Result<(), &'static str> {
    Err("XOR 0x80 is leftover-safe host mapping + implicit 21 36 overwrite; not a proven chip abort")
}

pub fn refuse_s19k_experimental_job_flip_as_production() -> Result<(), &'static str> {
    Err("DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP is experimental; production fill stays work_id")
}

/// Held AMTC S19k jig has no Closed11d job prefix (no UART abort job either).
pub fn s19k_jig_closed11d_prefix_hits(blob: &[u8]) -> usize {
    blob.windows(4)
        .filter(|w| w == &[JOB_PREAMBLE_0, JOB_PREAMBLE_1, JOB_CMD_TYPE, JOB_LEN_FIELD])
        .count()
}

pub fn admit_s19k_jig_has_no_closed11d_job(blob: &[u8]) -> Result<(), &'static str> {
    if s19k_jig_closed11d_prefix_hits(blob) != 0 {
        return Err("held S19k jig must not contain 55 AA 21 36");
    }
    Ok(())
}

pub fn refuse_s19k_jig_libc_abort_as_work_replace(blob: &[u8]) -> Result<(), &'static str> {
    let Some(off) = blob.windows(5).position(|w| w == b"abort") else {
        return Err("jig ELF should import libc abort");
    };
    let lo = off.saturating_sub(24);
    let hi = (off + 24).min(blob.len());
    let win = &blob[lo..hi];
    if win.windows(5).any(|w| w == b"stdin") || win.windows(7).any(|w| w == b"putchar") {
        return Err("jig abort is libc abort next to stdin/putchar; not a BM1366 work-replace");
    }
    let _ = off;
    Err("jig abort string is not a documented work-replace opcode")
}

/// Production serial_mining must keep the flip env-gated and default off.
pub fn admit_s19k_production_post_clean_job_flip_is_env_gated(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_fill_job_id") {
        return Err("serial_mining must assign Track-1 job_id via s19k_track1_fill_job_id");
    }
    if !src.contains("DCENT_S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP") {
        return Err("serial_mining must name the experimental post-clean job-flip env");
    }
    if !src.contains("s19k_experimental_post_clean_flip_enabled_from_env") {
        return Err("serial_mining must parse the flip env through the shipped helper");
    }
    Ok(())
}

/// : production serial_mining must keep the post-clean
/// chain-inactive broadcast env-gated, default off, queued after the
/// clean-block queue clear, and dispatched through the serial actor.
pub fn admit_s19k_production_post_clean_chain_inactive_is_env_gated(
    src: &str,
) -> Result<(), &'static str> {
    if !src.contains("DCENT_S19K_EXPERIMENTAL_POST_CLEAN_CHAIN_INACTIVE") {
        return Err("serial_mining must name the experimental post-clean chain-inactive env");
    }
    if !src.contains("s19k_experimental_post_clean_chain_inactive_enabled_from_env") {
        return Err("serial_mining must parse the chain-inactive env through the shipped helper");
    }
    if !src.contains("actor_send_chain_inactive_bm1366") {
        return Err(
            "serial actor must dispatch the chain-inactive sentinel via actor_send_chain_inactive_bm1366",
        );
    }
    let clear_at = src
        .find("flush stale work")
        .ok_or("serial_mining clean block must keep the queue clear marker")?;
    let queued_at = src
        .find("S19k post-clean chain-inactive broadcast queued")
        .ok_or("serial_mining must log the queued post-clean chain-inactive broadcast")?;
    if queued_at < clear_at {
        return Err("chain-inactive sentinel must be queued after the clean-block queue clear");
    }
    if !src.contains("clean_funnel.leftover_hit") {
        return Err("planner must see leftover_hit from the funnel, not env alone");
    }
    if !src.contains("s19k_leftover_hit_admits_experimental_inactive")
        && !src.contains("leftover_hit,")
    {
        return Err("post-clean inactive must be leftover-admitted");
    }
    Ok(())
}

/// Shipped fill TX must encode `work_id`, not stock `slot<<3`.
pub fn admit_bosminer_fill_path_job_id_is_work_id_shl_log() -> Result<(), &'static str> {
    if s19k_braiins_fill_midstate_log() != 0 {
        return Err("fill +0x55=1 ⇒ FUN_0125fc94 log 0");
    }
    if s19k_braiins_fill_job_id(2) != 2 {
        return Err("fill log=0 ⇒ job_id=work_id (not 2<<3=0x10)");
    }
    if s19k_braiins_fill_job_id(0x10) != 0x10 {
        return Err("fill log=0 is identity for every u8 work_id");
    }
    if s19k_braiins_uart_work_id_from_rx_job_byte(2, s19k_braiins_fill_midstate_log())? != 2 {
        return Err("fill RX inverse is the raw job byte");
    }
    Ok(())
}

/// AM3 factories do not store the +0x88/+0x90 pointers; clone+memcpy only.
pub fn refuse_am3_factory_as_first_writer_of_engine_fn_ptrs() -> Result<(), &'static str> {
    if BOSMINER_AM3_FACTORY_STR_88_90_HITS != 0 {
        return Ok(());
    }
    Err("five AM3 factories have 0 STR/LDR #0x88/#0x90; FUN_00875f54 still only copies X1")
}

/// `FUN_00bf3264` is not the +0x88 body. It divides the BLR return.
pub fn refuse_bf3264_as_engine_nonce_fn() -> Result<(), &'static str> {
    Err("FUN_00bf3264 is (blr+0x88_low & 0xff) / *param_4 after REV; +0x88 callee still unnamed")
}

/// `FUN_00bf3264`: `(nonce_fn_low & 0xff) / *divisor`. Panics if divisor is 0.
pub fn s19k_braiins_work_resp_index(nonce_fn_low: u64, divisor: u64) -> Result<u64, &'static str> {
    if divisor == 0 {
        return Err("FUN_00bf3264 panics when *param_4 == 0");
    }
    Ok((nonce_fn_low & 0xff) / divisor)
}

/// Five UART parse callers pass Worker+0x11c0 as `FUN_00bf3264` param_4.
pub fn admit_bosminer_uart_work_resp_div_is_worker_plus_0x11c0() -> Result<(), &'static str> {
    if BOSMINER_UART_WORK_RESP_DIV_OFF != 0x11C0 {
        return Err("UART parse MOVZ W25,#0x11c0");
    }
    if BOSMINER_WORK_RESP_DIV_MOVZ_INSN != 0x5282_3819 {
        return Err("MOVZ W25,#0x11c0 is 0x52823819");
    }
    if BOSMINER_WORK_RESP_ADD_X2_INSN != 0x8B19_0262 {
        return Err("ADD X2,X19,X25 before BL FUN_0091c0a0");
    }
    if BOSMINER_WORK_RESP_PARSE_CALLER_COUNT != 5 {
        return Err("five UART parse monomorphizations call FUN_0091c0a0");
    }
    if s19k_braiins_work_resp_index(0xAB, 2)? != 0x55 {
        return Err("FUN_00bf3264 is (low8)/divisor");
    }
    Ok(())
}

/// FPGA `FUN_008af670` uses +0x340. That is not the UART Worker field.
pub fn refuse_fpga_0x340_as_uart_work_resp_div() -> Result<(), &'static str> {
    Err("FUN_008af670 ADD X0,X19,#0x340 feeds FUN_00bf3264; UART parse uses Worker+0x11c0")
}

/// `FUN_00900810` `STR [SP,#0x88]` is a stack spill, not the engine fn-ptr writer.
pub fn refuse_worker_ctor_str88_sp_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_WORKER_CTOR_STR88_SP_INSN != 0xF900_47F3 {
        return Ok(());
    }
    Err("FUN_00900810 STR X19,[SP,#0x88] (0xF90047F3); engine+0x88 still only copied from factory X1")
}

/// `*(Worker+0x11c0)` is not proven chip_count / interval / cores.
pub fn refuse_unnamed_0x11c0_value_as_chip_count() -> Result<(), &'static str> {
    Err("RX+0x11c0 is HashChain+0x11F0 (copy +0x30); ctor STR XZR; Halt Box STR is another type; no named count")
}

/// RX parse object is `memcpy(wrapper+0x10, 0x1390)` (`FUN_0086e3f4`).
pub fn admit_bosminer_rx_object_is_wrapper_plus_0x10_copy() -> Result<(), &'static str> {
    if BOSMINER_RX_WRAPPER_COPY_OFF != 0x10 {
        return Err("FUN_0086e3f4 ADD X1,X19,#0x10");
    }
    if BOSMINER_RX_WRAPPER_COPY_LEN != 0x1390 {
        return Err("FUN_0086e3f4 MOVZ W2,#0x1390");
    }
    if BOSMINER_RX_WRAPPER_ADD_SRC_INSN != 0x9100_4261 {
        return Err("memcpy src is ADD X1,X19,#0x10");
    }
    if BOSMINER_RX_WRAPPER_SIZE_INSN != 0x5282_7202 {
        return Err("memcpy size is MOVZ W2,#0x1390");
    }
    if BOSMINER_UART_WORK_RESP_DIV_OFF + BOSMINER_RX_WRAPPER_COPY_OFF != BOSMINER_WRAPPER_DIV_OFF {
        return Err("RX+0x11c0 maps to wrapper+0x11d0");
    }
    Ok(())
}

/// Serde `FUN_00b270b4` / `FUN_0065f830` STR #0x11c0 is not UART bring-up.
pub fn refuse_serde_str_11c0_as_uart_div_writer() -> Result<(), &'static str> {
    Err("non-SP STR #0x11c0 @ 0xb28344/0x6625f0 are enum-tag deserializers, not HashChain bring-up")
}

fn engine88_first_load_off(va: u64) -> Option<usize> {
    va.checked_sub(0x400_000).map(|o| o as usize)
}

fn engine88_le_u32(blob: &[u8], va: u64) -> Option<u32> {
    let i = engine88_first_load_off(va)?;
    blob.get(i..i + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Six inits store work-type `4` at +0x80 then the helper Result at +0x88.
pub fn admit_bosminer_engine88_producer_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_ENGINE88_PRODUCER_HITS != 6 {
        return Err("engine+0x88 producer census drifted");
    }
    if BOSMINER_ENGINE88_WORK_TYPE != 4 {
        return Err("producer work-type immediate is not 4");
    }
    for &va in &BOSMINER_ENGINE88_MOVZ4_VA {
        let movz = engine88_le_u32(blob, va).ok_or("bosminer shorter than engine88 MOVZ #4")?;
        if movz != BOSMINER_ENGINE88_MOVZ4_INSN {
            return Err("producer site is missing MOVZ W9,#4");
        }
        let s80 = engine88_le_u32(blob, va + BOSMINER_ENGINE88_MOVZ_TO_STR80)
            .ok_or("bosminer shorter than engine88 STR #0x80")?;
        if s80 != BOSMINER_ENGINE88_STR80_INSN {
            return Err("producer site is not STR X9,[X19,#0x80]");
        }
        let s88 = engine88_le_u32(
            blob,
            va + BOSMINER_ENGINE88_MOVZ_TO_STR80 + BOSMINER_ENGINE88_STR80_TO_STR88,
        )
        .ok_or("bosminer shorter than engine88 STR #0x88")?;
        if s88 != BOSMINER_ENGINE88_STR88_INSN {
            return Err("producer site is not STR X0,[X19,#0x88]");
        }
    }
    let ldrb = engine88_le_u32(blob, BOSMINER_ENGINE88_PRODUCER_LDRB_VA)
        .ok_or("bosminer shorter than engine88 producer LDRB")?;
    if ldrb != BOSMINER_ENGINE88_PRODUCER_LDRB_INSN {
        return Err("FUN_008d9984 is not LDRB [X0,#0x70]");
    }
    Ok(())
}

/// Work-type 4 + Result store is not the fill identity `.text` at +0x88.
pub fn refuse_engine88_type4_result_as_fill_identity() -> Result<(), &'static str> {
    Err(
        "6 engine inits store work-type 4 at +0x80 and BL Result X0 at +0x88; not fill type-1 identity .text",
    )
}

/// : first-LOAD census of `MOVZ #1` then `STR`/`STRB [X19,#0x80]` then
/// `STR [X19,#0x88]` in a 20-insn window is **zero**. Fill +0x88 is copied.
pub const BOSMINER_FILL_TYPE1_COINSTALLED_88_HITS: usize = 0;
pub const BOSMINER_FILL_TYPE1_WIDE_STRB80_STR88_HITS: usize = 0;
pub const BOSMINER_BM1366_FACTORY_STR88_IN_FIRST_800: usize = 0;

pub fn admit_bosminer_fill_type1_plus88_coinstall_absent(hits: usize) -> Result<(), &'static str> {
    if hits != BOSMINER_FILL_TYPE1_COINSTALLED_88_HITS {
        return Err("fill type-1 +0x88 co-install census drifted");
    }
    if BOSMINER_FILL_TYPE1_WIDE_STRB80_STR88_HITS != 0 {
        return Err("wide STRB#0x80 + STR#0x88 census drifted");
    }
    if BOSMINER_BM1366_FACTORY_STR88_IN_FIRST_800 != 0 {
        return Err("FUN_00876ca8 first 0x800 grew a +0x88 store");
    }
    Ok(())
}

pub fn refuse_fill_type1_static_plus88_installer() -> Result<(), &'static str> {
    Err(
        "0 MOVZ#1+STR/STRB[X19,#0x80]+STR#0x88; factory 0 STR#0x88 in first 0x800; fill +0x88 is clone/factory copy, not a static installer",
    )
}

/// Five HashChain inits store `&self+0x90` at +0x88, not a .text nonce fn.
pub fn refuse_hashchain_str88_self_plus_90_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_HASHCHAIN_STR88_SELF_PTR_HITS != 5 {
        return Ok(());
    }
    Err("five HashChain inits ADD X20,X19,#0x90; STR X20,[X19,#0x88]; field pointer, not engine+0x88 fn")
}

/// HashChain run copies `self+0x30` size 0x1390; parse RX+0x11c0 is HashChain+0x11F0.
pub fn admit_bosminer_hashchain_div_is_self_plus_0x11f0() -> Result<(), &'static str> {
    if BOSMINER_HASHCHAIN_RX_COPY_OFF != 0x30 {
        return Err("FUN_0089271c ADD X1,X19,#0x30");
    }
    if BOSMINER_HASHCHAIN_COPY_ADD_INSN != 0x9100_C261 {
        return Err("HashChain copy src is ADD X1,X19,#0x30");
    }
    if BOSMINER_HASHCHAIN_COPY_SIZE_INSN != 0x5282_7202 {
        return Err("HashChain copy size is MOVZ W2,#0x1390");
    }
    if BOSMINER_HASHCHAIN_RX_COPY_OFF + BOSMINER_UART_WORK_RESP_DIV_OFF
        != BOSMINER_HASHCHAIN_DIV_OFF
    {
        return Err("RX+0x11c0 maps to HashChain+0x11F0");
    }
    if BOSMINER_HASHCHAIN_DIV_OFF - BOSMINER_WRAPPER_DIV_OFF
        != BOSMINER_HASHCHAIN_RX_COPY_OFF - BOSMINER_RX_WRAPPER_COPY_OFF
    {
        return Err("wrapper+0x11d0 and HashChain+0x11F0 differ only by 0x20 headers");
    }
    Ok(())
}

/// `FUN_00bf3264` is one deref + UDIV; zero hits the rustc panic cold path.
pub fn admit_bosminer_div_is_single_deref_udiv() -> Result<(), &'static str> {
    if BOSMINER_WORK_RESP_DIV_LDR_INSN != 0xF940_0008 {
        return Err("FUN_00bf3264 first insn is LDR X8,[X0]");
    }
    if BOSMINER_WORK_RESP_DIV_CBZ_INSN != 0xB400_00A8 {
        return Err("CBZ X8 → cold FUN_00453bd8, not fall-through RET");
    }
    if BOSMINER_WORK_RESP_DIV_AND_INSN != 0x9240_1C29 {
        return Err("AND X9,X1,#0xff before UDIV");
    }
    if BOSMINER_WORK_RESP_DIV_UDIV_INSN != 0x9AC8_0920 {
        return Err("UDIV X0,X9,X8 is (low8) / *X0");
    }
    if s19k_braiins_work_resp_index(0xAB, 2)? != 0x55 {
        return Err("single-deref formula (low8)/divisor");
    }
    Ok(())
}

/// `FUN_0086e3d0` / `FUN_0128caa4` drop TLS scope, they do not init HashChain.
pub fn refuse_86e3d0_as_hashchain_spawn() -> Result<(), &'static str> {
    if BOSMINER_TLS_DROP_MRS_INSN != 0xD53B_D056 {
        return Ok(());
    }
    Err("FUN_0086e3d0 copies 4 qwords then FUN_0128caa4 (MRS tpidr_el0); TLS drop, not spawn")
}

/// `FUN_00749200` +0x11f0 is a Halt.rs Box+vtable, not the UART divisor u64.
pub fn refuse_749200_halt_box_as_uart_div_writer() -> Result<(), &'static str> {
    if BOSMINER_HALT_BOX_STR_11F0_INSN != 0xF908_FA75 {
        return Ok(());
    }
    if !BOSMINER_HALT_RS.ends_with("halt.rs") {
        return Ok(());
    }
    Err("FUN_00749200 STR #0x11f0 is Halt.rs Box+vtable (rustc 0x19b3188); not UART *(HashChain+0x11F0)")
}

/// The six non-SP `LDR #0x11f0` are Box drops, not UART `*(RX+0x11c0)` readers.
pub fn refuse_ldr_11f0_as_uart_div_reader() -> Result<(), &'static str> {
    if BOSMINER_LDR_11F0_HITS != 6 {
        return Ok(());
    }
    if BOSMINER_LDR_11F0_PAIR_11F8_HITS != 6 {
        return Ok(());
    }
    if BOSMINER_LDR_11F0_INSN != 0xF948_FA75 {
        return Ok(());
    }
    if BOSMINER_LDR_11F8_INSN != 0xF948_FE76 {
        return Ok(());
    }
    Err("six LDR #0x11f0 pair LDR #0x11f8 then BLR vtable; Box drop, not FUN_00bf3264")
}

/// `MOVZ #0x11f0` feeds memcpy size (Halt clone / stack snapshot), not ADD dest.
pub fn refuse_movz_11f0_as_field_addend() -> Result<(), &'static str> {
    if BOSMINER_MOVZ_11F0_MEMCPY_INSN != 0x5282_3E02 {
        return Ok(());
    }
    Err("MOVZ W2,#0x11f0 @ 0x6a9208 / Halt 0x749248 is memcpy length, not HashChain field")
}

/// `0x1270` memcpy of `self+0x30` is Future snapshot/restore, not a chip_count store.
pub fn refuse_1270_future_memcpy_as_div_writer() -> Result<(), &'static str> {
    if BOSMINER_FUTURE_SNAP_SIZE != 0x1270 {
        return Ok(());
    }
    if BOSMINER_FUTURE_SNAP_SIZE_INSN != 0x5282_4E02 {
        return Ok(());
    }
    if BOSMINER_FUTURE_TAG2_INSN != 0xB900_3289 {
        return Ok(());
    }
    if BOSMINER_OBJECT_30_1270_MEMCPY_HITS != 54 {
        return Ok(());
    }
    Err("FUN_0048e770 copies +0x30 size 0x1270 then STR 2 at +0x30; FUN_0050b9d0 drops that state; not *(+0x11F0)")
}

/// `UBFX #17,#8` is mid-function hash/CRC, not a tiny engine+0x88 callee.
pub fn refuse_ubfx_17_8_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_UBFX_17_8_HITS != 5 {
        return Ok(());
    }
    if BOSMINER_UBFX_17_8_INSN != 0x5311_60C6 {
        return Ok(());
    }
    Err("5 UBFX >>17&0xff (0x531160c6 @ 0x582b30) sit in hash/CRC loops; none are W0;RET +0x88")
}

/// The only ADD#0x90+STR#0x88 hits are SP epilogue, not engine+0x88.
pub fn refuse_add90_str88_sp_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_ADD90_STR88_NONSP_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_ADD90_STR88_SP_INSN != 0xF900_47E8 {
        return Ok(());
    }
    if BOSMINER_REG_STR_LSL3_HITS != 0 {
        return Ok(());
    }
    Err("4 ADD#0x90+STR#0x88 are ADD SP,#0x90 / STR [SP,#0x88]; 0 non-SP; 0 STR [Xn,Xm,LSL#3]")
}

/// Clone copies factory X1 in bulk. It does not mint a .text ptr at Worker+0x88.
pub fn admit_bosminer_factory_x1_is_engine_template() -> Result<(), &'static str> {
    if BOSMINER_CLONE_SRC_MOV_INSN != 0xAA01_03F4 {
        return Err("FUN_00875f54 MOV X20,X1");
    }
    if BOSMINER_FACTORY_X1_SAVE_INSN != 0xAA01_03F8 {
        return Err("FUN_00876ca8 MOV X24,X1");
    }
    if BOSMINER_FACTORY_X1_LDR70_INSN != 0xF940_3B08 {
        return Err("factory LDR [X24,#0x70] is engine midstate log");
    }
    if BOSMINER_AM3_FACTORY_BL_HITS != 0 {
        return Err("factories must be fn-ptr/DATA, not direct BL");
    }
    Ok(())
}

/// `FUN_00876398` STR #0x88 is Future state, not the nonce fn.
pub fn refuse_876398_str88_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_FUTURE_STR88_INSN != 0xF900_4668 {
        return Ok(());
    }
    Err("FUN_00876398 STR X8,[X19,#0x88] is Future waker/poll; clone body has 0 non-SP STR #0x88")
}

/// No ADRP.text STR to HashChain+0x118; no STR W to +0x11c0/+0x11f0; no object split ADD.
pub fn refuse_str118_and_strw_11c0_as_named_writers() -> Result<(), &'static str> {
    if BOSMINER_STR118_ADRP_TEXT_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_STRW_11C0_NONSP_HITS != 0 || BOSMINER_STRW_11F0_NONSP_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_SPLIT_11C0_OBJ_HITS != 0 {
        return Ok(());
    }
    Err("0 STR #0x118 of .text; 0 STR W #0x11c0/#0x11f0 non-SP; 0 object-src ADD#0x1000+#0x1c0")
}

/// Dispatch `0x2faf08` is 3.125 M host baud, not a chip FastUART write.
pub fn admit_bosminer_dispatch_1366_baud_is_3125k() -> Result<(), &'static str> {
    if BOSMINER_DISPATCH_BAUD_3125K != 3_125_000 {
        return Err("0x2faf08 == 3125000");
    }
    if BOSMINER_DISPATCH_BAUD_MOVZ_INSN != 0x5295_E109 {
        return Err("MOVZ W9,#0xaf08");
    }
    if BOSMINER_DISPATCH_BAUD_MOVK_INSN != 0x72A0_05E9 {
        return Err("MOVK W9,#0x2f,LSL#16");
    }
    Ok(())
}

/// The only ADRP+ADD of `FUN_00876ca8` is the dispatch table store.
pub fn admit_bosminer_factory_addr_only_dispatch_store() -> Result<(), &'static str> {
    if BOSMINER_FACTORY_ADDR_ADRP_INSN != 0x90FF_FD08 {
        return Err("ADRP X8, page of FUN_00876ca8");
    }
    if BOSMINER_FACTORY_ADDR_ADD_INSN != 0x9132_A108 {
        return Err("ADD X8,X8,#0xca8");
    }
    if BOSMINER_AM3_FACTORY_BL_HITS != 0 {
        return Err("still 0 direct BL to factories");
    }
    Ok(())
}

/// Factory `BL FUN_00903534` then 0x15f8 snapshot is SP+0x40 ← SP+0x1640, not heap +0x11F0.
pub fn refuse_factory_15f8_as_heap_div_writer() -> Result<(), &'static str> {
    if BOSMINER_FACTORY_WORKER_NEW_BL_INSN != 0x9402_31E5 {
        return Ok(());
    }
    if BOSMINER_FACTORY_SNAP_SIZE_INSN != 0x5282_BF02 {
        return Ok(());
    }
    if BOSMINER_FACTORY_SNAP_DEST_ADD_INSN != 0x9101_03E9 {
        return Ok(());
    }
    Err("FUN_00876ca8 BL Worker::new then MOVZ #0x15f8 memcpy dest=ORR(SP+#0x40); stack snapshot")
}

/// `LDR *+0; ADD #0x10; STR #0x88` is a slice data pointer, not a .text nonce fn.
pub fn refuse_slice10_str88_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_SLICE10_STR88_HITS != 7 {
        return Ok(());
    }
    if BOSMINER_SLICE10_ADD_INSN != 0x9100_4108 {
        return Ok(());
    }
    Err("7 sites LDR [ptr]; ADD #0x10; STR [obj,#0x88] — rust slice+16, not engine+0x88 .text")
}

/// Chip-0x1366 factory is `HashMap::get` then `BLR *(entry+8)`.
pub fn admit_bosminer_factory_blr_is_get_value_plus_8() -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_GET_KEY_OFF != 0x19C {
        return Err("FUN_008787a8 hashes lookup+0x19c as u16 chip id");
    }
    if BOSMINER_FACTORY_LDR8_INSN != 0xF940_0437 {
        return Err("FUN_00835220 LDR X23,[X1,#8]");
    }
    if BOSMINER_FACTORY_BLR_INSN != 0xD63F_02E0 {
        return Err("FUN_00835220 BLR X23");
    }
    if BOSMINER_FACTORY_GET_BL_INSN != 0x9401_0D53 {
        return Err("BL FUN_008787a8");
    }
    if BOSMINER_FACTORY_GET_OUTER_BL_INSN != 0x97FE_DC15 {
        return Err("FUN_0087e02c BL FUN_00835220");
    }
    Ok(())
}

/// `FUN_0083b3a0` clones HashChain `+0xf0`/`+0x10` Strings; it does not copy `+0x88`.
pub fn refuse_83b3a0_as_engine_88_copy() -> Result<(), &'static str> {
    if BOSMINER_PREP_STR88_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_PREP_ADD_F0_INSN != 0x9103_C020 {
        return Ok(());
    }
    if BOSMINER_VEC_CLONE_LEN_LDR_INSN != 0xF940_0813 {
        return Ok(());
    }
    Err("FUN_0083b3a0 ADD #0xf0/#0x10 then FUN_012d276c String/Vec clone; 0 STR #0x88 in prep body")
}

/// FUN_00835220 X1 is `local_738` (`[SP,#0x78]`) written by spawn `BLR *value`.
pub fn admit_bosminer_factory_x1_is_spawn_local738() -> Result<(), &'static str> {
    if BOSMINER_FACTORY_X1_LDR_SP78_INSN != 0xF940_3FE8 {
        return Err("FUN_0087e02c LDR X8,[SP,#0x78]");
    }
    if BOSMINER_FACTORY_X1_MOV_INSN != 0xAA18_03E1 {
        return Err("MOV X1,X24 into FUN_00835220");
    }
    if BOSMINER_FACTORY_SPAWN_BLR_INSN != 0xD63F_02E0 {
        return Err("BLR spawn into local_748");
    }
    if BOSMINER_FACTORY_CTX_MOV_INSN != 0xAA00_03F6 {
        return Err("MOV X22,X0 context");
    }
    Ok(())
}

/// `FUN_0093cc3c` is an async poll of `context+0x230`, not factory X1.
pub fn refuse_93cc3c_as_factory_x1() -> Result<(), &'static str> {
    if BOSMINER_93CC3C_SRC_ADD_INSN != 0x9108_C000 {
        return Ok(());
    }
    if BOSMINER_93CC3C_BL_INSN != 0x9402_FAF7 {
        return Ok(());
    }
    Err("FUN_0093cc3c polls context+0x230 (Once/Future); 0 STR [SP,#0x78] in FUN_0087e02c")
}

/// `FUN_008dbdf4` boxes the 0x230 prep snapshot; it is not an engine+0x88 writer.
pub fn refuse_dbdf4_as_engine_88_writer() -> Result<(), &'static str> {
    if BOSMINER_VT0_STR88_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_VT0_COPY_230_INSN != 0x5280_4602 {
        return Ok(());
    }
    if BOSMINER_VT0_LDRB_228_INSN != 0x3948_A008 {
        return Ok(());
    }
    Err("FUN_008dbdf4 LDRB +0x228==1 then memcpy 0x230 / box 0x250; 0 STR #0x88; 0 BL")
}

/// vtable[0] is the prep boxer (tag +0x228, copy 0x230, box 0x250).
pub fn admit_bosminer_vt0_is_prep_boxer() -> Result<(), &'static str> {
    if BOSMINER_VT0_TAG_OFF != 0x228 {
        return Err("tag at prep+0x228");
    }
    if BOSMINER_VT0_COPY_SIZE != 0x230 {
        return Err("memcpy size 0x230");
    }
    if BOSMINER_VT0_BOX_SIZE != 0x250 {
        return Err("box size 0x250");
    }
    if BOSMINER_VT0_BL_HITS != 0 {
        return Err("0 direct BL; only HashMap BLR");
    }
    if BOSMINER_VT0_PANIC_LINE != 0x23 {
        return Err("panic line 35");
    }
    Ok(())
}

/// Two first-LOAD sites store tag `+0x228=1` via `MOVZ #1; STRB`.
pub fn admit_bosminer_tag228_ones_are_two_strb() -> Result<(), &'static str> {
    if BOSMINER_TAG1_STRB_HITS != 2 {
        return Err("exactly two MOVZ#1+STRB #0x228");
    }
    if BOSMINER_TAG1_A_MOVZ_INSN != 0x5280_002A {
        return Err("FUN_006079d4 MOVZ W10,#1");
    }
    if BOSMINER_TAG1_A_STRB_INSN != 0x3908_A26A {
        return Err("FUN_006079d4 STRB [X19,#0x228]");
    }
    if BOSMINER_TAG1_B_MOVZ_INSN != 0x5280_0028 {
        return Err("second MOVZ W8,#1");
    }
    if BOSMINER_TAG1_A_BL_HITS != 0 {
        return Err("FUN_006079d4 0 BL");
    }
    Ok(())
}

/// `FUN_005f4a8c` `MOVZ #0x7c; STRB #0x228` is not the vt0 tag.
pub fn refuse_5f5a20_7c_as_vt0_tag() -> Result<(), &'static str> {
    if BOSMINER_TAG7C_MOVZ_INSN != 0x5280_0F88 {
        return Ok(());
    }
    if BOSMINER_TAG7C_STRB_INSN != 0x3908_A268 {
        return Ok(());
    }
    Err("FUN_005f4a8c stores 0x7c at +0x228 (also +0x240=0x80); not vt0 tag 1")
}

/// `0x7493e4` is Halt `+0x1228` (split `X0+#0x1000`), not HashChain `+0x228`.
pub fn refuse_7493e4_as_hashchain_tag228() -> Result<(), &'static str> {
    if BOSMINER_HALT_SPLIT_ADD_INSN != 0x9140_0417 {
        return Ok(());
    }
    if BOSMINER_TAG1_B_STRB_INSN != 0x3908_A2E8 {
        return Ok(());
    }
    if BOSMINER_HALT_BOX_STR_11F0_INSN != 0xF908_FA75 {
        return Ok(());
    }
    Err("FUN_00749200 ADD X23,X0,#0x1000; STRB [X23,#0x228] is Halt +0x1228 (same fn STR #0x11f0)")
}

/// `FUN_006079d4` tag=1 is a 0x250 object (0 +0x19c / +0x11F0), not HashChain.
pub fn refuse_6079d4_as_hashchain_tag228() -> Result<(), &'static str> {
    if BOSMINER_TAG1_A_OFF_19C_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_TAG1_A_OFF_11F0_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_TAG1_A_ADD250_INSN != 0x9109_4276 {
        return Ok(());
    }
    Err("FUN_006079d4 MOV X19,X0; STRB #0x228; ADD #0x250; 0 chip_id +0x19c and 0 +0x11F0")
}

/// Instantiate `0x2a0` memcpy clones `FUN_00878950` output; it does not mint `+0x228`.
pub fn refuse_825568_2a0_as_first_228_writer() -> Result<(), &'static str> {
    if BOSMINER_INSTANTIATE_SNAP_INSN != 0x5280_5402 {
        return Ok(());
    }
    if BOSMINER_INSTANTIATE_SNAP_SIZE != 0x2A0 {
        return Ok(());
    }
    if BOSMINER_INSTANTIATE_BUILD_230_INSN != 0x5280_4602 {
        return Ok(());
    }
    Err("FUN_00825568 MOVZ #0x2a0 memcpy after FUN_00878950; covering clone of prep+tail, not first +0x228")
}

/// `FUN_00878950` `memcpy(dest, prep, 0x230)` copies prep `+0x228`, then stores at `+0x230`.
pub fn refuse_878950_230_as_first_228_writer() -> Result<(), &'static str> {
    if BOSMINER_INSTANTIATE_BUILD_230_INSN != 0x5280_4602 {
        return Ok(());
    }
    if BOSMINER_INSTANTIATE_BUILD_MEMCPY_BL_INSN != 0x940D_40DE {
        return Ok(());
    }
    Err("FUN_00878950 MOVZ #0x230 memcpy of FUN_0083b3a0 prep; +0x228 is copied, first new field is +0x230")
}

/// AM3 HashChain init functions do not store `+0x228` and do not memcpy `>=0x80`.
pub fn admit_am3_hashchain_init_has_no_228_store() -> Result<(), &'static str> {
    if BOSMINER_AM3_HC_INIT_STR228_HITS != 0 {
        return Err("0 STR W/STRB #0x228 in five AM3 HashChain inits");
    }
    if BOSMINER_AM3_HC_INIT_MEMCPY_GE80_HITS != 0 {
        return Err("0 memcpy size>=0x80 in five AM3 HashChain inits");
    }
    if BOSMINER_AM3_HC_INIT_FNS.len() != 5 {
        return Err("five AM3 HashChain init bodies");
    }
    if BOSMINER_AM3_HC_INIT_FNS[0].0 != 0x008C_FAD0 {
        return Err("FUN_008cfad0");
    }
    Ok(())
}

/// Split `ADD #0x200; STRB #0x28` does not write HashChain `+0x228`.
pub fn refuse_split_200_strb28_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_SPLIT_200_STRB28_HITS != 0 {
        return Ok(());
    }
    Err("0 ADD #0x200 then STRB #0x28 within 32 insns; no split +0x228 store")
}

/// `ADD #0x228; STRB [Xd,#0]` does not write the tag through a pointer.
pub fn refuse_add228_strb0_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_ADD228_STRB0_HITS != 0 {
        return Ok(());
    }
    Err("0 ADD #0x228 then STRB [Xd,#0] within 8 insns; no pointer-form store")
}

/// No `MOVZ #0x228; STRB [Xn,Xm]` first-LOAD register-offset store.
pub fn refuse_movz228_strb_regoff_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_MOVZ228_STRB_REGOFF_HITS != 0 {
        return Ok(());
    }
    Err("0 MOVZ #0x228 then STRB register-offset; serde/Default does not use Rm=0x228")
}

/// `ADD #0x228; BL` callees do not `STRB [X0,#0]` in the first 0x80 (not visit-store).
pub fn refuse_add228_bl_strb_x0_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_ADD228_BL_STRB_X0_0_HITS != 0 {
        return Ok(());
    }
    Err("0 ADD #0x228 BL callees STRB [X0,#0] early; visitors drop/clone/panic, they do not mint tag 1")
}

/// `FUN_0094fc6c` `memcpy(dst+0x228, stack, 0x200)` is not HashChain (0 +0x19c/+0x11F0).
pub fn refuse_9514c8_memcpy200_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_DEST228_MEMCPY_SIZE_INSN != 0x5280_4002 {
        return Ok(());
    }
    if BOSMINER_DEST228_OFF_19C_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_DEST228_OFF_11F0_HITS != 0 {
        return Ok(());
    }
    Err("FUN_0094fc6c ADD X0,X21,#0x228; MOVZ #0x200 memcpy; 0 chip_id +0x19c and 0 +0x11F0")
}

/// No `STP XZR,XZR` Default covering HashChain `+0x228`.
pub fn refuse_stp_xzr_as_hashchain_228_default() -> Result<(), &'static str> {
    if BOSMINER_STP_XZR_220_228_NONSP_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_STUR_XZR_228_HITS != 0 {
        return Ok(());
    }
    Err("0 STP XZR,XZR [Xn,#0x210/#0x220/#0x228] and 0 STUR XZR #0x228; no pair-zero Default")
}

/// `FUN_01200524` is a slot setter, not memset/alloc_zeroed.
pub fn refuse_1200524_as_memset() -> Result<(), &'static str> {
    if BOSMINER_SLOT_SET_ENTRY_INSN != 0xA9BE_57FE {
        return Ok(());
    }
    if BOSMINER_SLOT_SET_BL_HITS != 358 {
        return Ok(());
    }
    Err("FUN_01200524 stores X1/X2 into obj+0x10/+0x18 after optional drop; 358 BL; not memset")
}

/// `STR XZR`/`STR WZR`/`STRB WZR` at `#0x228` are not on HashChain objects.
pub fn refuse_wzr_228_stores_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_STR_XZR_228_NONSP_HITS != 7 {
        return Ok(());
    }
    if BOSMINER_STR_XZR_228_HC_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_STRB_WZR_228_NONSP_HITS != 16 {
        return Ok(());
    }
    if BOSMINER_STRB_WZR_228_HC_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_STR_WZR_228_HITS != 1 {
        return Ok(());
    }
    Err("7 STR XZR + 1 STR WZR + 16 STRB WZR at #0x228; 0 windows have +0x19c/+0x11F0")
}

/// `FUN_00836934` `STRB WZR #0x228` belongs to the ticket-mask future, not a
/// HashChain Default initializer.
pub fn refuse_ticket_mask_836c20_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_TICKET_MASK_STRB_228_INSN != 0x3908_A15F {
        return Ok(());
    }
    if BOSMINER_TICKET_MASK_STRB_FN_VA != 0x0083_6934 {
        return Ok(());
    }
    Err("FUN_00836934 ticket-mask STRB WZR [X10,#0x228]; not HashChain Default")
}

/// Post-alloc `STR #0x228` sites are String/BTree helpers, not HashChain.
pub fn refuse_post_alloc_str228_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_POST_ALLOC_STR228_NONSP_HITS != 3 {
        return Ok(());
    }
    if BOSMINER_POST_ALLOC_STR228_HC_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_POST_ALLOC_STR228_INSN != 0xF901_1728 {
        return Ok(());
    }
    Err("3 BL FUN_005f4a78 then STR #0x228 Xn!=SP before RET; 0 +0x19c/+0x11F0")
}

/// `FUN_00814490` / `FUN_0127c2f8` `STR [Xn,#0x228]` is a BTree child/next slot.
pub fn admit_bosminer_btree_str228_is_child_slot() -> Result<(), &'static str> {
    if BOSMINER_BTREE_STR220_228_HITS != 17 {
        return Err("17 STR #0x220 then STR #0x228 pairs");
    }
    if BOSMINER_BTREE_STR228_INSN != 0xF901_1419 {
        return Err("FUN_00814490 STR X25,[X0,#0x228]");
    }
    if BOSMINER_BTREE_NODE_LEN_OFF != 0x21A {
        return Err("BTree node len at +0x21a");
    }
    if BOSMINER_BTREE_ALLOC2_STR228_INSN != 0xF901_1418 {
        return Err("FUN_0127c2f8 STR X24,[X0,#0x228]");
    }
    Ok(())
}

/// dest=`MOV X0,Xn` covering `memcpy` is not a HashChain-base first `+0x228` write.
pub fn refuse_mov_dest_memcpy_ge229_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_MOV_DEST_MEMCPY_HC_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_MOV_DEST_228WIN_HITS != 7 {
        return Ok(());
    }
    if BOSMINER_BASE_ADD0_MEMCPY_GE229_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_FUTURE_POLL_MEMCPY_860_INSN != 0x5281_0C02 {
        return Ok(());
    }
    Err("0 dest=MOV memcpy with +0x19c/+0x11F0; 7 +0x228 windows are Future-poll/panic; 0 dest=ADD#0")
}

/// `FUN_00c6c594` `memcpy` `0x2b0` is a tokio-like object, not HashChain.
pub fn refuse_c6c594_2b0_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_C6C594_MEMCPY_2B0_INSN != 0x5280_5602 {
        return Ok(());
    }
    Err("FUN_00c6c594 MOVZ #0x2b0 memcpy onto X19 then STR +0x2b0; 0 +0x19c/+0x11F0")
}

/// Prep has exactly three `BL` sites: two instantiate + factory clone.
pub fn admit_bosminer_prep_has_three_bl_callers() -> Result<(), &'static str> {
    if BOSMINER_PREP_BL_HITS != 3 {
        return Err("3 BL FUN_0083b3a0");
    }
    if BOSMINER_PREP_BL_VAS[0] != 0x0082_55DC {
        return Err("FUN_00825568 BL prep");
    }
    if BOSMINER_PREP_BL_VAS[1] != 0x0082_5934 {
        return Err("FUN_008258c0 BL prep");
    }
    if BOSMINER_PREP_BL_VAS[2] != 0x0083_52E0 {
        return Err("FUN_00835220 BL prep");
    }
    if BOSMINER_PREP_BL_A_INSN != 0x9400_5771 {
        return Err("0x94005771");
    }
    Ok(())
}

/// `FUN_008258c0` is AM2 instantiate (0x2a0 + hashchain string), not first +0x228 writer.
pub fn refuse_8258c0_as_first_228_writer() -> Result<(), &'static str> {
    if BOSMINER_PREP_SIB_FN_VA != 0x0082_58C0 {
        return Ok(());
    }
    if BOSMINER_PREP_SIB_BL_VA != 0x0082_5934 {
        return Ok(());
    }
    Err("FUN_008258c0 is AM2 instantiate sibling; copies 0x2a0 after prep; not first +0x228 store")
}

/// Five AM3 wrappers poll a Future and call init(`self+0x18`); they do not alloc or store +0x228.
pub fn admit_am3_hashchain_wrapper_is_future_poll() -> Result<(), &'static str> {
    if BOSMINER_AM3_WRAP_HITS != 5 {
        return Err("5 AM3 Future-poll wrappers");
    }
    if BOSMINER_AM3_WRAP_LDR10_INSN != 0xB940_1008 {
        return Err("LDR W8,[X0,#0x10]");
    }
    if BOSMINER_AM3_WRAP_ADD18_INSN != 0x9100_6260 {
        return Err("ADD X0,X19,#0x18");
    }
    if BOSMINER_AM3_WRAP_FNS[0] != (0x008C_CE14, 0x008C_FAD0) {
        return Err("FUN_008cce14 -> FUN_008cfad0");
    }
    if BOSMINER_AM3_WRAP0_BL_INSN != 0x9400_0B23 {
        return Err("wrap0 BL init");
    }
    Ok(())
}

/// No unaligned `STUR` `#0x228` first-LOAD writer.
pub fn refuse_stur_228_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_STUR_228_ANY_HITS != 0 {
        return Ok(());
    }
    Err("0 STUR X/W/B #0x228; no unaligned first tag store")
}

/// Five AM3 wrappers have exactly ten `BL` callers (two each).
pub fn admit_am3_wrap_has_ten_bl_callers() -> Result<(), &'static str> {
    if BOSMINER_AM3_WRAP_BL_HITS != 10 {
        return Err("10 BL to five AM3 wrappers");
    }
    if BOSMINER_AM3_WRAP_CALLER_BL_INSN != 0x97FF_965E {
        return Err("FUN_008e7454 BL FUN_008cce14");
    }
    Ok(())
}

/// Wrap callers are outer Future poll: `ADD X0,X19,#0x20` then wrap; 0 `+0x228` store.
pub fn admit_am3_wrap_caller_is_outer_future() -> Result<(), &'static str> {
    if BOSMINER_AM3_WRAP_CALLER_ADD20_INSN != 0x9100_8260 {
        return Err("ADD X0,X19,#0x20");
    }
    if BOSMINER_AM3_WRAP_CALLER_FN_VA != 0x008E_7454 {
        return Err("FUN_008e7454");
    }
    if BOSMINER_AM3_WRAP_CALLER_STR228_HITS != 0 {
        return Err("0 STR #0x228 in FUN_008e7454");
    }
    Ok(())
}

/// `FUN_008e7454` does not mint HashChain `+0x228`.
pub fn refuse_8e7454_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_AM3_WRAP_CALLER_STR228_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_AM3_WRAP_CALLER_ADD20_INSN != 0x9100_8260 {
        return Ok(());
    }
    Err("FUN_008e7454 polls wrap(self+0x20); no alloc and no +0x228 store")
}

/// `FUN_008cb778` boxes the outer Future as size `0x180` (vtable `0x19c6b50`).
pub fn admit_bosminer_outer_future_box_is_180() -> Result<(), &'static str> {
    if BOSMINER_OUTER_BOX_SIZE != 0x180 {
        return Err("alloc/memcpy 0x180");
    }
    if BOSMINER_OUTER_BOX_SIZE_INSN != 0x5280_3000 {
        return Err("MOVZ X0,#0x180");
    }
    if BOSMINER_OUTER_BOX_180_HITS != 4 {
        return Err("4 0x180 installers");
    }
    if BOSMINER_OUTER_BOX_FN_VA != 0x008C_B778 {
        return Err("FUN_008cb778");
    }
    Ok(())
}

/// Vtable at `0x19c6b50` is `thunk_FUN_008e7454` (`0x84ca74`).
pub fn admit_bosminer_vtable_19c6b50_is_thunk_e7454() -> Result<(), &'static str> {
    if BOSMINER_OUTER_VT_VA != 0x019C_6B50 {
        return Err("0x19c6b50");
    }
    if BOSMINER_OUTER_VT_THUNK != 0x0084_CA74 {
        return Err("thunk 0x84ca74");
    }
    if BOSMINER_OUTER_VT_ADD_INSN != 0x912D_4108 {
        return Err("ADD #0xb50");
    }
    if BOSMINER_OUTER_VT_ADRP_HITS != 5 {
        return Err("5 ADRP vtable formers");
    }
    Ok(())
}

/// The `0x180` box cannot be a pre-init HashChain `+0x228` template.
pub fn refuse_8cb778_180_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_OUTER_BOX_STR228_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_OUTER_BOX_SIZE != 0x180 {
        return Ok(());
    }
    if BOSMINER_OUTER_BOX_SIZE >= 0x228 {
        return Ok(());
    }
    Err("FUN_008cb778 memcpy 0x180 < 0x228 and < outer+0x260; 0 STR #0x228")
}

/// `FUN_008ce99c` boxes the Future (`0xcc`) then schedules it at Arc+0x160.
pub fn admit_bosminer_8ce99c_boxes_and_schedules() -> Result<(), &'static str> {
    if BOSMINER_BOX_SCHED_TAG_INSN != 0x5280_1982 {
        return Err("MOVZ X2,#0xcc");
    }
    if BOSMINER_BOX_SCHED_BL_INSN != 0x97FF_F367 {
        return Err("BL FUN_008cb778");
    }
    if BOSMINER_BOX_SCHED_ADD160_INSN != 0x9105_82C0 {
        return Err("ADD X0,X22,#0x160");
    }
    if BOSMINER_BOX_SCHED_SPAWN_BL_INSN != 0x97FF_AAC5 {
        return Err("BL FUN_008b9504");
    }
    if BOSMINER_BOXER_BL_HITS != 4 {
        return Err("4 BL to 0x180 boxers");
    }
    Ok(())
}

/// `FUN_008b9504` is a run-queue insert that stores `box+0x18`, not HashChain+0x228.
pub fn admit_bosminer_8b9504_is_runqueue_insert() -> Result<(), &'static str> {
    if BOSMINER_RUNQ_STR18_INSN != 0xF900_0C29 {
        return Err("STR X9,[X1,#0x18]");
    }
    if BOSMINER_RUNQ_FN_VA != 0x008B_9504 {
        return Err("FUN_008b9504");
    }
    if BOSMINER_RUNQ_STR228_HITS != 0 {
        return Err("0 STR #0x228 in run-queue insert");
    }
    Ok(())
}

/// AM3 init dest is `wrap+0x18` = boxed Future `+0x38` (remain `0x148`).
pub fn admit_am3_init_dest_is_box_plus_38() -> Result<(), &'static str> {
    if BOSMINER_AM3_INIT_DEST_BOX_OFF != 0x20 + 0x18 {
        return Err("box+0x20 wrap + wrap+0x18");
    }
    if BOSMINER_AM3_INIT_DEST_REMAIN != 0x180 - 0x38 {
        return Err("0x148 remain");
    }
    if BOSMINER_AM3_INIT_DEST_REMAIN < 0x228 {
        // dest+0x228 does not fit in the box — proven size bound
    } else {
        return Err("remain must be < 0x228");
    }
    if BOSMINER_AM3_WRAP_ADD18_INSN != 0x9100_6260 {
        return Err("wrap ADD #0x18");
    }
    if BOSMINER_AM3_WRAP_CALLER_ADD20_INSN != 0x9100_8260 {
        return Err("outer ADD #0x20");
    }
    Ok(())
}

/// `FUN_008ce99c` does not write HashChain `+0x228`.
pub fn refuse_8ce99c_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_BOX_SCHED_STR228_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_BOX_SCHED_TAG != 0xCC {
        return Ok(());
    }
    Err("FUN_008ce99c boxes tag 0xcc and schedules at Arc+0x160; 0 STR #0x228")
}

/// `FUN_008518d0` assembles the boxer's `0x108` image at `SP+#0x1a0`.
pub fn admit_bosminer_8518d0_assembles_108_stack_image() -> Result<(), &'static str> {
    if BOSMINER_PARENT_IMAGE_ADD_INSN != 0x9106_83E1 {
        return Err("ADD X1,SP,#0x1a0");
    }
    if BOSMINER_PARENT_IMAGE_SIZE != 0x108 {
        return Err("0x108 boxer memcpy source");
    }
    if BOSMINER_PARENT_CE99C_BL_INSN != 0x9401_F3F9 {
        return Err("BL FUN_008ce99c");
    }
    if BOSMINER_PARENT_P2_LDR50_INSN != 0xF940_2829 {
        return Err("LDR X9,[X1,#0x50] copies param_2");
    }
    Ok(())
}

/// `FUN_008518d0` `param_2` is not a HashChain pointer; X1 to ce99c is the stack image.
pub fn refuse_8518d0_param2_as_hashchain_pointer() -> Result<(), &'static str> {
    if BOSMINER_PARENT_IMAGE_SP_OFF != 0x1A0 {
        return Ok(());
    }
    if BOSMINER_PARENT_IMAGE_SIZE != 0x108 {
        return Ok(());
    }
    Err("ce99c X1 = SP+#0x1a0 0x108 snapshot of param_1 header + param_2 fields; not HashChain*")
}

/// `*param_1` bit0 selects `FUN_008986c8` / `FUN_008cc148` (also 0x180).
pub fn admit_bosminer_8518d0_bit0_selects_alt_boxer() -> Result<(), &'static str> {
    if BOSMINER_PARENT_ALT_BL_INSN != 0x9401_1B48 {
        return Err("BL FUN_008986c8");
    }
    if BOSMINER_PARENT_ALT_FN_VA != 0x0089_86C8 {
        return Err("FUN_008986c8");
    }
    if BOSMINER_ALT_BOX_FN_VA != 0x008C_C148 {
        return Err("FUN_008cc148");
    }
    if BOSMINER_ALT_BOX_VT_VA != 0x019C_6D80 {
        return Err("vtable FUN_008e7638");
    }
    Ok(())
}

/// `FUN_008518d0` does not write HashChain `+0x228`.
pub fn refuse_8518d0_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_PARENT_STR228_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_PARENT_BL_HITS != 1 {
        return Ok(());
    }
    Err("0 STR #0x228 in FUN_008518d0; 0 ADD #0x19c/#0x11F0/#0x228; 1 parent BL")
}

/// `FUN_008790dc` is AM2 S17 `hashchainmessageevent` Future poll (vtable `0x19c0f90`).
pub fn admit_bosminer_8790dc_is_am2_s17_hashchain_msg_event() -> Result<(), &'static str> {
    if BOSMINER_MSG_EVT_FN_VA != 0x0087_90DC {
        return Err("FUN_008790dc");
    }
    if BOSMINER_MSG_EVT_ENTRY_INSN != 0xA9BA_7BFD {
        return Err("STP entry");
    }
    if BOSMINER_MSG_EVT_VT_VA != 0x019C_0F90 {
        return Err("vtable 0x19c0f90");
    }
    if BOSMINER_MSG_EVT_BL_HITS != 0 {
        return Err("0 BL; vtable poll only");
    }
    Ok(())
}

/// `FUN_008790dc` stages the 0x108 image at `SP+#0x2cc0` from `self+#0x2c70`.
pub fn admit_bosminer_8790dc_stages_108_at_sp_2cc0() -> Result<(), &'static str> {
    if BOSMINER_MSG_EVT_P2_ADD_HI_INSN != 0x9140_0BE1 {
        return Err("ADD X1,SP,#0x2000");
    }
    if BOSMINER_MSG_EVT_P2_ADD_LO_INSN != 0x9133_0021 {
        return Err("ADD X1,X1,#0xcc0");
    }
    if BOSMINER_MSG_EVT_STAGE_SP_OFF != 0x2CC0 {
        return Err("SP+#0x2cc0");
    }
    if BOSMINER_MSG_EVT_SRC_LDR_INSN != 0xF956_3A6A {
        return Err("LDR [X19,#0x2c70]");
    }
    if BOSMINER_MSG_EVT_BL_INSN != 0x97FF_609D {
        return Err("BL FUN_008518d0");
    }
    Ok(())
}

/// `self+#0x2c70` field cluster is not a HashChain with `+0x228`.
pub fn refuse_8790dc_2c70_as_hashchain_228_object() -> Result<(), &'static str> {
    if BOSMINER_MSG_EVT_SRC_OFF != 0x2C70 {
        return Ok(());
    }
    if BOSMINER_PARENT_IMAGE_SIZE != 0x108 {
        return Ok(());
    }
    Err("0x108 image staged from self+0x2c70; 0 ADD #0x19c/#0x11F0/#0x228 in FUN_008790dc")
}

/// `FUN_008790dc` does not write HashChain `+0x228`.
pub fn refuse_8790dc_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_MSG_EVT_STR228_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_MSG_EVT_WORKER_BL_INSN != 0x9401_E449 {
        return Ok(());
    }
    Err("0 STR #0x228 in FUN_008790dc; worker memcpy is 0x1c8 not +0x228")
}

/// All 10 AM3 `ADD X2,#0x228` form panic loc `0x19c6228` via `ADRP X2`.
pub fn admit_bosminer_am3_add228_is_panic_loc() -> Result<(), &'static str> {
    if BOSMINER_AM3_ADD228_ADRP_HITS != 10 {
        return Err("10 ADRP X2 then ADD #0x228");
    }
    if BOSMINER_AM3_ADD228_ADRP_INSN != 0xD000_87A2 {
        return Err("ADRP X2 @ 0x8d015c");
    }
    if BOSMINER_AM3_ADD228_LOC_VA != 0x019C_6228 {
        return Err("loc 0x19c6228");
    }
    if BOSMINER_AM3_HC_INIT_ADD228_INSN != 0x9108_A042 {
        return Err("ADD X2,X2,#0x228");
    }
    Ok(())
}

/// AM3 `ADD #0x228` is not `&HashChain+0x228`.
pub fn refuse_am3_add228_as_hashchain_field() -> Result<(), &'static str> {
    if BOSMINER_AM3_ADD228_ADRP_HITS != 10 {
        return Ok(());
    }
    if BOSMINER_AM3_ADD228_LOC_VA != 0x019C_6228 {
        return Ok(());
    }
    Err("10/10 ADD #0x228 follow ADRP X2 forming static loc 0x19c6228, not dest+0x228")
}

/// AM3 init bodies are Future poll with tag at `+0x80`.
pub fn admit_bosminer_am3_init_poll_tag_is_80() -> Result<(), &'static str> {
    if BOSMINER_AM3_INIT_TAG80_HITS != 5 {
        return Err("5 LDRB [X0,#0x80]");
    }
    if BOSMINER_AM3_INIT_TAG80_INSN != 0x3942_0008 {
        return Err("LDRB W8,[X0,#0x80]");
    }
    if BOSMINER_AM3_INIT_TAG80_VA != 0x008C_FAEC {
        return Err("FUN_008cfad0 tag load");
    }
    Ok(())
}

/// Instantiate prep X1 is `*param_1[2]`, not a newly allocated HashChain.
pub fn admit_bosminer_instantiate_x1_is_slot_deref() -> Result<(), &'static str> {
    if BOSMINER_INST_X1_LDR_INSN != 0xF940_0341 {
        return Err("LDR X1,[X26,#0]");
    }
    if BOSMINER_PREP_BL_A_INSN != 0x9400_5771 {
        return Err("BL FUN_0083b3a0");
    }
    if BOSMINER_INST_ARC_OFF != 0x2F0 {
        return Err("HashChain Arc +0x2f0");
    }
    if BOSMINER_INST_ARC_LDR_INSN != 0xF941_7909 {
        return Err("LDR [X8,#0x2f0]");
    }
    Ok(())
}

/// `FUN_0085c78c` supplies that slot from `self+0x260`.
pub fn admit_bosminer_5c78c_loads_hc_from_plus_260() -> Result<(), &'static str> {
    if BOSMINER_SRC5C_LDR260_INSN != 0xF941_32A9 {
        return Err("LDR X9,[X21,#0x260]");
    }
    if BOSMINER_SRC5C_BL_INSN != 0x97FF_983E {
        return Err("BL FUN_00842bb8");
    }
    if BOSMINER_SRC5C_FN_VA != 0x0085_C78C {
        return Err("FUN_0085c78c");
    }
    Ok(())
}

/// `FUN_00842bb8` allocates the result vec, not the HashChain.
pub fn refuse_42bb8_as_hashchain_allocator() -> Result<(), &'static str> {
    if BOSMINER_WRAP42_BL_INSN != 0x97FF_8A43 {
        return Ok(());
    }
    if BOSMINER_WRAP42_STR228_HITS != 0 {
        return Ok(());
    }
    Err("FUN_00842bb8 allocs result vec and calls instantiate; 0 STR #0x228")
}

/// `0x682090` `STR #0x228` is a Vec ptr after cap 8 at +0x218/+0x220.
pub fn refuse_682090_str228_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_VEC228_INSN != 0xF901_1677 {
        return Ok(());
    }
    if BOSMINER_VEC218_INSN != 0xF901_0E60 {
        return Ok(());
    }
    Err("FUN_00681c88 STR #8 at +0x218/+0x220 then STR X23 +0x228; Vec not HashChain")
}

/// `FUN_0085c78c` `self` is a 0x300-byte type with vtable `0x19ace88`.
pub fn admit_bosminer_5c78c_self_is_300() -> Result<(), &'static str> {
    if BOSMINER_SRC5C_TYPE_SIZE != 0x300 {
        return Err("vtable size qword 0x300");
    }
    if BOSMINER_SRC5C_TYPE_ALIGN != 0x10 {
        return Err("vtable align qword 0x10");
    }
    if BOSMINER_SRC5C_DROP_FN_VA != 0x006F_4F2C {
        return Err("drop FUN_006f4f2c");
    }
    if BOSMINER_SRC5C_VT_VA != 0x019A_CE88 {
        return Err("method0 FUN_0085c78c");
    }
    if BOSMINER_SRC5C_VT_ADRP_INSN != 0xF000_9521 {
        return Err("sole ADRP of 0x19ace70");
    }
    if BOSMINER_SRC5C_VT_ADD_INSN != 0x9139_C021 {
        return Err("ADD #0xe70");
    }
    Ok(())
}

/// `FUN_00705800` boxes that 0x300 image from `parent+0x3b0` (copy, not mint).
pub fn admit_bosminer_705800_boxes_300_from_parent_3b0() -> Result<(), &'static str> {
    if BOSMINER_BOX300_SRC_LDR_INSN != 0xF941_3298 {
        return Err("LDR X24,[X20,#0x260]");
    }
    if BOSMINER_BOX300_PARENT_OFF != 0x3B0 {
        return Err("parent +0x3b0");
    }
    if BOSMINER_BOX300_PARENT_LDR_INSN != 0xF941_D814 {
        return Err("LDR X20,[X0,#0x3b0]");
    }
    if BOSMINER_BOX300_MOVZ_INSN != 0x5280_6000 {
        return Err("MOVZ X0,#0x300");
    }
    if BOSMINER_BOX300_MEMCPY_SIZE_INSN != 0x5280_6002 {
        return Err("memcpy size 0x300");
    }
    if BOSMINER_BOX300_BL_HITS != 0 {
        return Err("0 BL; vtable/indirect only");
    }
    if BOSMINER_CLONE300_BL_HITS != 1 {
        return Err("FUN_008679ac has 1 BL");
    }
    Ok(())
}

/// `FUN_00836934` `STR #0x260` is a ticket-mask-future fn-ptr, not HashChain*.
pub fn refuse_836c34_str260_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_TICKET_MASK260_INSN != 0xF901_3148 {
        return Ok(());
    }
    if BOSMINER_TICKET_MASK260_FN_VA != 0x0089_B720 {
        return Ok(());
    }
    if BOSMINER_TICKET_MASK260_ADRP_INSN != 0xB000_0328 {
        return Ok(());
    }
    Err("FUN_00836934 STR X8,[X10,#0x260] is ADRP+ADD FUN_0089b720 (ticket-mask Future)")
}

/// Boxing the 0x300 container does not mint HashChain `+0x228`.
pub fn refuse_705800_as_hashchain_228_mint() -> Result<(), &'static str> {
    if BOSMINER_STR260_MOVZ300_NEAR_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_BOX300_SRC_LDR_INSN != 0xF941_3298 {
        return Ok(());
    }
    Err("0x300 box memcpy-copies existing +0x260 from parent+0x3b0; 0 MOVZ#0x300 near STR#0x260")
}

/// `FUN_00705464` stores the source object pointer at dest `+0x3b0`.
pub fn admit_bosminer_705464_stores_src_at_3b0() -> Result<(), &'static str> {
    if BOSMINER_PARENT3C0_MOV_SRC_INSN != 0xAA00_03F7 {
        return Err("MOV X23,X0 source");
    }
    if BOSMINER_PARENT3C0_MOV_DST_INSN != 0xAA08_03F6 {
        return Err("MOV X22,X8 dest");
    }
    if BOSMINER_PARENT3C0_STR3B0_INSN != 0xF901_DAD7 {
        return Err("STR X23,[X22,#0x3b0]");
    }
    if BOSMINER_PARENT3C0_STR2A0_INSN != 0xF901_52D7 {
        return Err("STR X23,[X22,#0x2a0] same source*");
    }
    if BOSMINER_PARENT3C0_TYPE_SIZE != 0x3C0 {
        return Err("parent type size 0x3c0");
    }
    Ok(())
}

/// Same ctor copies HashChain* from source `+0x260` into dest `+0x2e0`.
pub fn admit_bosminer_705464_copies_hc_to_2e0() -> Result<(), &'static str> {
    if BOSMINER_PARENT3C0_LDR260_INSN != 0xF941_32FB {
        return Err("LDR X27,[X23,#0x260]");
    }
    if BOSMINER_PARENT3C0_STR2E0_INSN != 0xF901_72DB {
        return Err("STR X27,[X22,#0x2e0]");
    }
    if BOSMINER_PARENT3C0_BL_HITS != 3 {
        return Err("3 BL to FUN_00705464");
    }
    Ok(())
}

/// Parent `+0x3b0` is a back-pointer to the 0x300 container, not HashChain*.
pub fn refuse_3b0_as_hashchain_pointer() -> Result<(), &'static str> {
    if BOSMINER_PARENT3C0_STR3B0_INSN != 0xF901_DAD7 {
        return Ok(());
    }
    if BOSMINER_PARENT3C0_MOV_SRC_INSN != 0xAA00_03F7 {
        return Ok(());
    }
    Err("STR +0x3b0 stores X23=X0 source object*; HashChain* is copied to +0x2e0")
}

/// `FUN_00705464` does not write HashChain `+0x228`.
pub fn refuse_705464_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_PARENT3C0_STR228_HITS != 0 {
        return Ok(());
    }
    Err("0 STR #0x228 in FUN_00705464; only copies existing +0x260 pointer")
}

/// Three clone callers load X0 from ELF `.data` pointer cells.
pub fn admit_bosminer_705464_callers_load_elf_statics() -> Result<(), &'static str> {
    if BOSMINER_CALL3C0_A_LDR_INSN != 0xF947_6800 {
        return Err("LDR X0,[X0,#0xed0]");
    }
    if BOSMINER_CALL3C0_B_LDR_INSN != 0xF946_9C00 {
        return Err("LDR X0,[X0,#0xd38]");
    }
    if BOSMINER_CALL3C0_C_LDR_INSN != 0xF945_0400 {
        return Err("LDR X0,[X0,#0xa08]");
    }
    if BOSMINER_CALL3C0_MOV_DST_INSN != 0xAA08_03F3 {
        return Err("MOV X19,X8 dest");
    }
    if BOSMINER_CALL3C0_MOVZ6_INSN != 0x5280_0026 {
        return Err("MOVZ X6,#1");
    }
    if BOSMINER_CALL3C0_BL_HITS != 0 {
        return Err("0 BL; vtable only");
    }
    Ok(())
}

/// Those cells already point at three static objects (vptr at +0).
pub fn admit_bosminer_call3c0_elf_objs_have_vptr() -> Result<(), &'static str> {
    if BOSMINER_CALL3C0_SLOT_A_VA != 0x01AC_EED0 {
        return Err("slot A 0x1aceed0");
    }
    if BOSMINER_CALL3C0_OBJ_A_VA != 0x01AE_01C0 {
        return Err("obj A 0x1ae01c0");
    }
    if BOSMINER_CALL3C0_VPTR_A != 0x0086_33A0 {
        return Err("vptr FUN_008633a0");
    }
    if BOSMINER_CALL3C0_VPTR_B != 0x0086_2C84 {
        return Err("vptr FUN_00862c84");
    }
    if BOSMINER_CALL3C0_VPTR_C != 0x0086_26A8 {
        return Err("vptr FUN_008626a8");
    }
    Ok(())
}

/// The three callers do not write HashChain* or `+0x228`.
pub fn refuse_call3c0_as_hashchain_260_mint() -> Result<(), &'static str> {
    if BOSMINER_CALL3C0_STR260_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_CALL3C0_STR228_HITS != 0 {
        return Ok(());
    }
    Err("3 callers: 0 STR #0x260/#0x228; X0 is an ELF static already constructed")
}

/// Static `+0` methods do not mint `+0x260` either.
pub fn refuse_call3c0_vptr_as_hashchain_260() -> Result<(), &'static str> {
    if BOSMINER_CALL3C0_VPTR_STR260_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_CALL3C0_VPTR_BL_HITS != 0 {
        return Ok(());
    }
    Err("FUN_008633a0/62c84/626a8: 0 STR #0x260, 0 BL; ELF +0x260 is still 0")
}

/// `FUN_00867740` is the static-object initializer (`X19=X8`, 3 `BL`).
pub fn admit_bosminer_867740_inits_static_obj() -> Result<(), &'static str> {
    if BOSMINER_INIT677_MOV_DST_INSN != 0xAA08_03F3 {
        return Err("MOV X19,X8 dest");
    }
    if BOSMINER_INIT677_BL_HITS != 3 {
        return Err("3 BL from vptr methods");
    }
    if BOSMINER_INIT677_BL_A_INSN != 0x9400_0FF0 {
        return Err("BL from FUN_008633a0");
    }
    if BOSMINER_INIT677_ENTRY_INSN != 0xD102_43FF {
        return Err("SUB SP entry");
    }
    Ok(())
}

/// First `+0x260` write is `STP.Q [X19,#0x250]` covering 32 bytes from `X9`.
pub fn admit_bosminer_867740_simd_covers_260() -> Result<(), &'static str> {
    if BOSMINER_INIT677_SIMD260_INSN != 0xAD12_8660 {
        return Err("STP.Q Q0,Q1,[X19,#0x250]");
    }
    if BOSMINER_INIT677_LDP_SRC_INSN != 0xAD40_0520 {
        return Err("LDP.Q from [X9,#0]");
    }
    if BOSMINER_INIT677_STR2E0_INSN != 0xF901_726B {
        return Err("STR X11,[X19,#0x2e0]");
    }
    Ok(())
}

/// No dedicated `STR X #0x260` in `FUN_00867740`.
pub fn refuse_867740_strx_260() -> Result<(), &'static str> {
    if BOSMINER_INIT677_STR260_HITS != 0 {
        return Ok(());
    }
    Err("0 STR X #0x260; +0x260 is the 2nd qword of STP.Q [X19,#0x250] from X9+0x10")
}

/// `STRH +0x228` is `param_16` u16, not a HashChain tag.
pub fn refuse_867740_strh228_as_hashchain_tag() -> Result<(), &'static str> {
    if BOSMINER_INIT677_STRH228_INSN != 0x7904_5268 {
        return Ok(());
    }
    Err("STRH W8,[X19,#0x228] stores param_16 low 16, not HashChain tag 1")
}

/// `FUN_00867740` X9 is caller `SP+#0x170` (`&local_120`).
pub fn admit_bosminer_x9_is_local120() -> Result<(), &'static str> {
    if BOSMINER_X9_LDR_SP_B8_INSN != 0xF940_5FE9 {
        return Err("LDR X9,[SP,#0xb8]");
    }
    if BOSMINER_X9_CALLER_ADD170_INSN != 0x9105_C3E8 {
        return Err("ADD X8,SP,#0x170");
    }
    if BOSMINER_X9_CALLER_STP20_INSN != 0xA902_23E9 {
        return Err("STP [SP,#0x20] = SP+0x160 / SP+0x170");
    }
    Ok(())
}

/// `local_110` / static `+0x260` is `*(0x1adfb28+0x10)` via slot `0x1acdf20`.
pub fn admit_bosminer_260_from_adfb28_plus_10() -> Result<(), &'static str> {
    if BOSMINER_X9_SLOT_LDR_INSN != 0xF947_92B5 {
        return Err("LDR X21,[X21,#0xf20]");
    }
    if BOSMINER_X9_OBJ_VA != 0x01AD_FB28 {
        return Err("ELF *0x1acdf20 = 0x1adfb28");
    }
    if BOSMINER_X9_OBJ_LDR10_INSN != 0xF940_0AA9 {
        return Err("LDR X9,[X21,#0x10]");
    }
    if BOSMINER_X9_LOCAL110_STR_INSN != 0xF900_C3E9 {
        return Err("STR X9,[SP,#0x180] local_110");
    }
    if BOSMINER_X9_SLOT_LDR_HITS != 3 {
        return Err("3 sibling loads of 0x1acdf20");
    }
    Ok(())
}

/// That `+0x10` field is ELF-zero, not a HashChain*.
pub fn refuse_adfb28_plus10_as_hashchain() -> Result<(), &'static str> {
    if BOSMINER_X9_OBJ_VPTR != 0x0086_31F0 {
        return Ok(());
    }
    if BOSMINER_X9_OBJ_LDR10_INSN != 0xF940_0AA9 {
        return Ok(());
    }
    Err("*(0x1adfb28+0x10) is 0 in ELF; SIMD copies that zero into static +0x260")
}

/// Ghidra `puVar6+0x10` = `0xbeee00` is the slot table, not the loaded object field.
pub fn refuse_beee00_as_static_260_source() -> Result<(), &'static str> {
    if BOSMINER_X9_SLOT_VA != 0x01AC_DF20 {
        return Ok(());
    }
    if BOSMINER_X9_OBJ_LDR10_INSN != 0xF940_0AA9 {
        return Ok(());
    }
    Err("LDR [X21,#0x10] uses X21=*0x1acdf20 (0x1adfb28), not 0x1acdf20+0x10 (0xbeee00)")
}

/// Exactly 6 true ADRP+LDR of the three ELF pointer cells (2 per caller).
pub fn admit_bosminer_true_slot_loads_are_six() -> Result<(), &'static str> {
    if BOSMINER_TRUE_SLOT_LDR_HITS != 6 {
        return Err("6 live-page slot LDRs");
    }
    if BOSMINER_TRUE_SLOT_A_ONCE_INSN != 0xF947_6AB5 {
        return Err("FUN_006f23a8 Once LDR X21");
    }
    if BOSMINER_CALL3C0_A_LDR_INSN != 0xF947_6800 {
        return Err("FUN_006f23a8 X0 LDR");
    }
    Ok(())
}

/// `FUN_008633a0` returns immediately after `BL FUN_00867740`.
pub fn admit_bosminer_633a0_returns_after_67740() -> Result<(), &'static str> {
    if BOSMINER_INIT677_BL_A_INSN != 0x9400_0FF0 {
        return Err("BL FUN_00867740");
    }
    if BOSMINER_INIT633_POST_BL_ADD_INSN != 0x9108_83FF {
        return Err("ADD SP,#0x220 epilogue");
    }
    if BOSMINER_INIT633_RET_INSN != 0xD65F_03C0 {
        return Err("RET");
    }
    Ok(())
}

/// No later `STR #0x260` after a true slot load, and no abs store to `0x1ae0420`.
pub fn refuse_later_overwrite_1ae0420() -> Result<(), &'static str> {
    if BOSMINER_OW260_ABS_STR_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_OW260_SLOT_STR_HITS != 0 {
        return Ok(());
    }
    Err("0 ADRP+STR 0x1ae0420; 0 STR#0x260 after 6 true slot LDRs; 633a0 RETs after SIMD copy")
}

/// `0xa25760` `LDR #0xed0` is page `0x1acd000` (`0x1acded0`), not slot A.
pub fn refuse_a25760_as_slot_a() -> Result<(), &'static str> {
    if BOSMINER_FAKE_SLOT_A25760_VA != 0x01AC_DED0 {
        return Ok(());
    }
    if BOSMINER_FAKE_SLOT_A25760_ADRP_INSN != 0x9000_854A {
        return Ok(());
    }
    Err("0xa25760 ADRP page 0x1acd000 +0xed0 = 0x1acded0, not 0x1aceed0")
}

/// `FUN_008631f0` is an X8-sret Default (0 BL, dest through X8, max STR +0x88).
pub fn admit_bosminer_8631f0_is_x8_sret_default() -> Result<(), &'static str> {
    if BOSMINER_INIT631_STR88_INSN != 0xB900_891F {
        return Err("STR WZR,[X8,#0x88]");
    }
    if BOSMINER_INIT631_STR10_INSN != 0xF900_090A {
        return Err("STR X10,[X8,#0x10]");
    }
    if BOSMINER_INIT631_BL_HITS != 0 {
        return Err("0 BL in FUN_008631f0");
    }
    if BOSMINER_INIT631_RET_INSN != 0xD65F_03C0 {
        return Err("RET");
    }
    if BOSMINER_INIT631_MAX_STR_OFF != 0x88 {
        return Err("max STR +0x88");
    }
    Ok(())
}

/// Sibling static is 0x98 bytes (next ELF object is  obj B).
pub fn admit_bosminer_adfb28_size_is_98() -> Result<(), &'static str> {
    if BOSMINER_SIBLING_SIZE != 0x98 {
        return Err("0x1adfbc0 - 0x1adfb28 = 0x98");
    }
    if BOSMINER_SIBLING_NEXT_VA != 0x01AD_FBC0 {
        return Err("next static is CALL3C0 obj B");
    }
    if BOSMINER_X9_OBJ_VA != 0x01AD_FB28 {
        return Err("sibling is 0x1adfb28");
    }
    Ok(())
}

/// `FUN_008631f0` is not a HashChain constructor.
pub fn refuse_8631f0_as_hashchain_ctor() -> Result<(), &'static str> {
    if BOSMINER_INIT631_MAX_STR_OFF != 0x88 {
        return Ok(());
    }
    if BOSMINER_INIT631_BL_HITS != 0 {
        return Ok(());
    }
    Err("FUN_008631f0 sret-inits a <=0x90 PSU-config (0.1/1.85/4000 f64s; +0x88 WZR); no +0x228")
}

/// `0x1adfb28+0x228` is not a HashChain field (0 xrefs; lands inside obj B).
pub fn refuse_adfb28_plus228_as_hashchain_field() -> Result<(), &'static str> {
    if BOSMINER_SIBLING_228_XREF_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_SIBLING_SIZE != 0x98 {
        return Ok(());
    }
    Err("0x1adfb28+0x228 has 0 xrefs and sits 0x190 into the 0x300 obj B; not a sibling field")
}

/// Five dest=`+#0x228` memcpys: two 0x1f0 field clones, two stack, one non-HC 0x200.
pub fn admit_dest228_memcpy_is_five_non_hashchain() -> Result<(), &'static str> {
    if BOSMINER_DEST228_MEMCPY_HITS != 5 {
        return Err("5 memcpy dest=Xn+#0x228");
    }
    if BOSMINER_CLONE228_MEMCPY_SIZE_INSN != 0x5280_3E02 {
        return Err("0x1f0 field-to-field clone");
    }
    if BOSMINER_DEST228_MEMCPY_ADD_INSN != 0x9108_A2A0 {
        return Err("FUN_0094fc6c ADD #0x228");
    }
    Ok(())
}

/// AM3 HashChain inits only form `&+0x228` for rustc panic line 34.
pub fn admit_am3_hashchain_add228_is_panic_ptr() -> Result<(), &'static str> {
    if BOSMINER_AM3_HC_INIT_ADD228_PANIC_HITS != 10 {
        return Err("10 ADD X2,X2,#0x228 panic sites");
    }
    if BOSMINER_AM3_HC_INIT_ADD228_INSN != 0x9108_A042 {
        return Err("ADD X2,X2,#0x228");
    }
    if BOSMINER_AM3_HC_INIT_PANIC_LINE_INSN != 0x5280_0441 {
        return Err("MOVZ W1,#0x22");
    }
    if BOSMINER_AM3_HC_INIT_PANIC_BL_INSN != 0x97EE_0D52 {
        return Err("BL FUN_004536b0");
    }
    Ok(())
}

/// No `MOVZ #1; STR W #0x228` on a non-SP base in the first LOAD.
pub fn refuse_movz1_strw_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_TAG1_STRW_NONSP_HITS != 0 {
        return Ok(());
    }
    Err("0 MOVZ #1 + STR W #0x228 (Xn!=SP); HashChain tag is not a 32-bit immediate 1 store")
}

/// `FUN_006079d4` `STR W #0x228` stores `0x01000000`, not tag 1, and not HashChain.
pub fn refuse_609a60_01000000_as_hashchain_tag() -> Result<(), &'static str> {
    if BOSMINER_TAG228_W1000000_MOVZ_INSN != 0x52A0_2008 {
        return Ok(());
    }
    if BOSMINER_TAG228_W1000000_STR_INSN != 0xB902_2A68 {
        return Ok(());
    }
    Err("FUN_006079d4 MOVZ W8,#0x100,LSL#16; STR W [X19,#0x228] = 0x01000000 on 0x250 object")
}

/// Prep snapshots HashChain `+0x228` with `LDR W`/`STR W`, not the two STRB sites.
pub fn admit_bosminer_prep_copies_hashchain_w228() -> Result<(), &'static str> {
    if BOSMINER_PREP_LDRW_228_INSN != 0xB942_2A9C {
        return Err("FUN_0083b3a0 LDR W28,[X20,#0x228]");
    }
    if BOSMINER_PREP_STRW_228_INSN != 0xB902_2A7C {
        return Err("FUN_0083b3a0 STR W28,[X19,#0x228]");
    }
    if BOSMINER_PREP_X20_MOV_INSN != 0xAA01_03F4 {
        return Err("X20=X1 HashChain source");
    }
    Ok(())
}

/// `FUN_0083b3a0` writes `+0x22c` from the source HashChain, not tag `+0x228`.
pub fn refuse_prep_22c_as_vt0_tag() -> Result<(), &'static str> {
    if BOSMINER_PREP_STRB_22C_INSN != 0x3908_B275 {
        return Ok(());
    }
    if BOSMINER_PREP_STR88_HITS != 0 {
        return Ok(());
    }
    Err("FUN_0083b3a0 STRB [X19,#0x22c] copies source+0x22c; 0 STRB #0x228 in prep")
}

/// HashMap value+8 is BM1366 vtable[0] (`FUN_008dbdf4`), not `FUN_00876ca8`.
pub fn admit_bosminer_value_plus8_is_bm1366_vt0() -> Result<(), &'static str> {
    if BOSMINER_DISPATCH_VT0_LDR_INSN != 0xF945_754A {
        return Err("LDR X10 from PTR_FUN_01acdae8");
    }
    if BOSMINER_BM1366_VT0_FN_VA != 0x008D_BDF4 {
        return Err("*(0x1acdae8) == FUN_008dbdf4");
    }
    if BOSMINER_INSERT_VALUE_ORR8_INSN != 0xB27D_02A3 {
        return Err("insert value src = &entry|8");
    }
    if BOSMINER_DISPATCH_1366_STP_INSN != 0xA902_ABE8 {
        return Err("STP factory, vt0");
    }
    Ok(())
}

/// SP+0x1640 is a clone of factory X1 (chip_id at +0x19c), not a new +0x11F0 count.
pub fn refuse_sp1640_clone_as_named_div_integer() -> Result<(), &'static str> {
    if BOSMINER_SP1640_CLONE_BL_INSN != 0x9400_2342 {
        return Ok(());
    }
    if BOSMINER_SP1640_CLONE_SRC_INSN != 0xAA18_03E1 {
        return Ok(());
    }
    if BOSMINER_HASHMAP_GET_KEY_OFF != 0x19C {
        return Ok(());
    }
    Err("FUN_0087fb4c clones X24 (factory X1) onto SP+0x1640; copies chip_id +0x19c; not a named *(+0x11F0) store")
}

/// ESP/AMTC `asic_index_from_nonce_be` is `(nonce>>17)&0xff / 2`, not the
/// Braiins BM1366 callback plus `FUN_00bf3264` path.
pub fn refuse_asic_index_from_nonce_be_as_bf3264() -> Result<(), &'static str> {
    Err("ESP/AMTC bits17..24 attribution is not Braiins BM1366 FUN_009256ac + FUN_00bf3264")
}

/// RX inverse + registry fit names the TX formula. Pointer body still unnamed.
pub fn admit_bosminer_uart_job_id_is_work_id_shl_log() -> Result<(), &'static str> {
    if BOSMINER_WORK_RESP_JOB_SHIFT != 0x28 {
        return Err("FUN_0091c0a0 job byte is u64>>0x28");
    }
    if BOSMINER_ENGINE_NONCE_FN_OFF != 0x88 {
        return Err("engine+0x88 is the work-response attribution callback");
    }
    if BOSMINER_PACK_CALLER_LSL_COUNT_INSN != 0x9ACA_2121 {
        return Err("pack-caller second arg is LSL X1,X9,X10 (1<<log)");
    }
    if s19k_braiins_uart_job_id(7, 0)? != 7 {
        return Err("fill midstates=1 ⇒ log=0 ⇒ job_id=work_id");
    }
    if s19k_braiins_uart_job_id(7, 3)? != 0x38 {
        return Err("log=3 ⇒ job_id=work_id<<3");
    }
    if s19k_braiins_uart_work_id_from_rx_job_byte(0x38, 3)? != 7 {
        return Err("RX inverse 0x38>>3 must be work_id 7");
    }
    Ok(())
}

/// `FUN_00875f54` only copies factory X1 `[0x12]`. Not the first writer.
pub fn refuse_factory_clone_as_first_writer_of_job_id_fn() -> Result<(), &'static str> {
    Err("FUN_00875f54 copies factory X1[0x12] onto Worker+0x90; first STR of a .text encoder is still unlocated")
}

/// `FUN_0125fc94`: count 1→log 0; else trailing zeros if 2/4/8.
pub fn s19k_braiins_midstate_log_from_count(count: u32) -> Result<u32, &'static str> {
    if count == 0 {
        return Err("BUG: zero midstates (FUN_0125fc94)");
    }
    if !count.is_power_of_two() {
        return Err("BUG: number of midstates not a power of 2 (midstate_count.rs)");
    }
    let log = count.trailing_zeros();
    if log > BOSMINER_MIDSTATE_LOG_MAX {
        return Err("invalid midstate count logarithm (FUN_0092f200, log>=4)");
    }
    Ok(log)
}

/// Argument to engine+0x88: `REV` of the LE-loaded payload low 32.
/// That is `from_be` of UART bytes [0:4] (ESP nonce word).
pub fn s19k_braiins_uart_nonce_arg_from_payload8(payload_le: u64) -> u32 {
    (payload_le as u32).swap_bytes()
}

/// Canonical callback nonce word after `REV`. This compatibility helper is
/// identity because its input is already the BE interpretation of UART bytes,
/// not because engine+0x88 returns a nonce. BM1366 engine+0x88 is the
/// attribution callback `FUN_009256ac`; `FUN_0091c0a0` stores the original
/// LE-loaded payload low32 separately at WorkResponse+0x30.
pub fn s19k_braiins_fill_nonce_word(uart_nonce_be: u32) -> u32 {
    uart_nonce_be
}

/// Retired inference kept as an explicit refusal for callers/tests that still
/// treat the +0x88 BLR return as a nonce word.
pub fn admit_bosminer_work_resp_blr_return_is_nonce() -> Result<(), &'static str> {
    Err("BM1366 +0x88 returns (encoded chip address, core); raw nonce is stored at WorkResponse+0x30")
}

/// `+0x80 != 1` is a panic/ADRP path, not a second response callback.
pub fn refuse_plus80_ne1_as_alt_nonce_transform() -> Result<(), &'static str> {
    Err("FUN_0091c0a0 +0x80!=1 branches to 0x91c1b0 ADRP/panic, not another response callback")
}

/// : `LDRB [X21,#0x80]; CMP #1` is the `bm1398_6x.rs:344` work-type tag.
pub fn admit_bosminer_plus80_is_work_type_tag() -> Result<(), &'static str> {
    if BOSMINER_ENGINE_WORK_TYPE_OFF != 0x80 {
        return Err("work-type tag is engine+0x80");
    }
    if BOSMINER_WORK_TYPE_VERSION_ROLLING != 1 {
        return Err("fill/VR work type is 1");
    }
    if BOSMINER_WORK_RESP_PLUS80_ADRP_INSN != 0xB000_5040 {
        return Err("ADRP X0 @ 0x91c1b0");
    }
    if BOSMINER_WORK_RESP_PLUS80_ADD_INSN != 0x9112_3C00 {
        return Err("ADD X0,#0x48F -> 0x132548f");
    }
    if BOSMINER_WORK_RESP_PLUS80_MOVZ_LEN_INSN != 0x5280_0601 {
        return Err("MOVZ W1,#0x30 message len 48");
    }
    if BOSMINER_WORK_RESP_PLUS80_LINE != 344 || BOSMINER_WORK_RESP_PLUS80_COL != 21 {
        return Err("Location is bm1398_6x.rs:344:21");
    }
    if BOSMINER_WORK_RESP_PLUS80_PANIC_MSG.len() != 48 {
        return Err("panic message is 48 bytes");
    }
    if BOSMINER_BM1398_6X_RS.len() != 48 {
        return Err("bm1398_6x.rs path is 48 bytes");
    }
    if BOSMINER_WORK_RESP_NOT_WORK_LINE != 319 || BOSMINER_WORK_RESP_NOT_WORK_MSG_LEN != 0x18 {
        return Err("sibling panic is Not a work response @ line 319");
    }
    Ok(())
}

/// Fill RX is only defined for version-rolling work-type `1`.
pub fn refuse_midstates_work_type_on_braiins_fill_rx(work_type: u8) -> Result<(), &'static str> {
    if work_type != BOSMINER_WORK_TYPE_VERSION_ROLLING {
        return Err("bm1398_6x.rs:344 BUG: Midstates work type in version-rolling mode");
    }
    Ok(())
}

/// `pic0x88.rs` is an AM2 PIC firmware module, not engine+0x88.
pub fn refuse_pic0x88_as_engine_plus88() -> Result<(), &'static str> {
    Err("pic0x88.rs is AM2 PIC firmware; BM1366 engine+0x88 is an attribution callback")
}

/// AM3 `LDRB [X0,#0x80]` is Future poll, not this work-type tag.
pub fn refuse_am3_future_plus80_as_work_type() -> Result<(), &'static str> {
    Err("AM3 LDRB [X0,#0x80] @ FUN_008cfad0 is Future poll; work-type is LDRB [X21,#0x80] in FUN_0091c0a0")
}

/// : work-type `engine+0x80` **is** `FUN_00bf2478` tag `self+0x20`.
pub fn admit_bosminer_plus80_is_verwidth_tag() -> Result<(), &'static str> {
    if BOSMINER_ENGINE_WORK_TYPE_OFF
        != BOSMINER_ENGINE_VERWIDTH_SELF_OFF + BOSMINER_VERWIDTH_TAG_OFF
    {
        return Err("engine+0x80 == verwidth-self+0x20");
    }
    if BOSMINER_WORK_RESP_MOV_X21_ENGINE_INSN != 0xAA01_03F5 {
        return Err("MOV X21,X1 — parse engine is X1");
    }
    if BOSMINER_WORK_RESP_ADD60_INSN != 0x9101_82A0 {
        return Err("ADD X0,X21,#0x60 feeds FUN_00bf2478 self");
    }
    if BOSMINER_VERWIDTH_LDRB20_INSN != 0x3940_8008 {
        return Err("verwidth LDRB [X0,#0x20] is the same tag");
    }
    if BOSMINER_VERWIDTH_PARSE_BL_TARGET_VA != BOSMINER_VERWIDTH_FN_VA {
        return Err("parse BL 0x940B58DD targets FUN_00bf2478 entry, not +4");
    }
    if BOSMINER_VERWIDTH_CMP_VA != BOSMINER_VERWIDTH_FN_VA + 4 {
        return Err("CMP #1 is entry+4, not the BL target");
    }
    if BOSMINER_VERWIDTH_CMP_INSN != 0x7100_051F {
        return Err("entry+4 is CMP #1");
    }
    if BOSMINER_ENGINE_MIDSTATE_COUNT_OFF != BOSMINER_ENGINE_VERWIDTH_SELF_OFF + 0x18 {
        return Err("count at engine+0x78 = verwidth+0x18");
    }
    Ok(())
}

/// UART fill parse never takes `FUN_00bf2478`'s already-log (`+0x10`) arm.
pub fn refuse_verwidth_else_as_uart_fill_path() -> Result<(), &'static str> {
    Err("FUN_0091c0a0 panics on work-type!=1 before BL 0xbf2478; else LDR [X0,#0x10] is dead on fill UART")
}

/// A64 `BL` target is the insn VA plus `imm26<<2`. `0x940B58DD` @ `0x91c104`
/// is `0xbf2478`, not mid-entry `0xbf247c`.
pub fn refuse_verwidth_mid_entry_as_parse_bl_target() -> Result<(), &'static str> {
    Err("parse BL 0x940B58DD targets FUN_00bf2478 entry; CMP @ +4 is not a mid-entry BL")
}

/// Lone `RET` cannot name the +0x88 callee.
pub fn refuse_ret_only_as_named_plus88() -> Result<(), &'static str> {
    if BOSMINER_RET_ONLY_SITES != 269 || BOSMINER_RET_ONLY_DATA_PTRS != 220 {
        return Err("RET-only census drift");
    }
    Err("269 RET-only sites / 220 DATA ptrs; rustc identity cannot name +0x88")
}

/// Factory/template DATA cannot name +0x88 ( offline exhaustion).
pub fn refuse_factory_data_as_named_plus88() -> Result<(), &'static str> {
    if BOSMINER_FACTORY_DATA_PTR_HITS != 0 {
        return Err("factory DATA ptr census drift");
    }
    if BOSMINER_ADRP_TEXT_NONSP_STR88_RET_HITS != 0 {
        return Err("ADRP.text non-SP STR#0x88 RET census drift");
    }
    if BOSMINER_REV_W0_RET_HITS != 0 {
        return Err("REV W0,W0;RET appeared — re-check swap_bytes leaf");
    }
    Err(
        "0 DATA ptrs to FUN_00876ca8; 0 ADRP.text non-SP STR#0x88 of RET/REV; factory X1 is runtime X24",
    )
}

/// Factory X1 is `X24` from `FUN_0087e02c`, not a rodata engine template.
pub fn admit_bosminer_factory_x1_is_runtime_x24() -> Result<(), &'static str> {
    if BOSMINER_FACTORY_X1_FROM_X24_INSN != 0xAA18_03E1 {
        return Err("MOV X1,X24 @ 0x87e1c8");
    }
    if BOSMINER_HC290_STR_INSN != 0xF901_4AFA {
        return Err("STR X26,[X23,#0x290] @ 0x878c98");
    }
    if BOSMINER_FACTORY_DATA_PTR_HITS != 0 {
        return Err("factory must not appear as a DATA u64");
    }
    Ok(())
}

/// bm1366.rs `STR [X19,#0x88]` is a `FUN_008d9984` Result, not the nonce fn.
pub fn refuse_bm1366_str88_result_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_BM1366_STR88_RESULT_INSN != 0xF900_4660 {
        return Ok(());
    }
    Err("FUN_008dc95c STR X0,[X19,#0x88] is BL FUN_008d9984 Result, not a .text nonce fn")
}

/// Stripped bosminer has no `.rustc` / `core::convert::identity` to name +0x88.
pub fn refuse_rustc_metadata_as_named_plus88() -> Result<(), &'static str> {
    if BOSMINER_RUSTC_SECTION_PRESENT {
        return Err(".rustc section appeared — re-open metadata hunt");
    }
    if BOSMINER_IDENTITY_STR_HITS != 0 {
        return Err("identity string appeared — re-bind +0x88");
    }
    if !BOSMINER_RUSTC_VERSION.starts_with("rustc version 1.87.0") {
        return Err("rustc .comment version drift");
    }
    if BOSMINER_ELF_SHNUM != 18 {
        return Err("ELF shnum drift");
    }
    Err("no .rustc section; no core::convert::identity; rustc 1.87.0 .comment cannot name +0x88")
}

/// `FUN_00bf3264` is the work-response **index**, not the pool nonce.
pub fn refuse_work_resp_low8_div_as_pool_nonce() -> Result<(), &'static str> {
    Err("FUN_00bf3264 (X1&0xff)/*Worker+0x11c0 is index; pool nonce is the full REV/+0x88 word")
}

/// Chip 0x1366 dispatch ADRP+ADD lands on factory `FUN_00876ca8`.
pub fn admit_bosminer_1366_factory_is_876ca8() -> Result<(), &'static str> {
    if BOSMINER_BM1366_DISPATCH_MOVZ_INSN != 0x5282_6CCA {
        return Err("dispatch MOVZ W10,#0x1366");
    }
    if BOSMINER_BM1366_DISPATCH_ADD_INSN != 0x9132_A108 {
        return Err("dispatch ADD X8,X8,#0xCA8");
    }
    if BOSMINER_BM1366_FACTORY_FN_VA != 0x0087_6CA8 {
        return Err("0x876000+0xCA8 is FUN_00876ca8");
    }
    if BOSMINER_BM1366_FACTORY_PROLOGUE_INSN != 0xA9BA_7BFD {
        return Err("factory prologue STP X29,X30");
    }
    Ok(())
}

/// Clone copies the 16B at X1+136 onto dest+136 (Worker+0x88 fn ptr).
pub fn admit_bosminer_clone_copies_plus88_qword() -> Result<(), &'static str> {
    if BOSMINER_CLONE_Q88_OFF != 0x88 {
        return Err("Q copy offset must be 136");
    }
    if BOSMINER_CLONE_LDUR_Q88_INSN != 0x3CC8_8285 {
        return Err("LDUR Q5,[X20,#136]");
    }
    if BOSMINER_CLONE_STUR_Q88_INSN != 0x3C88_8265 {
        return Err("STUR Q5,[X19,#136]");
    }
    if BOSMINER_CLONE_DEST_MOV_INSN != 0xAA00_03F3 {
        return Err("clone dest is not MOV X19,X0");
    }
    if BOSMINER_CLONE_SRC_MOV_INSN != 0xAA01_03F4 {
        return Err("clone src is not MOV X20,X1");
    }
    Ok(())
}

/// Five AM3 factories `MOV X24,X1` then `BL FUN_00875f54` (0x588 stride).
pub fn admit_bosminer_factory_clone_bl_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FACTORY_CLONE_BL_HITS != 5 {
        return Err("factory clone-BL census drifted");
    }
    if BOSMINER_FACTORY_CLONE_BL_VA[1] - BOSMINER_FACTORY_CLONE_BL_VA[0]
        != BOSMINER_FACTORY_CLONE_BL_STRIDE
    {
        return Err("factory clone-BL stride is not 0x588");
    }
    if BOSMINER_FACTORY_CLONE_BL_VA[1] != BOSMINER_BM1366_FACTORY_FN_VA + 0x7C {
        return Err("FUN_00876ca8+0x7c is not the BM1366 factory clone BL");
    }
    for i in 0..BOSMINER_FACTORY_CLONE_BL_HITS {
        let bl_va = BOSMINER_FACTORY_CLONE_BL_VA[i];
        let bl = engine88_le_u32(blob, bl_va).ok_or("bosminer shorter than factory clone BL")?;
        if bl != BOSMINER_FACTORY_CLONE_BL_INSN[i] {
            return Err("factory clone BL encoding drifted");
        }
        let save = engine88_le_u32(blob, bl_va - BOSMINER_FACTORY_X1_SAVE_TO_CLONE_BL)
            .ok_or("bosminer shorter than factory X1 save")?;
        if save != BOSMINER_FACTORY_X1_SAVE_INSN_CLONE {
            return Err("factory does not MOV X24,X1 before clone");
        }
    }
    let dest = engine88_le_u32(blob, BOSMINER_CLONE_DEST_MOV_VA)
        .ok_or("bosminer shorter than clone dest MOV")?;
    if dest != BOSMINER_CLONE_DEST_MOV_INSN {
        return Err("0x875f74 is not MOV X19,X0");
    }
    let src = engine88_le_u32(blob, BOSMINER_CLONE_SRC_MOV_VA)
        .ok_or("bosminer shorter than clone src MOV")?;
    if src != BOSMINER_CLONE_SRC_MOV_INSN {
        return Err("0x875f80 is not MOV X20,X1");
    }
    let ldur = engine88_le_u32(blob, BOSMINER_CLONE_LDUR_Q88_VA)
        .ok_or("bosminer shorter than clone LDUR Q5")?;
    if ldur != BOSMINER_CLONE_LDUR_Q88_INSN {
        return Err("0x875fac is not LDUR Q5,[X20,#136]");
    }
    let stur = engine88_le_u32(blob, BOSMINER_CLONE_STUR_Q88_VA)
        .ok_or("bosminer shorter than clone STUR Q5")?;
    if stur != BOSMINER_CLONE_STUR_Q88_INSN {
        return Err("0x8761d4 is not STUR Q5,[X19,#136]");
    }
    Ok(())
}

/// Copied +0x88 qword is factory `X1` contents, not a `.text` identity leaf.
pub fn refuse_clone_q88_as_named_text_identity() -> Result<(), &'static str> {
    Err(
        "FUN_00875f54 copies 16B from X1+0x88; five factories pass saved X1; not ADRP of a named identity .text",
    )
}

/// Prep `FUN_0083b3a0` copies source `X1+136` via `Q5` onto `SP+0x230+136`.
pub fn admit_bosminer_prep_q88_from_x1(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_PREP_Q88_LDUR_INSN != BOSMINER_CLONE_LDUR_Q88_INSN {
        return Err("prep LDUR Q5 encoding must match clone LDUR Q5");
    }
    if BOSMINER_PREP_Q88_STUR_INSN == BOSMINER_CLONE_STUR_Q88_INSN {
        return Err("prep STUR dest must stay X11, not clone dest X19");
    }
    if BOSMINER_PREP_Q88_STACK_BASE != 0x230 {
        return Err("prep Q dest base is SP+0x230");
    }
    if BOSMINER_PREP_STR88_HITS != 0 {
        return Err("prep grew a STR #0x88 — re-open dest identity");
    }
    let mov = engine88_le_u32(blob, BOSMINER_PREP_X20_MOV_VA)
        .ok_or("bosminer shorter than prep MOV X20,X1")?;
    if mov != BOSMINER_PREP_X20_MOV_INSN {
        return Err("0x83b3d4 is not MOV X20,X1");
    }
    let ldur = engine88_le_u32(blob, BOSMINER_PREP_Q88_LDUR_VA)
        .ok_or("bosminer shorter than prep LDUR Q5")?;
    if ldur != BOSMINER_PREP_Q88_LDUR_INSN {
        return Err("0x83b400 is not LDUR Q5,[X20,#136]");
    }
    let add = engine88_le_u32(blob, BOSMINER_PREP_Q88_DEST_ADD_VA)
        .ok_or("bosminer shorter than prep ADD X11,SP,#0x230")?;
    if add != BOSMINER_PREP_Q88_DEST_ADD_INSN {
        return Err("0x83b578 is not ADD X11,SP,#0x230");
    }
    let stur = engine88_le_u32(blob, BOSMINER_PREP_Q88_STUR_VA)
        .ok_or("bosminer shorter than prep STUR Q5")?;
    if stur != BOSMINER_PREP_Q88_STUR_INSN {
        return Err("0x83b630 is not STUR Q5,[X11,#136]");
    }
    Ok(())
}

/// `FUN_00835220` saves `X2` as `X19` and that becomes prep `X1`.
pub fn admit_bosminer_get_caller_x2_is_prep_source(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_GET_PREP_X1_INSN != BOSMINER_PREP_SRC_MOV_INSN {
        return Err("GET_PREP_X1 must stay the Wave-60 MOV X1,X19");
    }
    if BOSMINER_GET_PREP_X1_VA + 4 != BOSMINER_FACTORY_PREP_BL_VA {
        return Err("MOV X1,X19 is not immediately before BL FUN_0083b3a0");
    }
    let x19 = engine88_le_u32(blob, BOSMINER_GET_X19_FROM_X2_VA)
        .ok_or("bosminer shorter than MOV X19,X2")?;
    if x19 != BOSMINER_GET_X19_FROM_X2_INSN {
        return Err("0x835240 is not MOV X19,X2");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_GET_PREP_X1_VA)
        .ok_or("bosminer shorter than get-caller MOV X1,X19")?;
    if x1 != BOSMINER_GET_PREP_X1_INSN {
        return Err("0x8352dc is not MOV X1,X19");
    }
    let bl = engine88_le_u32(blob, BOSMINER_FACTORY_PREP_BL_VA)
        .ok_or("bosminer shorter than BL prep")?;
    if bl != BOSMINER_FACTORY_PREP_BL_INSN {
        return Err("0x8352e0 is not BL FUN_0083b3a0");
    }
    Ok(())
}

/// Production `FUN_0087e02c` passes two objects: `X2=SP+0x2e0`, `X1=X24`.
pub fn admit_bosminer_prod_two_templates(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_PREP_TEMPLATE_STACK_OFF != 0x2E0 {
        return Err("prep source stack slot is SP+0x2e0");
    }
    if BOSMINER_PREP_TEMPLATE_STACK_OFF == BOSMINER_PREP_Q88_STACK_BASE {
        return Err("prep dest SP+0x230 must not equal source SP+0x2e0");
    }
    if BOSMINER_PROD_CALL_X1_MOV_INSN != BOSMINER_FACTORY_X1_FROM_X24_INSN {
        return Err("prod X1 MOV must stay Wave-123 MOV X1,X24");
    }
    if BOSMINER_PROD_CALL_X1_MOV_VA != BOSMINER_FACTORY_X1_FROM_X24_VA {
        return Err("prod X1 VA must stay 0x87e1c8");
    }
    let x0 = engine88_le_u32(blob, BOSMINER_PROD_CONSTRUCT_X0_ADD_VA)
        .ok_or("bosminer shorter than ADD X0,SP,#0x2e0")?;
    if x0 != BOSMINER_PROD_CONSTRUCT_X0_ADD_INSN {
        return Err("0x87e190 is not ADD X0,SP,#0x2e0");
    }
    let x2 = engine88_le_u32(blob, BOSMINER_PROD_CALL_X2_ADD_VA)
        .ok_or("bosminer shorter than ADD X2,SP,#0x2e0")?;
    if x2 != BOSMINER_PROD_CALL_X2_ADD_INSN {
        return Err("0x87e1c0 is not ADD X2,SP,#0x2e0");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_PROD_CALL_X1_MOV_VA)
        .ok_or("bosminer shorter than MOV X1,X24")?;
    if x1 != BOSMINER_PROD_CALL_X1_MOV_INSN {
        return Err("0x87e1c8 is not MOV X1,X24");
    }
    Ok(())
}

/// Prep `X2` / `SP+0x2e0` is not the factory clone source.
pub fn refuse_prep_x2_as_factory_x1() -> Result<(), &'static str> {
    Err(
        "FUN_0087e02c X2=SP+0x2e0 is prep/HashChain source; X1=X24 is factory clone source; not one object",
    )
}

/// Prep `Q5` dest is stack `SP+0x230`, not factory dest `X19` / Worker+0x88.
pub fn refuse_prep_q88_dest_as_factory_dest() -> Result<(), &'static str> {
    Err(
        "FUN_0083b3a0 STUR Q5,[X11,#136] with X11=SP+0x230; dest X19 has 0 STR #0x88; not Worker+0x88",
    )
}

/// `FUN_0087fb4c` is a dest/src wrapper that `BL`s factory clone `FUN_00875f54`.
pub fn admit_bosminer_87fb4c_wraps_clone(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_SP1640_CLONE_FN_VA != 0x0087_FB4C {
        return Err("wrapper must stay FUN_0087fb4c");
    }
    if BOSMINER_WRAP_CLONE_DEST_MOV_INSN != BOSMINER_CLONE_DEST_MOV_INSN {
        return Err("wrapper dest MOV must stay MOV X19,X0");
    }
    if BOSMINER_WRAP_CLONE_SRC_MOV_INSN != BOSMINER_CLONE_SRC_MOV_INSN {
        return Err("wrapper src MOV must stay MOV X20,X1");
    }
    if BOSMINER_WRAP_CLONE_BL_VA != BOSMINER_SP1640_CLONE_FN_VA + 0x34 {
        return Err("wrapper BL is not FUN_0087fb4c+0x34");
    }
    let dest = engine88_le_u32(blob, BOSMINER_WRAP_CLONE_DEST_MOV_VA)
        .ok_or("bosminer shorter than wrapper dest MOV")?;
    if dest != BOSMINER_WRAP_CLONE_DEST_MOV_INSN {
        return Err("0x87fb70 is not MOV X19,X0");
    }
    let src = engine88_le_u32(blob, BOSMINER_WRAP_CLONE_SRC_MOV_VA)
        .ok_or("bosminer shorter than wrapper src MOV")?;
    if src != BOSMINER_WRAP_CLONE_SRC_MOV_INSN {
        return Err("0x87fb78 is not MOV X20,X1");
    }
    let bl = engine88_le_u32(blob, BOSMINER_WRAP_CLONE_BL_VA)
        .ok_or("bosminer shorter than wrapper BL clone")?;
    if bl != BOSMINER_WRAP_CLONE_BL_INSN {
        return Err("0x87fb80 is not BL FUN_00875f54");
    }
    Ok(())
}

/// Production builds prep `SP+0x2e0` by cloning context `X22`, not factory `X24`.
pub fn admit_bosminer_prod_prep_source_is_x22_clone(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_PROD_WRAP_BL_VA != BOSMINER_PROD_CONSTRUCT_X0_ADD_VA + 8 {
        return Err("BL wrapper is not ADD X0,SP,#0x2e0 + 8");
    }
    if BOSMINER_PROD_WRAP_SRC_MOV_VA + 4 != BOSMINER_PROD_WRAP_BL_VA {
        return Err("MOV X1,X22 is not immediately before BL wrapper");
    }
    if BOSMINER_PROD_WRAP_SRC_MOV_INSN == BOSMINER_FACTORY_X1_FROM_X24_INSN {
        return Err("prep-source clone src must not be MOV X1,X24");
    }
    let ctx = engine88_le_u32(blob, BOSMINER_PROD_CTX_MOV_VA)
        .ok_or("bosminer shorter than MOV X22,X0")?;
    if ctx != BOSMINER_FACTORY_CTX_MOV_INSN {
        return Err("0x87e044 is not MOV X22,X0");
    }
    let dest = engine88_le_u32(blob, BOSMINER_PROD_CONSTRUCT_X0_ADD_VA)
        .ok_or("bosminer shorter than ADD X0,SP,#0x2e0")?;
    if dest != BOSMINER_PROD_CONSTRUCT_X0_ADD_INSN {
        return Err("0x87e190 is not ADD X0,SP,#0x2e0");
    }
    let src = engine88_le_u32(blob, BOSMINER_PROD_WRAP_SRC_MOV_VA)
        .ok_or("bosminer shorter than MOV X1,X22")?;
    if src != BOSMINER_PROD_WRAP_SRC_MOV_INSN {
        return Err("0x87e194 is not MOV X1,X22");
    }
    let bl = engine88_le_u32(blob, BOSMINER_PROD_WRAP_BL_VA)
        .ok_or("bosminer shorter than BL FUN_0087fb4c")?;
    if bl != BOSMINER_PROD_WRAP_BL_INSN {
        return Err("0x87e198 is not BL FUN_0087fb4c");
    }
    Ok(())
}

/// `SP+0x2e0+0x88` is a clone of context `X22`, not factory `X24`.
pub fn refuse_prod_sp2e0_as_factory_x24_clone() -> Result<(), &'static str> {
    Err(
        "FUN_0087e02c clones X22 onto SP+0x2e0 via FUN_0087fb4c; factory X24 clone is the SP+0x1640 site",
    )
}

fn e02c_second_load_off(va: u64) -> Option<usize> {
    va.checked_sub(0x410_000).map(|o| o as usize)
}

fn e02c_le_u64(blob: &[u8], va: u64) -> Option<u64> {
    let i = e02c_second_load_off(va)?;
    blob.get(i..i + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

/// `FUN_0087e02c` is method 0 of two `0x2a0` rust vtables (fixture.rs / hardware.rs).
pub fn admit_bosminer_e02c_is_0x2a0_vtable_method(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_E02C_VTABLE_HITS != 2 {
        return Err("FUN_0087e02c DATA ptr census drifted");
    }
    if BOSMINER_E02C_TYPE_SIZE != BOSMINER_INSTANTIATE_SNAP_SIZE {
        return Err("e02c type size must stay the 0x2a0 instantiate snap");
    }
    if BOSMINER_E02C_TYPE_ALIGN != 0x10 {
        return Err("e02c type align is 16");
    }
    if BOSMINER_FIXTURE_RS.len() != BOSMINER_FIXTURE_RS_LEN {
        return Err("fixture.rs path length is not 0x43");
    }
    if BOSMINER_HARDWARE_RS.len() != BOSMINER_HARDWARE_RS_LEN {
        return Err("hardware.rs path length is not 0x2e");
    }
    if BOSMINER_E02C_TYPE_SIZE <= BOSMINER_CLONE_Q88_OFF {
        return Err("0x2a0 type must contain +0x88");
    }
    for i in 0..BOSMINER_E02C_VTABLE_HITS {
        let slot = e02c_le_u64(blob, BOSMINER_E02C_VTABLE_VA[i])
            .ok_or("bosminer shorter than e02c vtable slot")?;
        if slot != BOSMINER_PROD_FN_VA {
            return Err("vtable method 0 is not FUN_0087e02c");
        }
        let size = e02c_le_u64(
            blob,
            BOSMINER_E02C_VTABLE_VA[i] - BOSMINER_E02C_SIZE_BEFORE_SLOT,
        )
        .ok_or("bosminer shorter than e02c type size")?;
        if size != BOSMINER_E02C_TYPE_SIZE as u64 {
            return Err("vtable size word is not 0x2a0");
        }
        let align = e02c_le_u64(
            blob,
            BOSMINER_E02C_VTABLE_VA[i] - BOSMINER_E02C_SIZE_BEFORE_SLOT + 8,
        )
        .ok_or("bosminer shorter than e02c type align")?;
        if align != BOSMINER_E02C_TYPE_ALIGN as u64 {
            return Err("vtable align word is not 16");
        }
        let file_off = BOSMINER_E02C_VTABLE_FILE_OFF[i];
        if e02c_second_load_off(BOSMINER_E02C_VTABLE_VA[i]) != Some(file_off as usize) {
            return Err("second-LOAD VA/file delta is not 0x410000");
        }
    }
    Ok(())
}

/// The 0x2a0 vtable does not name engine+0x88 `.text`.
pub fn refuse_e02c_vtable_as_named_plus88() -> Result<(), &'static str> {
    Err(
        "FUN_0087e02c is fixture.rs:258 / hardware.rs:352 method 0 on a 0x2a0 object; +0x88 is a field, not a named identity .text",
    )
}

/// Method 0 follows `X22+0x290` then loads that object's `+0x88`.
pub fn admit_bosminer_ctx_290_then_88(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_CTX_X22_PLUS88_HITS != 0 {
        return Err("X22+#0x88 load/store appeared in FUN_0087e02c");
    }
    if BOSMINER_CTX_290_THEN_88_VA <= BOSMINER_CTX_290_LDR_VA {
        return Err("+0x88 follow must be after LDR [X22,#0x290]");
    }
    let inner = engine88_le_u32(blob, BOSMINER_CTX_290_LDR_VA)
        .ok_or("bosminer shorter than LDR [X22,#0x290]")?;
    if inner != BOSMINER_CTX_290_LDR_INSN {
        return Err("0x87e11c is not LDR X9,[X22,#0x290]");
    }
    let field = engine88_le_u32(blob, BOSMINER_CTX_290_THEN_88_VA)
        .ok_or("bosminer shorter than LDR [X9,#0x88]")?;
    if field != BOSMINER_CTX_290_THEN_88_INSN {
        return Err("0x87e128 is not LDR X9,[X9,#0x88]");
    }
    let sp = engine88_le_u32(blob, BOSMINER_SP88_LDR_VA)
        .ok_or("bosminer shorter than LDR [SP,#0x88]")?;
    if sp != BOSMINER_SP88_LDR_INSN {
        return Err("0x87e070 is not LDR X1,[SP,#0x88]");
    }
    Ok(())
}

/// `X22+0x88` is not a method-0 load; `SP+0x88` is a stack slot.
pub fn refuse_ctx_self_plus88_as_method0_load() -> Result<(), &'static str> {
    Err(
        "FUN_0087e02c has 0 LDR/STR [X22,#0x88]; +0x88 is loaded from *(X22+0x290); SP+#0x88 is a stack arg",
    )
}

/// `*(X22+0x290)` is `FUN_008787a8` HashMap-get self (key at lookup+0x19c).
pub fn admit_bosminer_ctx_290_is_hashmap_get_self(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_PROD_GET_BL_VA != BOSMINER_PROD_MAP_LDR_VA + 8 {
        return Err("BL get is not LDR [X22,#0x290] + 8");
    }
    if BOSMINER_HASHMAP_INNER_OFF != 0xC0 {
        return Err("get inner is +0xC0");
    }
    if BOSMINER_HASHMAP_GET_KEY_OFF != 0x19C {
        return Err("get key stays +0x19c");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_PROD_MAP_LDR_VA)
        .ok_or("bosminer shorter than LDR X0,[X22,#0x290]")?;
    if ldr != BOSMINER_PROD_MAP_LDR_INSN {
        return Err("0x87e080 is not LDR X0,[X22,#0x290]");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_PROD_MAP_LDR_VA + 4)
        .ok_or("bosminer shorter than MOV X1,X22")?;
    if x1 != BOSMINER_PROD_WRAP_SRC_MOV_INSN {
        return Err("0x87e084 is not MOV X1,X22");
    }
    let bl = engine88_le_u32(blob, BOSMINER_PROD_GET_BL_VA)
        .ok_or("bosminer shorter than BL FUN_008787a8")?;
    if bl != BOSMINER_PROD_GET_BL_INSN {
        return Err("0x87e088 is not BL FUN_008787a8");
    }
    let add_c0 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_ADD_C0_VA)
        .ok_or("bosminer shorter than ADD X0,#0xC0")?;
    if add_c0 != BOSMINER_HASHMAP_GET_ADD_C0_INSN {
        return Err("0x8787b8 is not ADD X0,X0,#0xC0");
    }
    let a8 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_A8_LDR_VA)
        .ok_or("bosminer shorter than LDR [X20,#0xA8]")?;
    if a8 != BOSMINER_HASHMAP_GET_A8_LDR_INSN {
        return Err("0x8787c8 is not LDR X8,[X20,#0xA8]");
    }
    let key = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_KEY_ADD_VA)
        .ok_or("bosminer shorter than ADD X19,X1,#0x19c")?;
    if key != BOSMINER_HASHMAP_GET_KEY_ADD_INSN {
        return Err("0x8787cc is not ADD X19,X1,#0x19c");
    }
    Ok(())
}

/// Context `+0x290` is not the HashChain engine slot at the same numeric offset.
pub fn refuse_ctx_290_as_hashchain_engine() -> Result<(), &'static str> {
    if BOSMINER_HC290_STR_INSN != 0xF901_4AFA {
        return Ok(());
    }
    if BOSMINER_HC290_STR298_INSN != 0xF901_4EF9 {
        return Ok(());
    }
    Err(
        "context+0x290 is HashMap-get self; HashChain engine is STR X26,[X23,#0x290] then STR #0x298 @ 0x878c98",
    )
}

/// Get uses `+0xC0`/`+0xA8`, so map-object `+0x88` is not the engine nonce fn.
pub fn refuse_hashmap_plus88_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_GET_ADD_C0_INSN != 0x9103_0000 {
        return Ok(());
    }
    Err(
        "FUN_008787a8 walks self+0xC0 / +0xA8; method-0 LDR [map,#0x88] is not the BM1366 attribution callback",
    )
}

/// Ten non-SP `STR #0x88` in AM3 `0x860000..0x890000`.
pub fn admit_bosminer_am3_str88_census(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_AM3_STR88_HITS != 10 {
        return Err("AM3 STR#0x88 census drifted");
    }
    if BOSMINER_AM3_STR88_DEST_A8_HITS != 0 {
        return Err("AM3 STR#0x88 dest grew a STR #0xA8");
    }
    if BOSMINER_AM3_STR88_VA[4] != BOSMINER_SLICE10_STR88_VA {
        return Err("AM3[4] must stay the Wave-61 SLICE10 site");
    }
    if BOSMINER_AM3_STR88_VA[6] != BOSMINER_FUTURE_STR88_VA {
        return Err("AM3[6] must stay the Wave-62 FUTURE site");
    }
    for i in 0..BOSMINER_AM3_STR88_HITS {
        let got = engine88_le_u32(blob, BOSMINER_AM3_STR88_VA[i])
            .ok_or("bosminer shorter than AM3 STR#0x88")?;
        if got != BOSMINER_AM3_STR88_INSN[i] {
            return Err("AM3 STR#0x88 encoding drifted");
        }
    }
    Ok(())
}

/// Three Result stores: `STR X0` after `BL` packed-tag `LDRB #0x70` helper.
pub fn admit_bosminer_am3_str88_result_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_AM3_STR88_RESULT_HITS != 3 {
        return Err("AM3 Result STR#0x88 census drifted");
    }
    if BOSMINER_AM3_TAG70_HELPER_LDRB_INSN != BOSMINER_ENGINE88_PRODUCER_LDRB_INSN {
        return Err("tag70 helper LDRB must match FUN_008d9984 encoding");
    }
    for &va in &BOSMINER_AM3_STR88_RESULT_VA {
        let st = engine88_le_u32(blob, va).ok_or("bosminer shorter than Result STR X0")?;
        if st != BOSMINER_AM3_STR88_RESULT_INSN {
            return Err("Result site is not STR X0,[X19,#0x88]");
        }
    }
    for &h in &BOSMINER_AM3_TAG70_HELPER_VA {
        let ldrb = engine88_le_u32(blob, h + BOSMINER_AM3_TAG70_HELPER_LDRB_OFF)
            .ok_or("bosminer shorter than tag70 LDRB")?;
        if ldrb != BOSMINER_AM3_TAG70_HELPER_LDRB_INSN {
            return Err("helper is not LDRB [X0,#0x70]");
        }
    }
    Ok(())
}

/// Two sites store `X10+0x18` at dest+0x88 after `MOVZ W8,#4`.
pub fn admit_bosminer_am3_str88_add18_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_AM3_STR88_ADD18_HITS != 2 {
        return Err("AM3 ADD#0x18 STR#0x88 census drifted");
    }
    for &va in &BOSMINER_AM3_STR88_ADD18_VA {
        let add = engine88_le_u32(blob, va - BOSMINER_AM3_STR88_ADD18_BEFORE)
            .ok_or("bosminer shorter than ADD X8,X10,#0x18")?;
        if add != BOSMINER_AM3_STR88_ADD18_INSN {
            return Err("ADD#0x18 site drifted");
        }
        let movz = engine88_le_u32(blob, va - BOSMINER_AM3_STR88_MOVZ4_BEFORE)
            .ok_or("bosminer shorter than MOVZ W8,#4")?;
        if movz != BOSMINER_AM3_STR88_MOVZ4_INSN {
            return Err("MOVZ #4 before ADD#0x18 drifted");
        }
        let st = engine88_le_u32(blob, va).ok_or("bosminer shorter than ADD18 STR")?;
        if st != 0xF900_4668 {
            return Err("ADD#0x18 dest is not STR X8,[X19,#0x88]");
        }
    }
    let sl = engine88_le_u32(
        blob,
        BOSMINER_AM3_STR88_SLICE10_CLONE_VA - BOSMINER_AM3_STR88_SLICE10_ADD_BEFORE,
    )
    .ok_or("bosminer shorter than SLICE10 clone ADD")?;
    if sl != BOSMINER_SLICE10_ADD_INSN {
        return Err("0x88e0ac is not ADD X8,#0x10");
    }
    let z = engine88_le_u32(blob, BOSMINER_AM3_STR88_ZERO_VA)
        .ok_or("bosminer shorter than STR XZR #0x88")?;
    if z != BOSMINER_AM3_STR88_ZERO_INSN {
        return Err("0x86dde8 is not STR XZR,[X19,#0x88]");
    }
    Ok(())
}

/// AM3 `STR #0x88` dests are not HashMap-get self (`+0xA8` ctrl).
pub fn refuse_am3_str88_as_hashmap_plus88() -> Result<(), &'static str> {
    if BOSMINER_AM3_STR88_DEST_A8_HITS != 0 {
        return Ok(());
    }
    Err(
        "10 AM3 STR#0x88 dests have 0 STR [X19,#0xA8]; HashMap get walks +0xC0/+0xA8, not these stores",
    )
}

/// None of the AM3 `STR #0x88` sites is engine nonce `.text`.
pub fn refuse_am3_str88_as_engine_nonce_text() -> Result<(), &'static str> {
    Err(
        "AM3 STR#0x88 = Result X0 / X10+0x18 / slice+16 / XZR / future waker / field X9; not ADRP identity .text",
    )
}

/// First-LOAD census: dest has both HashMap-get `+0xA8` and `+0xC0`.
pub fn admit_bosminer_hashmap_str88_census(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_STR88_HITS != 11 {
        return Err("HashMap-shaped STR#0x88 census drifted");
    }
    if BOSMINER_HASHMAP_STR88_WINDOW != 0x300 {
        return Err("±0x300 window drifted");
    }
    for &va in &BOSMINER_AM3_STR88_RESULT_VA {
        if BOSMINER_HASHMAP_STR88_VA.contains(&va) {
            return Err("Wave-157 Result STR#0x88 is not a HashMap dest");
        }
    }
    for i in 0..BOSMINER_HASHMAP_STR88_HITS {
        let got = engine88_le_u32(blob, BOSMINER_HASHMAP_STR88_VA[i])
            .ok_or("bosminer shorter than HashMap STR#0x88")?;
        if got != BOSMINER_HASHMAP_STR88_INSN[i] {
            return Err("HashMap STR#0x88 encoding drifted");
        }
    }
    Ok(())
}

/// Three inits `ADD X0,X19,#0xA8` / `#0xC0` then `STR X20,[X19,#0x88]` (0x8B8 stride).
pub fn admit_bosminer_hashmap_str88_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_STR88_FAMILY_HITS != 3 {
        return Err("HashMap STR#0x88 family census drifted");
    }
    if BOSMINER_HASHMAP_STR88_FAMILY_VA[1] - BOSMINER_HASHMAP_STR88_FAMILY_VA[0]
        != BOSMINER_HASHMAP_STR88_FAMILY_STRIDE
    {
        return Err("family stride is not 0x8B8");
    }
    if BOSMINER_HASHMAP_STR88_FAMILY_VA[2] - BOSMINER_HASHMAP_STR88_FAMILY_VA[1]
        != BOSMINER_HASHMAP_STR88_FAMILY_STRIDE
    {
        return Err("family second stride is not 0x8B8");
    }
    for &va in &BOSMINER_HASHMAP_STR88_FAMILY_VA {
        let st = engine88_le_u32(blob, va).ok_or("bosminer shorter than family STR X20")?;
        if st != BOSMINER_HASHMAP_STR88_FAMILY_INSN {
            return Err("family site is not STR X20,[X19,#0x88]");
        }
        let a8 = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_ADD_A8_BEFORE)
            .ok_or("bosminer shorter than ADD #0xA8")?;
        if a8 != BOSMINER_HASHMAP_STR88_ADD_A8_INSN {
            return Err("family ADD X0,X19,#0xA8 drifted");
        }
        let c0 = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_ADD_C0_BEFORE)
            .ok_or("bosminer shorter than ADD #0xC0")?;
        if c0 != BOSMINER_HASHMAP_STR88_ADD_C0_INSN {
            return Err("family ADD X0,X19,#0xC0 drifted");
        }
    }
    Ok(())
}

/// HashMap-shaped dest `+0x88` is not engine nonce `.text`.
pub fn refuse_hashmap_str88_as_engine_nonce_text() -> Result<(), &'static str> {
    Err(
        "11 STR#0x88 dests with +0xA8 and +0xC0 store X0/X8/X9/X20/X21/X24; 3-site family stores X20 after HashMap ADD #0xA8/#0xC0; not ADRP identity .text",
    )
}

/// Family `X20` is Result-Ok `[SP,#0x118]` after `BL FUN_00861090`.
pub fn admit_bosminer_hashmap_x20_is_result_ok(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_STR88_OK_SP != BOSMINER_HASHMAP_STR88_SRET_SP + 8 {
        return Err("Ok payload must be sret+8");
    }
    if BOSMINER_HASHMAP_STR88_SELF_B8_OFF != 0xB8 {
        return Err("helper X0 is *(self+0xB8)");
    }
    for i in 0..BOSMINER_HASHMAP_STR88_FAMILY_HITS {
        let va = BOSMINER_HASHMAP_STR88_FAMILY_VA[i];
        let bl = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_BL_BEFORE)
            .ok_or("bosminer shorter than family Result BL")?;
        if bl != BOSMINER_HASHMAP_STR88_BL_INSN[i] {
            return Err("family BL FUN_00861090 drifted");
        }
        let ldrw = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_LDRB8_BEFORE)
            .ok_or("bosminer shorter than LDR W8,[SP,#0x110]")?;
        if ldrw != BOSMINER_HASHMAP_STR88_LDRW_SP110_INSN {
            return Err("family is not LDR W8,[SP,#0x110]");
        }
        let tbz = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_TBZ_BEFORE)
            .ok_or("bosminer shorter than TBZ W8,#0")?;
        if tbz != BOSMINER_HASHMAP_STR88_TBZ_INSN {
            return Err("family is not TBZ W8,#0 to LDP");
        }
        let ldp = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_LDP_BEFORE)
            .ok_or("bosminer shorter than LDP X20,X23,[SP,#0x118]")?;
        if ldp != BOSMINER_HASHMAP_STR88_LDP_INSN {
            return Err("family is not LDP X20,X23,[SP,#0x118]");
        }
        let sret = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_SRET_ADD_BEFORE)
            .ok_or("bosminer shorter than ADD X8,SP,#0x110")?;
        if sret != BOSMINER_HASHMAP_STR88_SRET_ADD_INSN {
            return Err("sret dest is not SP+#0x110");
        }
        let b8 = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_SELF_B8_BEFORE)
            .ok_or("bosminer shorter than LDR [X19,#0xB8]")?;
        if b8 != BOSMINER_HASHMAP_STR88_SELF_B8_INSN {
            return Err("helper X0 is not LDR [X19,#0xB8]");
        }
        let a88 = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_ADD88_BEFORE)
            .ok_or("bosminer shorter than ADD X20,#0x88")?;
        if a88 != BOSMINER_HASHMAP_STR88_ADD88_INSN {
            return Err("dead ADD X20,X19,#0x88 drifted");
        }
        let a90 = engine88_le_u32(blob, va - BOSMINER_HASHMAP_STR88_ADD90_BEFORE)
            .ok_or("bosminer shorter than ADD X20,#0x90")?;
        if a90 != BOSMINER_HASHMAP_STR88_ADD90_INSN {
            return Err("dead ADD X20,X19,#0x90 drifted");
        }
    }
    Ok(())
}

/// `ADD X20,X19,#0x88` does not reach the family `STR`.
pub fn refuse_hashmap_x20_as_dest_plus88_addr() -> Result<(), &'static str> {
    Err("ADD X20,X19,#0x88 is overwritten; STR path is TBZ->LDP [SP,#0x118] after BL FUN_00861090")
}

/// `ADD X20,X19,#0x90` is on the TBZ-not-taken skip path.
pub fn refuse_hashmap_x20_as_dest_plus90_addr() -> Result<(), &'static str> {
    Err("ADD X20,X19,#0x90 does not reach STR; Ok path reloads X20 from SP+#0x118")
}

/// `FUN_00861090` Ok low qword is a clone of `*(self+0xB8)`.
pub fn admit_bosminer_hashmap_helper_ok_is_b8_clone(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_CLONE_ALLOC_SIZE != 0x18 {
        return Err("clone alloc size is 0x18");
    }
    if BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN != 8 {
        return Err("clone alloc align is 8");
    }
    let inner = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_LDR_INNER_VA)
        .ok_or("bosminer shorter than LDR X22,[X0]")?;
    if inner != BOSMINER_HASHMAP_HELPER_LDR_INNER_INSN {
        return Err("0x86109c is not LDR X22,[X0]");
    }
    let save = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_SAVE_X0_VA)
        .ok_or("bosminer shorter than MOV X20,X0")?;
    if save != BOSMINER_HASHMAP_HELPER_SAVE_X0_INSN {
        return Err("0x8610a0 is not MOV X20,X0");
    }
    let sret = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_SRET_MOV_VA)
        .ok_or("bosminer shorter than MOV X19,X8")?;
    if sret != BOSMINER_HASHMAP_HELPER_SRET_MOV_INSN {
        return Err("0x8610a4 is not MOV X19,X8");
    }
    let add10 = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_ADD10_VA)
        .ok_or("bosminer shorter than ADD X0,X22,#0x10")?;
    if add10 != BOSMINER_HASHMAP_HELPER_ADD10_INSN {
        return Err("0x8610b0 is not ADD X0,X22,#0x10");
    }
    let bl = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_CLONE_BL_VA)
        .ok_or("bosminer shorter than BL FUN_008b60ac")?;
    if bl != BOSMINER_HASHMAP_HELPER_CLONE_BL_INSN {
        return Err("0x8610b4 is not BL FUN_008b60ac");
    }
    let ok = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_OK_STR_VA)
        .ok_or("bosminer shorter than STR X0,[X19,#8]")?;
    if ok != BOSMINER_HASHMAP_HELPER_OK_STR_INSN {
        return Err("0x861148 is not STR X0,[X19,#8]");
    }
    let hi = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_OK_HI_VA)
        .ok_or("bosminer shorter than STR X1,[X19,#0x10]")?;
    if hi != BOSMINER_HASHMAP_HELPER_OK_HI_INSN {
        return Err("0x86114c is not STR X1,[X19,#0x10]");
    }
    let tag = engine88_le_u32(blob, BOSMINER_HASHMAP_HELPER_TAG_VA)
        .ok_or("bosminer shorter than STR XZR,[X19]")?;
    if tag != BOSMINER_HASHMAP_HELPER_TAG_INSN {
        return Err("0x861150 is not STR XZR,[X19]");
    }
    let sz = engine88_le_u32(blob, BOSMINER_HASHMAP_CLONE_ALLOC_SZ_VA)
        .ok_or("bosminer shorter than MOVZ W1,#0x18")?;
    if sz != BOSMINER_HASHMAP_CLONE_ALLOC_SZ_INSN {
        return Err("0x8b6120 is not MOVZ W1,#0x18");
    }
    let al = engine88_le_u32(blob, BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN_VA)
        .ok_or("bosminer shorter than MOVZ W2,#8")?;
    if al != BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN_INSN {
        return Err("0x8b6124 is not MOVZ W2,#8");
    }
    Ok(())
}

/// The 8 non-family HashMap dests stay classified and exclude the X20 family.
pub fn admit_bosminer_hashmap_str88_rest_census(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_STR88_REST_HITS + BOSMINER_HASHMAP_STR88_FAMILY_HITS
        != BOSMINER_HASHMAP_STR88_HITS
    {
        return Err("8 rest + 3 family must be the 11 HashMap dests");
    }
    for &va in &BOSMINER_HASHMAP_STR88_FAMILY_VA {
        if BOSMINER_HASHMAP_STR88_REST_VA.contains(&va) {
            return Err("family site leaked into rest census");
        }
    }
    for &va in &BOSMINER_HASHMAP_STR88_REST_VA {
        if !BOSMINER_HASHMAP_STR88_VA.contains(&va) {
            return Err("rest site is not in the 11 HashMap dests");
        }
        let got = engine88_le_u32(blob, va).ok_or("bosminer shorter than rest STR#0x88")?;
        if got == BOSMINER_HASHMAP_STR88_FAMILY_INSN {
            return Err("rest site is the family STR X20 encoding");
        }
    }
    let add = engine88_le_u32(
        blob,
        BOSMINER_HASHMAP_STR88_SLICE10_REST_VA - BOSMINER_HASHMAP_STR88_SLICE10_REST_ADD_BEFORE,
    )
    .ok_or("bosminer shorter than rest SLICE10 ADD")?;
    if add != BOSMINER_SLICE10_ADD_INSN {
        return Err("0x655088 is not ADD X8,#0x10");
    }
    Ok(())
}

/// Helper Ok qword is a `*(self+0xB8)` clone, not engine nonce `.text`.
pub fn refuse_hashmap_helper_ok_as_engine_nonce() -> Result<(), &'static str> {
    Err(
        "FUN_00861090 stores Ok(X0) at sret+8 after Arc-like clone of *(self+0xB8)+0x10 (alloc 0x18/8); not ADRP identity .text",
    )
}

/// `FUN_008b60ac` extracts `[node+0x10]` then dealloc-shaped `BL` thunk0 `(ptr,0x18,8)`.
pub fn admit_bosminer_hashmap_18_is_dealloc_node(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_CLONE_ALLOC_SIZE != 0x18 {
        return Err("node size is 0x18");
    }
    let node = engine88_le_u32(blob, BOSMINER_HASHMAP_18_NODE_LDR_VA)
        .ok_or("bosminer shorter than LDR X19,[X0,#8]")?;
    if node != BOSMINER_HASHMAP_18_NODE_LDR_INSN {
        return Err("0x8b60b8 is not LDR X19,[X0,#8]");
    }
    let add = engine88_le_u32(blob, BOSMINER_HASHMAP_18_NODE_ADD10_VA)
        .ok_or("bosminer shorter than ADD X8,X19,#0x10")?;
    if add != BOSMINER_HASHMAP_18_NODE_ADD10_INSN {
        return Err("0x8b60c0 is not ADD X8,X19,#0x10");
    }
    let lo = engine88_le_u32(blob, BOSMINER_HASHMAP_18_PAIR_LO_VA)
        .ok_or("bosminer shorter than LDR X21,[X8]")?;
    if lo != BOSMINER_HASHMAP_18_PAIR_LO_INSN {
        return Err("0x8b6100 is not LDR X21,[X8]");
    }
    let hi = engine88_le_u32(blob, BOSMINER_HASHMAP_18_PAIR_HI_VA)
        .ok_or("bosminer shorter than LDR X20,[X8,#8]")?;
    if hi != BOSMINER_HASHMAP_18_PAIR_HI_INSN {
        return Err("0x8b60f8 is not LDR X20,[X8,#8]");
    }
    let x0 = engine88_le_u32(blob, BOSMINER_HASHMAP_18_DEALLOC_X0_VA)
        .ok_or("bosminer shorter than MOV X0,X19")?;
    if x0 != BOSMINER_HASHMAP_18_DEALLOC_X0_INSN {
        return Err("dealloc X0 is not the node X19");
    }
    let bl = engine88_le_u32(blob, BOSMINER_HASHMAP_18_DEALLOC_BL_VA)
        .ok_or("bosminer shorter than BL heap thunk0")?;
    if bl != BOSMINER_HASHMAP_18_DEALLOC_BL_INSN {
        return Err("0x8b6128 is not BL 0x5f4a7c");
    }
    let ret0 = engine88_le_u32(blob, BOSMINER_HASHMAP_18_RET_X0_VA)
        .ok_or("bosminer shorter than MOV X0,X21")?;
    if ret0 != BOSMINER_HASHMAP_18_RET_X0_INSN {
        return Err("return X0 is not extracted X21");
    }
    let ret1 = engine88_le_u32(blob, BOSMINER_HASHMAP_18_RET_X1_VA)
        .ok_or("bosminer shorter than MOV X1,X20")?;
    if ret1 != BOSMINER_HASHMAP_18_RET_X1_INSN {
        return Err("return X1 is not extracted X20");
    }
    let thunk = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK0_VA)
        .ok_or("bosminer shorter than heap thunk0")?;
    if thunk != BOSMINER_RUSTC_HEAP_THUNK0_INSN {
        return Err("0x5f4a7c is not the first rustc heap B thunk");
    }
    if BOSMINER_RUSTC_HEAP_THUNK1_VA != BOSMINER_RUSTC_HEAP_THUNK0_VA + 4
        || BOSMINER_RUSTC_HEAP_THUNK2_VA != BOSMINER_RUSTC_HEAP_THUNK0_VA + 8
    {
        return Err("heap thunk trio is not 4-byte stride");
    }
    Ok(())
}

/// `(X0=node, X1=0x18, X2=8)` is dealloc, not `alloc(size,align)`.
pub fn refuse_hashmap_18_as_alloc() -> Result<(), &'static str> {
    Err(
        "FUN_008b60ac MOV X0,X19; MOVZ W1,#0x18; MOVZ W2,#8; BL thunk0 — (ptr,size,align) dealloc, not alloc(size,align)",
    )
}

/// `0x5de708` stores helper `X0` after `LDR [X19,#0xA0]`.
pub fn admit_bosminer_hashmap_5de708_is_result_x0(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_5DE708_VA != BOSMINER_HASHMAP_STR88_REST_VA[0] {
        return Err("0x5de708 must stay rest[0]");
    }
    let bl = engine88_le_u32(blob, BOSMINER_HASHMAP_5DE708_BL_VA)
        .ok_or("bosminer shorter than 0x5de6fc BL")?;
    if bl != BOSMINER_HASHMAP_5DE708_BL_INSN {
        return Err("0x5de6fc is not BL 0x586cd8");
    }
    let a0 = engine88_le_u32(blob, BOSMINER_HASHMAP_5DE708_LDR_A0_VA)
        .ok_or("bosminer shorter than LDR #0xA0")?;
    if a0 != BOSMINER_HASHMAP_5DE708_LDR_A0_INSN {
        return Err("0x5de704 is not LDR X8,[X19,#0xA0]");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHMAP_5DE708_VA)
        .ok_or("bosminer shorter than STR X0 #0x88")?;
    if st != BOSMINER_HASHMAP_5DE708_STR_INSN {
        return Err("0x5de708 is not STR X0,[X19,#0x88]");
    }
    Ok(())
}

/// `0x115c698` rewrites `X21+0x88` after loading `X21+0x88` / `+0xA8`.
pub fn admit_bosminer_hashmap_115c698_is_field_rewrite(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_115C698_VA != BOSMINER_HASHMAP_STR88_REST_VA[6] {
        return Err("0x115c698 must stay rest[6]");
    }
    let ldr88 = engine88_le_u32(blob, BOSMINER_HASHMAP_115C680_LDR88_VA)
        .ok_or("bosminer shorter than LDR [X21,#0x88]")?;
    if ldr88 != BOSMINER_HASHMAP_115C680_LDR88_INSN {
        return Err("0x115c680 is not LDR X20,[X21,#0x88]");
    }
    let ldra8 = engine88_le_u32(blob, BOSMINER_HASHMAP_115C694_LDR_A8_VA)
        .ok_or("bosminer shorter than LDR [X21,#0xA8]")?;
    if ldra8 != BOSMINER_HASHMAP_115C694_LDR_A8_INSN {
        return Err("0x115c694 is not LDR X20,[X21,#0xA8]");
    }
    let st88 = engine88_le_u32(blob, BOSMINER_HASHMAP_115C698_VA)
        .ok_or("bosminer shorter than STR [X21,#0x88]")?;
    if st88 != BOSMINER_HASHMAP_115C698_STR_INSN {
        return Err("0x115c698 is not STR X8,[X21,#0x88]");
    }
    let sta8 = engine88_le_u32(blob, BOSMINER_HASHMAP_115C6B0_STR_A8_VA)
        .ok_or("bosminer shorter than STR [X21,#0xA8]")?;
    if sta8 != BOSMINER_HASHMAP_115C6B0_STR_A8_INSN {
        return Err("0x115c6b0 is not STR X8,[X21,#0xA8]");
    }
    Ok(())
}

/// thunk0 body is a 4-insn dummy-frame tail to the CBZ-X0 dealloc dispatcher.
pub fn admit_bosminer_heap_thunk0_is_tail_trampoline(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_RUSTC_HEAP_THUNK0_B_TGT != BOSMINER_RUSTC_HEAP_DISP_VA {
        return Err("thunk0 B target must be 0xbc9f10");
    }
    if BOSMINER_RUSTC_HEAP_DISP_B_TGT != BOSMINER_RUSTC_HEAP_DEALLOC_ARM_VA {
        return Err("dispatcher first arm must be 0xbca3cc");
    }
    if BOSMINER_RUSTC_HEAP_THUNK1_BODY_VA != BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA + 0x10 {
        return Err("thunk1 body is not immediately after the 4-insn trampoline");
    }
    let stp = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA)
        .ok_or("bosminer shorter than thunk0 STP")?;
    if stp != BOSMINER_RUSTC_HEAP_THUNK0_STP_INSN {
        return Err("0x129b128 is not STP X29,X30,[SP,#-0x10]!");
    }
    let mov = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA + 4)
        .ok_or("bosminer shorter than thunk0 MOV")?;
    if mov != BOSMINER_RUSTC_HEAP_THUNK0_MOV_INSN {
        return Err("0x129b12c is not MOV X29,SP");
    }
    let ldp = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK0_LDP_VA)
        .ok_or("bosminer shorter than thunk0 LDP")?;
    if ldp != BOSMINER_RUSTC_HEAP_THUNK0_LDP_INSN {
        return Err("0x129b130 is not LDP X29,X30,[SP],#0x10");
    }
    let b = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK0_B_VA)
        .ok_or("bosminer shorter than thunk0 B")?;
    if b != BOSMINER_RUSTC_HEAP_THUNK0_B_INSN {
        return Err("0x129b134 is not B 0xbc9f10");
    }
    let disp = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_DISP_VA)
        .ok_or("bosminer shorter than heap dispatcher")?;
    if disp != BOSMINER_RUSTC_HEAP_DISP_B_INSN {
        return Err("0xbc9f10 is not B 0xbca3cc");
    }
    let cbz = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_DEALLOC_ARM_VA)
        .ok_or("bosminer shorter than dealloc CBZ")?;
    if cbz != BOSMINER_RUSTC_HEAP_DEALLOC_CBZ_INSN {
        return Err("0xbca3cc is not CBZ X0");
    }
    let sub = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK1_BODY_VA)
        .ok_or("bosminer shorter than thunk1 SUB")?;
    if sub != BOSMINER_RUSTC_HEAP_THUNK1_SUB_INSN {
        return Err("0x129b138 is not SUB SP,#0x40");
    }
    Ok(())
}

/// thunk0 is not the realloc-shaped body (that is thunk1).
pub fn refuse_heap_thunk0_as_realloc() -> Result<(), &'static str> {
    Err(
        "thunk0 body is 4-insn dummy-frame B 0xbc9f10 (CBZ-X0 dealloc arm); thunk1 at 0x129b138 is the real SUB-SP realloc-shaped fn",
    )
}

/// rest[1]/[2]/[4]/[5]/[7] stay bound to their classified VAs; rest[3] stays SLICE10.
pub fn admit_bosminer_hashmap_str88_rest_named() -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_STR88_REST_VA[1] != BOSMINER_HASHMAP_626AAC_VA {
        return Err("rest[1] must stay 0x626aac");
    }
    if BOSMINER_HASHMAP_STR88_REST_VA[2] != BOSMINER_HASHMAP_654C10_VA {
        return Err("rest[2] must stay 0x654c10");
    }
    if BOSMINER_HASHMAP_STR88_REST_VA[3] != BOSMINER_HASHMAP_STR88_SLICE10_REST_VA {
        return Err("rest[3] must stay SLICE10 0x655098");
    }
    if BOSMINER_HASHMAP_STR88_REST_VA[4] != BOSMINER_HASHMAP_9F3F00_VA {
        return Err("rest[4] must stay 0x9f3f00");
    }
    if BOSMINER_HASHMAP_STR88_REST_VA[5] != BOSMINER_HASHMAP_B824C8_VA {
        return Err("rest[5] must stay 0xb824c8");
    }
    if BOSMINER_HASHMAP_STR88_REST_VA[7] != BOSMINER_HASHMAP_115C788_VA {
        return Err("rest[7] must stay 0x115c788");
    }
    if BOSMINER_PANIC_DTOR_MSG.len() != usize::from(BOSMINER_PANIC_DTOR_MSG_LEN) {
        return Err("destructor panic string is 0x24 bytes");
    }
    Ok(())
}

/// `0x626aac` stores `X0` loaded from `[X23]`, not a `0x4538b0` panic return.
pub fn admit_bosminer_hashmap_626aac_is_x0_from_x23(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_626AAC_VA != BOSMINER_HASHMAP_STR88_REST_VA[1] {
        return Err("0x626aac must stay rest[1]");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_HASHMAP_62672C_LDR_VA)
        .ok_or("bosminer shorter than LDR X0,[X23]")?;
    if ldr != BOSMINER_HASHMAP_62672C_LDR_INSN {
        return Err("0x62672c is not LDR X0,[X23]");
    }
    let b = engine88_le_u32(blob, BOSMINER_HASHMAP_626730_B_VA)
        .ok_or("bosminer shorter than B 0x626aac")?;
    if b != BOSMINER_HASHMAP_626730_B_INSN {
        return Err("0x626730 is not B 0x626aac");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHMAP_626AAC_VA)
        .ok_or("bosminer shorter than STR X0 #0x88")?;
    if st != BOSMINER_HASHMAP_626AAC_STR_INSN {
        return Err("0x626aac is not STR X0,[X19,#0x88]");
    }
    let bl = engine88_le_u32(blob, BOSMINER_HASHMAP_626AA8_PANIC_BL_VA)
        .ok_or("bosminer shorter than panic BL")?;
    if bl != BOSMINER_HASHMAP_626AA8_PANIC_BL_INSN {
        return Err("0x626aa8 is not BL 0x4538b0");
    }
    let movz = engine88_le_u32(blob, BOSMINER_PANIC_DTOR_MOVZ_VA)
        .ok_or("bosminer shorter than panic MOVZ")?;
    if movz != BOSMINER_PANIC_DTOR_MOVZ_INSN {
        return Err("0x4538c0 is not MOVZ W1,#0x24");
    }
    Ok(())
}

/// Linear predecessor `BL 0x4538b0` is a no-return destructor panic.
pub fn refuse_hashmap_626aac_as_panic_4538b0_return() -> Result<(), &'static str> {
    Err(
        "0x626aa8 BL 0x4538b0 is panic-in-destructor (string len 0x24); STR X0 is reached by B 0x626730 after LDR X0,[X23]",
    )
}

/// `0x654c10` copies `X19+0x90` into `X19+0x88`.
pub fn admit_bosminer_hashmap_654c10_is_x24_from_plus90(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_654C10_VA != BOSMINER_HASHMAP_STR88_REST_VA[2] {
        return Err("0x654c10 must stay rest[2]");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_HASHMAP_654690_LDR90_VA)
        .ok_or("bosminer shorter than LDR X24,#0x90")?;
    if ldr != BOSMINER_HASHMAP_654690_LDR90_INSN {
        return Err("0x654690 is not LDR X24,[X19,#0x90]");
    }
    let b = engine88_le_u32(blob, BOSMINER_HASHMAP_654698_B_VA)
        .ok_or("bosminer shorter than B 0x654c10")?;
    if b != BOSMINER_HASHMAP_654698_B_INSN {
        return Err("0x654698 is not B 0x654c10");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHMAP_654C10_VA)
        .ok_or("bosminer shorter than STR X24 #0x88")?;
    if st != BOSMINER_HASHMAP_654C10_STR_INSN {
        return Err("0x654c10 is not STR X24,[X19,#0x88]");
    }
    Ok(())
}

/// `0x9f3f00` stores stack `X8` (`LDR [SP,#0x58]`).
pub fn admit_bosminer_hashmap_9f3f00_is_stack_x8(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_9F3F00_VA != BOSMINER_HASHMAP_STR88_REST_VA[4] {
        return Err("0x9f3f00 must stay rest[4]");
    }
    if BOSMINER_HASHMAP_9F3ED8_SP_OFF != 0x58 {
        return Err("stack slot is [SP,#0x58]");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_HASHMAP_9F3ED8_LDR_VA)
        .ok_or("bosminer shorter than LDR X8,[SP,#0x58]")?;
    if ldr != BOSMINER_HASHMAP_9F3ED8_LDR_INSN {
        return Err("0x9f3ed8 is not LDR X8,[SP,#0x58]");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHMAP_9F3F00_VA)
        .ok_or("bosminer shorter than STR X8 #0x88")?;
    if st != BOSMINER_HASHMAP_9F3F00_STR_INSN {
        return Err("0x9f3f00 is not STR X8,[X19,#0x88]");
    }
    Ok(())
}

/// `0xb824c8` stores `X8+8`, not a `0x4538b0` panic return.
pub fn admit_bosminer_hashmap_b824c8_is_x8_plus8(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_B824C8_VA != BOSMINER_HASHMAP_STR88_REST_VA[5] {
        return Err("0xb824c8 must stay rest[5]");
    }
    let add = engine88_le_u32(blob, BOSMINER_HASHMAP_B824C0_ADD8_VA)
        .ok_or("bosminer shorter than ADD X9,X8,#8")?;
    if add != BOSMINER_HASHMAP_B824C0_ADD8_INSN {
        return Err("0xb824c0 is not ADD X9,X8,#8");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHMAP_B824C8_VA)
        .ok_or("bosminer shorter than STR X9 #0x88")?;
    if st != BOSMINER_HASHMAP_B824C8_STR_INSN {
        return Err("0xb824c8 is not STR X9,[X19,#0x88]");
    }
    let bl = engine88_le_u32(blob, BOSMINER_HASHMAP_B824BC_PANIC_BL_VA)
        .ok_or("bosminer shorter than b824 panic BL")?;
    if bl != BOSMINER_HASHMAP_B824BC_PANIC_BL_INSN {
        return Err("0xb824bc is not BL 0x4538b0");
    }
    Ok(())
}

/// Linear predecessor `BL 0x4538b0` at `0xb824bc` does not produce X9.
pub fn refuse_hashmap_b824c8_as_panic_4538b0_return() -> Result<(), &'static str> {
    Err(
        "0xb824bc BL 0x4538b0 is panic-in-destructor; STR X9 is ADD X9,X8,#8 interior ptr, reached by B.cond to 0xb824c0",
    )
}

/// `0x115c788` is the rest[7] sibling of the  `X21+0x88/+0xA8` rewrite.
pub fn admit_bosminer_hashmap_115c788_is_field_rewrite(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_115C788_VA != BOSMINER_HASHMAP_STR88_REST_VA[7] {
        return Err("0x115c788 must stay rest[7]");
    }
    if BOSMINER_HASHMAP_115C788_STR_INSN != BOSMINER_HASHMAP_115C698_STR_INSN {
        return Err("sibling STR encoding must match rest[6]");
    }
    if BOSMINER_HASHMAP_115C784_LDR_A8_INSN != BOSMINER_HASHMAP_115C694_LDR_A8_INSN {
        return Err("sibling LDR #0xA8 encoding must match rest[6]");
    }
    let ldra8 = engine88_le_u32(blob, BOSMINER_HASHMAP_115C784_LDR_A8_VA)
        .ok_or("bosminer shorter than sibling LDR #0xA8")?;
    if ldra8 != BOSMINER_HASHMAP_115C784_LDR_A8_INSN {
        return Err("0x115c784 is not LDR X20,[X21,#0xA8]");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHMAP_115C788_VA)
        .ok_or("bosminer shorter than sibling STR #0x88")?;
    if st != BOSMINER_HASHMAP_115C788_STR_INSN {
        return Err("0x115c788 is not STR X8,[X21,#0x88]");
    }
    Ok(())
}

/// Classified rest dests are field/stack/interior stores, not engine nonce `.text`.
pub fn refuse_hashmap_rest_dests_as_engine_nonce_text() -> Result<(), &'static str> {
    Err(
        "rest dests are LDR[X23]/+0x90-slide/SLICE10/stack-X8/X8+8/field-rewrite — none is ADRP identity .text",
    )
}

/// thunk2 is a real `SUB SP,#0x30` function that tails into a `CBZ X1`/`UMULH` size product.
pub fn admit_bosminer_heap_thunk2_is_size_product(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_RUSTC_HEAP_THUNK2_B_TGT != 0x00BC_9E18 {
        return Err("thunk2 B target must be 0xbc9e18");
    }
    if BOSMINER_RUSTC_HEAP_THUNK2_BODY_VA == BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA {
        return Err("thunk2 body is not thunk0");
    }
    let sub = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_BODY_VA)
        .ok_or("bosminer shorter than thunk2 SUB")?;
    if sub != BOSMINER_RUSTC_HEAP_THUNK2_SUB_INSN {
        return Err("0x129b1e4 is not SUB SP,#0x30");
    }
    let cmp = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_CMP_VA)
        .ok_or("bosminer shorter than thunk2 CMP")?;
    if cmp != BOSMINER_RUSTC_HEAP_THUNK2_CMP_INSN {
        return Err("0x129b1f4 is not CMP X1,#0x10");
    }
    let save = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_SAVE_VA)
        .ok_or("bosminer shorter than thunk2 MOV X19,X0")?;
    if save != BOSMINER_RUSTC_HEAP_THUNK2_SAVE_INSN {
        return Err("0x129b1f8 is not MOV X19,X0");
    }
    let b = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_B_VA)
        .ok_or("bosminer shorter than thunk2 B")?;
    if b != BOSMINER_RUSTC_HEAP_THUNK2_B_INSN {
        return Err("0x129b21c is not B 0xbc9e18");
    }
    let stp = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_B_TGT)
        .ok_or("bosminer shorter than 0xbc9e18 STP")?;
    if stp != BOSMINER_RUSTC_HEAP_THUNK2_TGT_STP_INSN {
        return Err("0xbc9e18 is not STP X29,X30,[SP,#-0x30]!");
    }
    let cbz = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_TGT_CBZ_VA)
        .ok_or("bosminer shorter than 0xbc9e24 CBZ")?;
    if cbz != BOSMINER_RUSTC_HEAP_THUNK2_TGT_CBZ_INSN {
        return Err("0xbc9e24 is not CBZ X1");
    }
    let umul = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_VA)
        .ok_or("bosminer shorter than UMULH")?;
    if umul != BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_INSN {
        return Err("0xbc9e28 is not UMULH X2,X0,X1");
    }
    let mul = engine88_le_u32(blob, BOSMINER_RUSTC_HEAP_THUNK2_TGT_MUL_VA)
        .ok_or("bosminer shorter than MUL")?;
    if mul != BOSMINER_RUSTC_HEAP_THUNK2_TGT_MUL_INSN {
        return Err("0xbc9e30 is not MUL X19,X1,X0");
    }
    Ok(())
}

/// thunk2 is not the 4-insn dummy-frame trampoline.
pub fn refuse_heap_thunk2_as_dummy_trampoline() -> Result<(), &'static str> {
    Err(
        "thunk2 @ 0x129b1e4 is SUB SP,#0x30 + CMP X1,#0x10 + B 0xbc9e18 (CBZ X1/UMULH/MUL); not the 4-insn thunk0 trampoline",
    )
}

/// thunk2 is not the  dealloc `(ptr,0x18,8)` path.
pub fn refuse_heap_thunk2_as_dealloc() -> Result<(), &'static str> {
    Err(
        "dealloc is thunk0 dummy-frame B 0xbc9f10 / CBZ X0; thunk2 tails to 0xbc9e18 size-product (CBZ X1 + UMULH)",
    )
}

/// Fill type-1 +0x88 template is spawn `X24` (`[SP,#0x78]` after `BLR X23`), not ADRP identity.
pub fn admit_bosminer_fill_plus88_template_is_spawn_x24(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_SPAWN_BLR_VA != BOSMINER_FACTORY_SPAWN_BLR_VA {
        return Err("spawn BLR must stay Wave-123 0x87e15c");
    }
    if BOSMINER_SPAWN_SRET_ADD_INSN != BOSMINER_FACTORY_SPAWN_DEST_ADD_INSN {
        return Err("spawn sret ADD must stay ADD X8,SP,#0x68");
    }
    if BOSMINER_SPAWN_OK_SP != 0x78 {
        return Err("spawn Ok qword is [SP,#0x78]");
    }
    if BOSMINER_ADRP_ADD_STR88_HITS != 0 {
        return Err("ADRP+ADD+STR#0x88 census drifted");
    }
    if BOSMINER_ADRP_LDR_TEXT_STR88_NONSP_HITS != 0 {
        return Err("ADRP+LDR+.text+STR#0x88 non-SP census drifted");
    }
    if BOSMINER_E02C_METHODS_STR88_HITS != 0 {
        return Err("0x2a0 vtable methods grew a STR #0x88");
    }
    if BOSMINER_PROD_CALL_X1_MOV_VA != BOSMINER_SPAWN_X24_LDR_VA + 0x40 {
        return Err("MOV X1,X24 is not 0x40 after LDR X24,[SP,#0x60]");
    }
    let x23 = engine88_le_u32(blob, BOSMINER_SPAWN_X23_LDR_VA)
        .ok_or("bosminer shorter than LDR X23,[X1]")?;
    if x23 != BOSMINER_SPAWN_X23_LDR_INSN {
        return Err("0x87e094 is not LDR X23,[X1]");
    }
    let sret = engine88_le_u32(blob, BOSMINER_SPAWN_SRET_ADD_VA)
        .ok_or("bosminer shorter than ADD X8,SP,#0x68")?;
    if sret != BOSMINER_SPAWN_SRET_ADD_INSN {
        return Err("0x87e144 is not ADD X8,SP,#0x68");
    }
    let blr =
        engine88_le_u32(blob, BOSMINER_SPAWN_BLR_VA).ok_or("bosminer shorter than BLR X23")?;
    if blr != BOSMINER_SPAWN_BLR_INSN {
        return Err("0x87e15c is not BLR X23");
    }
    let ok = engine88_le_u32(blob, BOSMINER_SPAWN_OK_LDR_VA)
        .ok_or("bosminer shorter than LDR [SP,#0x78]")?;
    if ok != BOSMINER_SPAWN_OK_LDR_INSN {
        return Err("0x87e168 is not LDR X8,[SP,#0x78]");
    }
    let stash = engine88_le_u32(blob, BOSMINER_SPAWN_X24_STASH_VA)
        .ok_or("bosminer shorter than STR [SP,#0x60]")?;
    if stash != BOSMINER_SPAWN_X24_STASH_INSN {
        return Err("0x87e170 is not STR X8,[SP,#0x60]");
    }
    let x24 = engine88_le_u32(blob, BOSMINER_SPAWN_X24_LDR_VA)
        .ok_or("bosminer shorter than LDR X24,[SP,#0x60]")?;
    if x24 != BOSMINER_SPAWN_X24_LDR_INSN {
        return Err("0x87e188 is not LDR X24,[SP,#0x60]");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_PROD_CALL_X1_MOV_VA)
        .ok_or("bosminer shorter than MOV X1,X24")?;
    if x1 != BOSMINER_PROD_CALL_X1_MOV_INSN {
        return Err("0x87e1c8 is not MOV X1,X24");
    }
    Ok(())
}

/// No first-LOAD ADRP materializes a .text identity into engine +0x88.
pub fn refuse_fill_type1_adrp_identity_installer() -> Result<(), &'static str> {
    Err(
        "0 ADRP+ADD+STR#0x88; 0 ADRP+LDR+.text+STR#0x88 non-SP; factory/0x2a0 methods do not STR #0x88; fill +0x88 is spawn X24 clone source",
    )
}

/// `FUN_008787a8` returns `(X0=tag, X1=payload)` on both RETs.
pub fn admit_bosminer_hashmap_get_returns_tag_payload(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_GET_RET_X0_INSN != 0xAA13_03E0 {
        return Err("get X0 is MOV X0,X19");
    }
    if BOSMINER_HASHMAP_GET_RET_X1_INSN != 0xAA14_03E1 {
        return Err("get X1 is MOV X1,X20");
    }
    let add8 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_HIT_ADD8_VA)
        .ok_or("bosminer shorter than ADD X20,X21,#8")?;
    if add8 != BOSMINER_HASHMAP_GET_HIT_ADD8_INSN {
        return Err("0x878910 is not ADD X20,X21,#8");
    }
    let xzr = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_HIT_XZR_VA)
        .ok_or("bosminer shorter than MOV X19,XZR")?;
    if xzr != BOSMINER_HASHMAP_GET_HIT_XZR_INSN {
        return Err("0x878918 is not MOV X19,XZR");
    }
    let hx0 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_HIT_X0_VA)
        .ok_or("bosminer shorter than hit MOV X0,X19")?;
    if hx0 != BOSMINER_HASHMAP_GET_RET_X0_INSN {
        return Err("0x87891c is not MOV X0,X19");
    }
    let hx1 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_HIT_X1_VA)
        .ok_or("bosminer shorter than hit MOV X1,X20")?;
    if hx1 != BOSMINER_HASHMAP_GET_RET_X1_INSN {
        return Err("0x878920 is not MOV X1,X20");
    }
    let hret = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_HIT_RET_VA)
        .ok_or("bosminer shorter than hit RET")?;
    if hret != BOSMINER_HASHMAP_GET_RET_INSN {
        return Err("0x878930 is not RET");
    }
    let tag = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_MISS_TAG_VA)
        .ok_or("bosminer shorter than MOVZ W19,#1")?;
    if tag != BOSMINER_HASHMAP_GET_MISS_TAG_INSN {
        return Err("0x8788e4 is not MOVZ W19,#1");
    }
    let mx0 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_MISS_X0_VA)
        .ok_or("bosminer shorter than miss MOV X0,X19")?;
    if mx0 != BOSMINER_HASHMAP_GET_RET_X0_INSN {
        return Err("0x878938 is not MOV X0,X19");
    }
    let mx1 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_MISS_X1_VA)
        .ok_or("bosminer shorter than miss MOV X1,X20")?;
    if mx1 != BOSMINER_HASHMAP_GET_RET_X1_INSN {
        return Err("0x87893c is not MOV X1,X20");
    }
    let mret = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_MISS_RET_VA)
        .ok_or("bosminer shorter than miss RET")?;
    if mret != BOSMINER_HASHMAP_GET_RET_INSN {
        return Err("0x87894c is not RET");
    }
    Ok(())
}

/// Spawn `X23` is `LDR [X1]` of the get payload; miss payload is a `0x50` alloc.
pub fn admit_bosminer_spawn_x23_is_payload_qword0(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_SPAWN_TBZ_TGT != 0x0087_E278 {
        return Err("TBZ skip target is 0x87e278");
    }
    if BOSMINER_SPAWN_DEFAULT_SIZE != 0x50 {
        return Err("miss default size is 0x50");
    }
    if BOSMINER_SPAWN_DEFAULT_ALLOC_BL_TGT + 4 != BOSMINER_RUSTC_HEAP_THUNK0_VA {
        return Err("miss alloc stub is 4 bytes before thunk0");
    }
    if BOSMINER_SPAWN_MISS_PAYLOAD0_VA < 0x0178_EB88 {
        return Err("miss payload[0] typeinfo must be second LOAD");
    }
    let tbz =
        engine88_le_u32(blob, BOSMINER_SPAWN_TBZ_VA).ok_or("bosminer shorter than TBZ W0,#0")?;
    if tbz != BOSMINER_SPAWN_TBZ_INSN {
        return Err("0x87e08c is not TBZ W0,#0");
    }
    let x23 = engine88_le_u32(blob, BOSMINER_SPAWN_X23_LDR_VA)
        .ok_or("bosminer shorter than LDR X23,[X1]")?;
    if x23 != BOSMINER_SPAWN_X23_LDR_INSN {
        return Err("0x87e094 is not LDR X23,[X1]");
    }
    let sz = engine88_le_u32(blob, BOSMINER_SPAWN_DEFAULT_SIZE_VA)
        .ok_or("bosminer shorter than MOVZ W0,#0x50")?;
    if sz != BOSMINER_SPAWN_DEFAULT_SIZE_INSN {
        return Err("0x40be90 is not MOVZ W0,#0x50");
    }
    let al = engine88_le_u32(blob, BOSMINER_SPAWN_DEFAULT_ALIGN_VA)
        .ok_or("bosminer shorter than MOVZ W1,#8")?;
    if al != BOSMINER_SPAWN_DEFAULT_ALIGN_INSN {
        return Err("0x40be80 is not MOVZ W1,#8");
    }
    let bl = engine88_le_u32(blob, BOSMINER_SPAWN_DEFAULT_ALLOC_BL_VA)
        .ok_or("bosminer shorter than BL alloc stub")?;
    if bl != BOSMINER_SPAWN_DEFAULT_ALLOC_BL_INSN {
        return Err("0x40bea4 is not BL 0x5f4a78");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_SPAWN_MISS_TYPEINFO_ADRP_VA)
        .ok_or("bosminer shorter than typeinfo ADRP")?;
    if adrp != BOSMINER_SPAWN_MISS_TYPEINFO_ADRP_INSN {
        return Err("0x40be64 is not ADRP of 0x19bde50");
    }
    let add = engine88_le_u32(blob, BOSMINER_SPAWN_MISS_TYPEINFO_ADD_VA)
        .ok_or("bosminer shorter than typeinfo ADD")?;
    if add != BOSMINER_SPAWN_MISS_TYPEINFO_ADD_INSN {
        return Err("0x40be68 is not ADD #0x19bde50");
    }
    let st = engine88_le_u32(blob, BOSMINER_SPAWN_MISS_TYPEINFO_STR_VA)
        .ok_or("bosminer shorter than STR typeinfo [SP]")?;
    if st != BOSMINER_SPAWN_MISS_TYPEINFO_STR_INSN {
        return Err("0x40be70 is not STR X8,[SP]");
    }
    Ok(())
}

/// Miss-path `X23` is a second-LOAD typeinfo pointer, not first-LOAD identity `.text`.
pub fn refuse_spawn_x23_as_first_load_identity_text() -> Result<(), &'static str> {
    Err(
        "get tag0 (hit, X1=node+8) TBZ-skips spawn; tag1 miss X23=[X1] is 0x50 default whose qword0 is second-LOAD 0x19bde50, not first-LOAD identity .text",
    )
}

/// Insert helper uses the same hash as get and copies 0x18 from `X3` (`entry|8`).
pub fn admit_bosminer_hashmap_insert_copies_18_from_entry8(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_INSERT_VALUE_SIZE != 0x18 {
        return Err("insert value copy is 0x18");
    }
    if BOSMINER_HASHMAP_INSERT_VALUE_SIZE >= 0x88 {
        return Err("0x18 copy cannot reach value+0x88");
    }
    if BOSMINER_HASHMAP_INSERT_ORR8_INSN != BOSMINER_INSERT_VALUE_ORR8_INSN {
        return Err("ORR #8 must stay the Wave-60 insert src");
    }
    if BOSMINER_HASHMAP_INSERT_NONSP_STR88_HITS != 0 {
        return Err("insert helper grew a non-SP STR #0x88");
    }
    let src = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_SRC_MOV_VA)
        .ok_or("bosminer shorter than MOV X21,X3")?;
    if src != BOSMINER_HASHMAP_INSERT_SRC_MOV_INSN {
        return Err("0x8da530 is not MOV X21,X3");
    }
    let ih = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_HASH_BL_VA)
        .ok_or("bosminer shorter than insert hash BL")?;
    if ih != BOSMINER_HASHMAP_INSERT_HASH_BL_INSN {
        return Err("0x8da53c is not BL 0x8b8c84");
    }
    let gh = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_HASH_BL_VA)
        .ok_or("bosminer shorter than get hash BL")?;
    if gh != BOSMINER_HASHMAP_GET_HASH_BL_INSN {
        return Err("0x8787dc is not BL 0x8b8c84");
    }
    let lq = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_LDR_Q_VA)
        .ok_or("bosminer shorter than LDR Q1,[X21]")?;
    if lq != BOSMINER_HASHMAP_INSERT_LDR_Q_INSN {
        return Err("0x8da610 is not LDR Q1,[X21]");
    }
    let lx = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_LDR_X10_VA)
        .ok_or("bosminer shorter than LDR X9,[X21,#0x10]")?;
    if lx != BOSMINER_HASHMAP_INSERT_LDR_X10_INSN {
        return Err("0x8da614 is not LDR X9,[X21,#0x10]");
    }
    let sq = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_STUR_Q_VA)
        .ok_or("bosminer shorter than STUR Q1,[X17,#-0x20]")?;
    if sq != BOSMINER_HASHMAP_INSERT_STUR_Q_INSN {
        return Err("0x8da620 is not STUR Q1,[X17,#-0x20]");
    }
    let sx = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_STUR_X18_VA)
        .ok_or("bosminer shorter than STUR X9,[X17,#-8]")?;
    if sx != BOSMINER_HASHMAP_INSERT_STUR_X18_INSN {
        return Err("0x8da624 is not STUR X9,[X17,#-8]");
    }
    let orr = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_ORR8_VA)
        .ok_or("bosminer shorter than ORR X3,X21,#8")?;
    if orr != BOSMINER_HASHMAP_INSERT_ORR8_INSN {
        return Err("0x8d4a4c is not ORR X3,X21,#8");
    }
    let bl = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_CALL_BL_VA)
        .ok_or("bosminer shorter than BL insert helper")?;
    if bl != BOSMINER_HASHMAP_INSERT_CALL_BL_INSN {
        return Err("0x8d4a5c is not BL FUN_008da510");
    }
    Ok(())
}

/// Insert copies 0x18 at `entry|8`; it does not install engine +0x88 identity `.text`.
pub fn refuse_hashmap_insert_as_plus88_identity() -> Result<(), &'static str> {
    Err(
        "FUN_008da510 HIT copies Q+[0x10] from X3=entry|8 onto [X17-0x20] (0x18 bytes); 0 non-SP STR #0x88; value+8 is vt0, not identity .text at +0x88",
    )
}

/// `entry|8` qword0 is `FUN_00877d40` (factory clone-BL family[4]), stored via STP [SP,#0x38].
pub fn admit_bosminer_entry8_qword0_is_factory4(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_ENTRY8_QWORD0_FN_VA + 0x7C != BOSMINER_FACTORY_CLONE_BL_VA[4] {
        return Err("FUN_00877d40+0x7c must be factory clone-BL[4]");
    }
    if BOSMINER_FACTORY4_PROLOGUE_INSN != BOSMINER_BM1366_FACTORY_PROLOGUE_INSN {
        return Err("factory4 prologue must match FUN_00876ca8 STP");
    }
    if BOSMINER_ENTRY8_INSERT_FN_VA != 0x008D_4A10 {
        return Err("insert wrapper is FUN_008d4a10");
    }
    if BOSMINER_VT0_250_NONSP_STR88_HITS != 0 {
        return Err("0x250 box grew a non-SP STR #0x88");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_ENTRY8_QWORD0_ADRP_VA)
        .ok_or("bosminer shorter than ADRP X9 factory4")?;
    if adrp != BOSMINER_ENTRY8_QWORD0_ADRP_INSN {
        return Err("0x8624a0 is not ADRP X9,FUN_00877d40");
    }
    let add = engine88_le_u32(blob, BOSMINER_ENTRY8_QWORD0_ADD_VA)
        .ok_or("bosminer shorter than ADD X9,#0xd40")?;
    if add != BOSMINER_ENTRY8_QWORD0_ADD_INSN {
        return Err("0x8624a4 is not ADD X9,#0xd40");
    }
    let stp = engine88_le_u32(blob, BOSMINER_ENTRY8_QWORD0_STP_VA)
        .ok_or("bosminer shorter than STP [SP,#0x38]")?;
    if stp != BOSMINER_ENTRY8_QWORD0_STP_INSN {
        return Err("0x8624bc is not STP X9,X8,[SP,#0x38]");
    }
    let s1366 = engine88_le_u32(blob, BOSMINER_ENTRY8_1366_STP_VA)
        .ok_or("bosminer shorter than 1366 STP")?;
    if s1366 != BOSMINER_ENTRY8_1366_STP_INSN {
        return Err("0x8624d4 is not STP X9,X10,[SP,#0x58]");
    }
    let src = engine88_le_u32(blob, BOSMINER_ENTRY8_SRC_ADD_VA)
        .ok_or("bosminer shorter than ADD X1,SP,#0x30")?;
    if src != BOSMINER_ENTRY8_SRC_ADD_INSN {
        return Err("0x86256c is not ADD X1,SP,#0x30");
    }
    let ibl = engine88_le_u32(blob, BOSMINER_ENTRY8_INSERT_BL_VA)
        .ok_or("bosminer shorter than BL FUN_008d4a10")?;
    if ibl != BOSMINER_ENTRY8_INSERT_BL_INSN {
        return Err("0x862570 is not BL FUN_008d4a10");
    }
    let ldp = engine88_le_u32(blob, BOSMINER_ENTRY8_LDP_SRC_VA)
        .ok_or("bosminer shorter than LDP Q0,Q1,[X20]")?;
    if ldp != BOSMINER_ENTRY8_LDP_SRC_INSN {
        return Err("0x8d4a40 is not LDP Q0,Q1,[X20]");
    }
    let spm = engine88_le_u32(blob, BOSMINER_ENTRY8_SP_MOV_VA)
        .ok_or("bosminer shorter than ADD X21,SP")?;
    if spm != BOSMINER_ENTRY8_SP_MOV_INSN {
        return Err("0x8d4a44 is not ADD X21,SP,#0");
    }
    let stp_sp = engine88_le_u32(blob, BOSMINER_ENTRY8_STP_SP_VA)
        .ok_or("bosminer shorter than STP Q0,Q1,[SP]")?;
    if stp_sp != BOSMINER_ENTRY8_STP_SP_INSN {
        return Err("0x8d4a54 is not STP Q0,Q1,[SP]");
    }
    let pro = engine88_le_u32(blob, BOSMINER_ENTRY8_QWORD0_FN_VA)
        .ok_or("bosminer shorter than factory4 prologue")?;
    if pro != BOSMINER_FACTORY4_PROLOGUE_INSN {
        return Err("0x877d40 is not STP X29,X30 factory prologue");
    }
    Ok(())
}

/// qword0 is factory `#4` `.text`, not rustc identity; 0x250 box has no extra +0x88 store.
pub fn refuse_entry8_qword0_as_identity_text() -> Result<(), &'static str> {
    Err(
        "entry|8 qword0 is FUN_00877d40 (factory clone-BL[4]); 1366 pair is STP (factory4, vt0); 0 non-SP STR #0x88 after MOVZ #0x250",
    )
}

/// 1366 uses **two** factory monomorphs: dispatch `0x876ca8` (snap 0x15F8) and insert qword0 `0x877d40` (snap 0x1608).
pub fn admit_bosminer_1366_uses_two_factory_monomorphs(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FACTORY4_FN_VA != BOSMINER_ENTRY8_QWORD0_FN_VA {
        return Err("factory4 VA must stay entry|8 qword0");
    }
    if BOSMINER_FACTORY4_FN_VA == BOSMINER_BM1366_FACTORY_FN_VA {
        return Err("factory4 is not FUN_00876ca8");
    }
    if BOSMINER_FACTORY4_SNAP_SIZE != BOSMINER_FACTORY_SNAP_SIZE as u16 + 0x10 {
        return Err("factory4 snap is 0x15F8+0x10");
    }
    if BOSMINER_FACTORY4_FRAME != BOSMINER_FACTORY_876_FRAME + 0x30 {
        return Err("factory4 frame is 0x690+0x30");
    }
    if BOSMINER_FACTORY4_CLONE_BL_VA != BOSMINER_FACTORY_CLONE_BL_VA[4] {
        return Err("factory4 clone BL must stay family[4]");
    }
    if BOSMINER_FACTORY_876_CLONE_BL_VA != BOSMINER_FACTORY_CLONE_BL_VA[1] {
        return Err("876ca8 clone BL must stay family[1]");
    }
    if BOSMINER_FACTORY_876_WORKER_NEW_VA != BOSMINER_WORKER_NEW_FN_VA {
        return Err("876ca8 worker_new must stay FUN_00903534");
    }
    if BOSMINER_FACTORY4_WORKER_NEW_VA == BOSMINER_WORKER_NEW_FN_VA {
        return Err("factory4 worker_new is not FUN_00903534");
    }
    let f4 = engine88_le_u32(blob, BOSMINER_FACTORY4_FRAME_VA)
        .ok_or("bosminer shorter than factory4 SUB SP")?;
    if f4 != BOSMINER_FACTORY4_FRAME_INSN {
        return Err("0x877d78 is not SUB SP,#0x6c0");
    }
    let f876 = engine88_le_u32(blob, BOSMINER_FACTORY_876_FRAME_VA)
        .ok_or("bosminer shorter than 876ca8 SUB SP")?;
    if f876 != BOSMINER_FACTORY_876_FRAME_INSN {
        return Err("0x876ce0 is not SUB SP,#0x690");
    }
    let s4 = engine88_le_u32(blob, BOSMINER_FACTORY4_SNAP_SIZE_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x1608")?;
    if s4 != BOSMINER_FACTORY4_SNAP_SIZE_INSN {
        return Err("0x877e50 is not MOVZ W2,#0x1608");
    }
    let s876 = engine88_le_u32(blob, BOSMINER_FACTORY_SNAP_SIZE_VA)
        .ok_or("bosminer shorter than 876ca8 MOVZ #0x15F8")?;
    if s876 != BOSMINER_FACTORY_SNAP_SIZE_INSN {
        return Err("0x876db8 is not MOVZ W2,#0x15F8");
    }
    let w4 = engine88_le_u32(blob, BOSMINER_FACTORY4_WORKER_NEW_BL_VA)
        .ok_or("bosminer shorter than factory4 worker_new BL")?;
    if w4 != BOSMINER_FACTORY4_WORKER_NEW_BL_INSN {
        return Err("0x877e38 is not BL FUN_00904434");
    }
    let w876 = engine88_le_u32(blob, BOSMINER_FACTORY_WORKER_NEW_BL_VA)
        .ok_or("bosminer shorter than 876ca8 worker_new BL")?;
    if w876 != BOSMINER_FACTORY_WORKER_NEW_BL_INSN {
        return Err("0x876da0 is not BL FUN_00903534");
    }
    let c4 = engine88_le_u32(blob, BOSMINER_FACTORY4_CLONE_BL_VA)
        .ok_or("bosminer shorter than factory4 clone BL")?;
    if c4 != BOSMINER_FACTORY_CLONE_BL_INSN[4] {
        return Err("0x877dbc is not BL FUN_00875f54");
    }
    let c876 = engine88_le_u32(blob, BOSMINER_FACTORY_876_CLONE_BL_VA)
        .ok_or("bosminer shorter than 876ca8 clone BL")?;
    if c876 != BOSMINER_FACTORY_CLONE_BL_INSN[1] {
        return Err("0x876d24 is not BL FUN_00875f54");
    }
    let dmov = engine88_le_u32(blob, BOSMINER_BM1366_DISPATCH_MOVZ_VA)
        .ok_or("bosminer shorter than dispatch MOVZ #0x1366")?;
    if dmov != BOSMINER_BM1366_DISPATCH_MOVZ_INSN {
        return Err("0x8d6d14 is not MOVZ W10,#0x1366");
    }
    Ok(())
}

/// The two 1366 factories are not the same function and must not be merged.
pub fn refuse_factory4_as_876ca8() -> Result<(), &'static str> {
    Err(
        "1366 dispatch materializes FUN_00876ca8 (snap 0x15F8, worker_new 0x903534); insert qword0 is FUN_00877d40 (snap 0x1608, worker_new 0x904434); both BL clone 0x875f54",
    )
}

/// worker_new `0x903534` / `0x904434` are sibling monomorphs; factory extra sizes are snap+8 / snap+0x298.
pub fn admit_bosminer_worker_new_monomorphs_split(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FACTORY_876_WORKER_NEW_VA == BOSMINER_FACTORY4_WORKER_NEW_VA {
        return Err("worker_new monomorphs must stay distinct");
    }
    if BOSMINER_WORKER_NEW_FACTORY4_FRAME != BOSMINER_WORKER_NEW_876_FRAME + 0x20 {
        return Err("factory4 worker_new frame is 0xEE0+0x20");
    }
    if BOSMINER_FACTORY_876_COPY1600 != BOSMINER_FACTORY_SNAP_SIZE as u16 + 8 {
        return Err("876 second copy is snap+8");
    }
    if BOSMINER_FACTORY4_COPY1610 != BOSMINER_FACTORY4_SNAP_SIZE + 8 {
        return Err("factory4 second copy is snap+8");
    }
    if BOSMINER_FACTORY_876_ALLOC1890 != BOSMINER_FACTORY_876_COPY1600 + 0x290 {
        return Err("876 alloc is copy+0x290");
    }
    if BOSMINER_FACTORY4_ALLOC18A0 != BOSMINER_FACTORY4_COPY1610 + 0x290 {
        return Err("factory4 alloc is copy+0x290");
    }
    let f876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_FRAME_VA)
        .ok_or("bosminer shorter than 876 worker_new SUB SP")?;
    if f876 != BOSMINER_WORKER_NEW_876_FRAME_INSN {
        return Err("0x903550 is not SUB SP,#0xee0");
    }
    let f4 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_FRAME_VA)
        .ok_or("bosminer shorter than factory4 worker_new SUB SP")?;
    if f4 != BOSMINER_WORKER_NEW_FACTORY4_FRAME_INSN {
        return Err("0x904450 is not SUB SP,#0xf00");
    }
    let c876 = engine88_le_u32(blob, BOSMINER_FACTORY_876_COPY1600_VA)
        .ok_or("bosminer shorter than 876 MOVZ #0x1600")?;
    if c876 != BOSMINER_FACTORY_876_COPY1600_INSN {
        return Err("0x876e58 is not MOVZ W2,#0x1600");
    }
    let c4 = engine88_le_u32(blob, BOSMINER_FACTORY4_COPY1610_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x1610")?;
    if c4 != BOSMINER_FACTORY4_COPY1610_INSN {
        return Err("0x877ef0 is not MOVZ W2,#0x1610");
    }
    let m876 = engine88_le_u32(blob, BOSMINER_FACTORY_876_COPY230_VA)
        .ok_or("bosminer shorter than 876 MOVZ #0x230")?;
    let m4 = engine88_le_u32(blob, BOSMINER_FACTORY4_COPY230_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x230")?;
    if m876 != BOSMINER_FACTORY_COPY_230_INSN || m4 != BOSMINER_FACTORY_COPY_230_INSN {
        return Err("both factories MOVZ W2,#0x230");
    }
    let a876 = engine88_le_u32(blob, BOSMINER_FACTORY_876_ALLOC1890_VA)
        .ok_or("bosminer shorter than 876 MOVZ #0x1890")?;
    if a876 != BOSMINER_FACTORY_876_ALLOC1890_INSN {
        return Err("0x876ec4 is not MOVZ W2,#0x1890");
    }
    let a4 = engine88_le_u32(blob, BOSMINER_FACTORY4_ALLOC18A0_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x18a0")?;
    if a4 != BOSMINER_FACTORY4_ALLOC18A0_INSN {
        return Err("0x877f5c is not MOVZ W2,#0x18a0");
    }
    let c1a8 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_COPY1A8_VA)
        .ok_or("bosminer shorter than 876 worker_new MOVZ #0x1a8")?;
    if c1a8 != BOSMINER_WORKER_NEW_876_COPY1A8_INSN {
        return Err("0x903690 is not MOVZ W2,#0x1a8");
    }
    let ca = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_CA00_VA)
        .ok_or("bosminer shorter than factory4 worker_new MOVZ #0xca00")?;
    if ca != BOSMINER_WORKER_NEW_FACTORY4_CA00_INSN {
        return Err("0x9044d8 is not MOVZ W9,#0xca00");
    }
    Ok(())
}

/// The two worker_new functions are not interchangeable.
pub fn refuse_worker_new_factory4_as_876() -> Result<(), &'static str> {
    Err(
        "876 worker_new FUN_00903534 frame 0xEE0 MOVZ #0x1a8; factory4 FUN_00904434 frame 0xF00 MOVZ W9 #0xca00; factory extra sizes +0x10 (0x1600/0x1610, 0x1890/0x18a0); 0x230 memcpy shared",
    )
}

/// factory4 `#0xca00` is MOVZ+MOVK `1_000_000_000`, then `CMP W8,W9`.
pub fn admit_bosminer_factory4_ca00_is_1e9(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_WORKER_NEW_FACTORY4_1E9 != 1_000_000_000 {
        return Err("1e9 pin drifted");
    }
    let lo = u32::from(BOSMINER_WORKER_NEW_FACTORY4_CA00);
    let hi = 0x3B9A_u32;
    if (hi << 16) | lo != BOSMINER_WORKER_NEW_FACTORY4_1E9 {
        return Err("MOVZ #0xca00 + MOVK #0x3b9a LSL#16 is 1e9");
    }
    if BOSMINER_CA00_MOVZ_W9_HITS != 230 {
        return Err("first-LOAD MOVZ W9 #0xca00 census is 230");
    }
    let z = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_CA00_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0xca00")?;
    if z != BOSMINER_WORKER_NEW_FACTORY4_CA00_INSN {
        return Err("0x9044d8 is not MOVZ W9,#0xca00");
    }
    let k = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_MOVK_VA)
        .ok_or("bosminer shorter than factory4 MOVK #0x3b9a")?;
    if k != BOSMINER_WORKER_NEW_FACTORY4_MOVK_INSN {
        return Err("0x9044e0 is not MOVK W9,#0x3b9a,LSL#16");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_LDR_W8_VA)
        .ok_or("bosminer shorter than factory4 LDR W8")?;
    if ldr != BOSMINER_WORKER_NEW_FACTORY4_LDR_W8_INSN {
        return Err("0x9044d4 is not LDR W8,[SP,#0x380]");
    }
    let cmp = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_CMP_VA)
        .ok_or("bosminer shorter than factory4 CMP W8,W9")?;
    if cmp != BOSMINER_WORKER_NEW_FACTORY4_CMP_INSN {
        return Err("0x9044e4 is not CMP W8,W9");
    }
    let bne = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_BNE_VA)
        .ok_or("bosminer shorter than factory4 B.NE")?;
    if bne != BOSMINER_WORKER_NEW_FACTORY4_BNE_INSN {
        return Err("0x9044e8 is not B.NE");
    }
    Ok(())
}

/// `#0xca00` is not a factory4-only type tag or extra-size.
pub fn refuse_ca00_as_factory4_type_tag() -> Result<(), &'static str> {
    Err(
        "factory4 MOVZ W9,#0xca00 + MOVK #0x3b9a,LSL#16 = 1_000_000_000; CMP W8,W9; 230 first-LOAD MOVZ W9 #0xca00 hits; 876 worker_new has none in first 0x800",
    )
}

/// Both worker_new monomorphs memcpy `#0x1a8` through `FUN_00bc8fe0`.
pub fn admit_bosminer_worker_new_copy1a8_shared(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_WORKER_NEW_FACTORY4_COPY1A8_VA != BOSMINER_FACTORY4_WORKER_NEW_VA + 0x25C {
        return Err("factory4 #0x1a8 is worker_new+0x25c");
    }
    if BOSMINER_WORKER_NEW_876_COPY1A8_VA != BOSMINER_FACTORY_876_WORKER_NEW_VA + 0x15C {
        return Err("876 #0x1a8 is worker_new+0x15c");
    }
    if BOSMINER_WORKER_NEW_876_MEMCPY_BL_VA
        != BOSMINER_WORKER_NEW_876_COPY1A8_VA + u64::from(BOSMINER_WORKER_NEW_COPY1A8_TO_MEMCPY)
    {
        return Err("876 memcpy BL is #0x1a8+0x3c");
    }
    if BOSMINER_WORKER_NEW_FACTORY4_MEMCPY_BL_VA
        != BOSMINER_WORKER_NEW_FACTORY4_COPY1A8_VA
            + u64::from(BOSMINER_WORKER_NEW_COPY1A8_TO_MEMCPY)
    {
        return Err("factory4 memcpy BL is #0x1a8+0x3c");
    }
    if BOSMINER_WORKER_NEW_1A8_MOVZ_HITS != 64 {
        return Err("first-LOAD MOVZ W2 #0x1a8 census is 64");
    }
    let z876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_COPY1A8_VA)
        .ok_or("bosminer shorter than 876 MOVZ #0x1a8")?;
    if z876 != BOSMINER_WORKER_NEW_876_COPY1A8_INSN {
        return Err("0x903690 is not MOVZ W2,#0x1a8");
    }
    let z4 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_COPY1A8_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x1a8")?;
    if z4 != BOSMINER_WORKER_NEW_876_COPY1A8_INSN {
        return Err("0x904690 is not MOVZ W2,#0x1a8");
    }
    let b876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_MEMCPY_BL_VA)
        .ok_or("bosminer shorter than 876 memcpy BL")?;
    if b876 != BOSMINER_WORKER_NEW_876_MEMCPY_BL_INSN {
        return Err("0x9036cc is not BL FUN_00bc8fe0");
    }
    let b4 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_MEMCPY_BL_VA)
        .ok_or("bosminer shorter than factory4 memcpy BL")?;
    if b4 != BOSMINER_WORKER_NEW_FACTORY4_MEMCPY_BL_INSN {
        return Err("0x9046cc is not BL FUN_00bc8fe0");
    }
    Ok(())
}

/// `#0x1a8` is a shared worker_new copy, not the factory +16 type-param.
pub fn refuse_copy1a8_as_factory_type_param() -> Result<(), &'static str> {
    Err(
        "both worker_new MOVZ W2,#0x1a8 then BL memcpy 0xbc8fe0 at +0x3c; 64 first-LOAD hits; +16 factory snap is not 0x1a8",
    )
}

/// factory4 extra 16 B is the snap tail: dest `SP+#0x40` shared, src low `#0x640` vs `#0x650`.
pub fn admit_bosminer_factory4_snap_extra_is_tail_16(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FACTORY4_SNAP_SRC_LOW != BOSMINER_FACTORY_SNAP_SRC_LOW + 0x10 {
        return Err("factory4 src low is 0x640+0x10");
    }
    if u32::from(BOSMINER_FACTORY_SNAP_SRC_HIGH) + u32::from(BOSMINER_FACTORY_SNAP_SRC_LOW)
        != u32::from(BOSMINER_FACTORY_SNAP_DEST_OFF) + u32::from(BOSMINER_FACTORY_876_COPY1600)
    {
        return Err("876 src is dest+0x1600");
    }
    if u32::from(BOSMINER_FACTORY_SNAP_SRC_HIGH) + u32::from(BOSMINER_FACTORY4_SNAP_SRC_LOW)
        != u32::from(BOSMINER_FACTORY_SNAP_DEST_OFF) + u32::from(BOSMINER_FACTORY4_COPY1610)
    {
        return Err("factory4 src is dest+0x1610");
    }
    if BOSMINER_ENTRY8_PLUS10_VALUE != 0x002F_AF08 {
        return Err("entry|8+0x10 is 0x2faf08");
    }
    let d876 = engine88_le_u32(blob, BOSMINER_FACTORY_SNAP_DEST_ADD_VA)
        .ok_or("bosminer shorter than 876 dest ADD")?;
    let d4 = engine88_le_u32(blob, BOSMINER_FACTORY4_SNAP_DEST_ADD_VA)
        .ok_or("bosminer shorter than factory4 dest ADD")?;
    if d876 != BOSMINER_FACTORY_SNAP_DEST_ADD_INSN || d4 != BOSMINER_FACTORY_SNAP_DEST_ADD_INSN {
        return Err("both snap dest ADD X9,SP,#0x40");
    }
    let h876 = engine88_le_u32(blob, BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_VA)
        .ok_or("bosminer shorter than 876 src high ADD")?;
    let h4 = engine88_le_u32(blob, BOSMINER_FACTORY4_SNAP_SRC_HIGH_ADD_VA)
        .ok_or("bosminer shorter than factory4 src high ADD")?;
    if h876 != BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_INSN
        || h4 != BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_INSN
    {
        return Err("both snap src high ADD X8,SP,#0x1000");
    }
    let l876 = engine88_le_u32(blob, BOSMINER_FACTORY_876_SNAP_SRC_LOW_ADD_VA)
        .ok_or("bosminer shorter than 876 src low ADD")?;
    if l876 != BOSMINER_FACTORY_876_SNAP_SRC_LOW_ADD_INSN {
        return Err("0x876dbc is not ADD X8,#0x640");
    }
    let l4 = engine88_le_u32(blob, BOSMINER_FACTORY4_SNAP_SRC_LOW_ADD_VA)
        .ok_or("bosminer shorter than factory4 src low ADD")?;
    if l4 != BOSMINER_FACTORY4_SNAP_SRC_LOW_ADD_INSN {
        return Err("0x877e54 is not ADD X8,#0x650");
    }
    let mz = engine88_le_u32(blob, BOSMINER_ENTRY8_PLUS10_MOVZ_VA)
        .ok_or("bosminer shorter than entry+0x10 MOVZ")?;
    if mz != BOSMINER_ENTRY8_PLUS10_MOVZ_INSN {
        return Err("0x8624c0 is not MOVZ W8,#0xaf08");
    }
    let mk = engine88_le_u32(blob, BOSMINER_ENTRY8_PLUS10_MOVK_VA)
        .ok_or("bosminer shorter than entry+0x10 MOVK")?;
    if mk != BOSMINER_ENTRY8_PLUS10_MOVK_INSN {
        return Err("0x8624c4 is not MOVK W8,#0x2f,LSL#16");
    }
    let st = engine88_le_u32(blob, BOSMINER_ENTRY8_PLUS10_STR_VA)
        .ok_or("bosminer shorter than entry+0x10 STR")?;
    if st != BOSMINER_ENTRY8_PLUS10_STR_INSN {
        return Err("0x8624c8 is not STR X8,[SP,#0x48]");
    }
    Ok(())
}

/// `entry|8+0x10` is an 8-byte `0x2faf08`, not the factory snap tail.
pub fn refuse_entry8_plus10_as_snap_extra16() -> Result<(), &'static str> {
    Err(
        "entry|8+0x10 is STR [SP,#0x48] of MOVZ+MOVK 0x2faf08 (8 B); factory4 extra 16 B is snap tail dest SP+0x40 src #0x650 size 0x1608",
    )
}

/// Extra 16 B is two worker_new qwords at `+0x15F8` / `+0x1600`; only factory4 snap copies them.
pub fn admit_bosminer_snap_extra16_is_worker_new_tail(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_WORKER_NEW_TAIL_Q0_OFF != BOSMINER_FACTORY_SNAP_SIZE as u16 {
        return Err("tail Q0 is at 876 snap end");
    }
    if BOSMINER_WORKER_NEW_TAIL_Q1_OFF != BOSMINER_WORKER_NEW_TAIL_Q0_OFF + 8 {
        return Err("tail Q1 is Q0+8");
    }
    if BOSMINER_FACTORY4_SNAP_SIZE != BOSMINER_WORKER_NEW_TAIL_Q1_OFF + 8 {
        return Err("factory4 snap covers both tail qwords");
    }
    if BOSMINER_FACTORY_SNAP_SIZE as u16 + 0x10 != BOSMINER_FACTORY4_SNAP_SIZE {
        return Err("factory4 snap is 876 snap + two qwords");
    }
    let a = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_15F8_VA)
        .ok_or("bosminer shorter than 876 STR #0x15f8")?;
    if a != BOSMINER_WORKER_NEW_876_STR_15F8_INSN {
        return Err("0x903f90 is not STR X9,[X22,#0x15f8]");
    }
    let b = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_1600_VA)
        .ok_or("bosminer shorter than 876 STR #0x1600")?;
    if b != BOSMINER_WORKER_NEW_876_STR_1600_INSN {
        return Err("0x903fc4 is not STR X21,[X22,#0x1600]");
    }
    let c = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_STR_15F8_VA)
        .ok_or("bosminer shorter than factory4 STR #0x15f8")?;
    if c != BOSMINER_WORKER_NEW_FACTORY4_STR_15F8_INSN {
        return Err("0x904ed4 is not STR X19,[X21,#0x15f8]");
    }
    let d = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_STR_1600_VA)
        .ok_or("bosminer shorter than factory4 STR #0x1600")?;
    if d != BOSMINER_WORKER_NEW_FACTORY4_STR_1600_INSN {
        return Err("0x904ec0 is not STR X9,[X21,#0x1600]");
    }
    Ok(())
}

/// The tail qwords are worker_new fields, not HashMap `0x2faf08`.
pub fn refuse_tail16_as_entry8_plus10() -> Result<(), &'static str> {
    Err(
        "both worker_new STR +0x15F8 and +0x1600; factory4 snap 0x1608 copies them; 876 snap 0x15F8 does not; not entry|8+0x10 0x2faf08",
    )
}

/// 876 `+0x15F8` is Worker::new arg0 (`X0` via `X24` / `SP+#0x30`); `+0x1600` is the next call return.
pub fn admit_bosminer_876_tail_15f8_is_arg0(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_WORKER_NEW_FACTORY4_1209 != 0x1209 {
        return Err("factory4 +0x1600 constant is 0x1209");
    }
    if BOSMINER_AF08_MOVZ_W8_HITS != 4 {
        return Err("first-LOAD MOVZ W8 #0xaf08 census is 4");
    }
    let m24 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_MOV_X24_X0_VA)
        .ok_or("bosminer shorter than MOV X24,X0")?;
    if m24 != BOSMINER_WORKER_NEW_876_MOV_X24_X0_INSN {
        return Err("0x903560 is not MOV X24,X0");
    }
    let m22 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_MOV_X22_X8_VA)
        .ok_or("bosminer shorter than MOV X22,X8")?;
    if m22 != BOSMINER_WORKER_NEW_876_MOV_X22_X8_INSN {
        return Err("0x903564 is not MOV X22,X8");
    }
    let st24 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_X24_SP30_VA)
        .ok_or("bosminer shorter than STR X24 [SP,#0x30]")?;
    if st24 != BOSMINER_WORKER_NEW_876_STR_X24_SP30_INSN {
        return Err("0x903e30 is not STR X24,[SP,#0x30]");
    }
    let ld9 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_LDR_X9_SP30_VA)
        .ok_or("bosminer shorter than LDR X9 [SP,#0x30]")?;
    if ld9 != BOSMINER_WORKER_NEW_876_LDR_X9_SP30_INSN {
        return Err("0x903f64 is not LDR X9,[SP,#0x30]");
    }
    let c13 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_13B8_VA)
        .ok_or("bosminer shorter than STR #0x13b8")?;
    if c13 != BOSMINER_WORKER_NEW_876_STR_13B8_INSN {
        return Err("0x903f78 is not STR X9,[X22,#0x13b8]");
    }
    let t15 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_15F8_VA)
        .ok_or("bosminer shorter than STR #0x15f8")?;
    if t15 != BOSMINER_WORKER_NEW_876_STR_15F8_INSN {
        return Err("0x903f90 is not STR X9,[X22,#0x15f8]");
    }
    let mx0 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_MOV_X0_X24_VA)
        .ok_or("bosminer shorter than MOV X0,X24")?;
    if mx0 != BOSMINER_WORKER_NEW_876_MOV_X0_X24_INSN {
        return Err("0x903754 is not MOV X0,X24");
    }
    let bl = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_CALL_BL_VA)
        .ok_or("bosminer shorter than BL after MOV X0,X24")?;
    if bl != BOSMINER_WORKER_NEW_876_CALL_BL_INSN {
        return Err("0x90375c is not BL FUN_00bf33a4");
    }
    let sp = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_SP5F0_VA)
        .ok_or("bosminer shorter than STR X0 [SP,#0x5f0]")?;
    if sp != BOSMINER_WORKER_NEW_876_STR_SP5F0_INSN {
        return Err("0x903768 is not STR X0,[SP,#0x5f0]");
    }
    let ld21 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_LDR_X21_SP5F0_VA)
        .ok_or("bosminer shorter than LDR X21 [SP,#0x5f0]")?;
    if ld21 != BOSMINER_WORKER_NEW_876_LDR_X21_SP5F0_INSN {
        return Err("0x903f00 is not LDR X21,[SP,#0x5f0]");
    }
    let t16 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_1600_VA)
        .ok_or("bosminer shorter than STR #0x1600")?;
    if t16 != BOSMINER_WORKER_NEW_876_STR_1600_INSN {
        return Err("0x903fc4 is not STR X21,[X22,#0x1600]");
    }
    let z = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x1209")?;
    if z != BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN {
        return Err("0x904e6c is not MOVZ W9,#0x1209");
    }
    let cmp =
        engine88_le_u32(blob, BOSMINER_AF08_CMP_VA).ok_or("bosminer shorter than 0x2faf08 CMP")?;
    if cmp != BOSMINER_AF08_CMP_INSN {
        return Err("0xbc00b4 is not CMP X1,X8");
    }
    let c11 = engine88_le_u32(blob, BOSMINER_AF08_CLASS11_VA)
        .ok_or("bosminer shorter than size-class 11")?;
    if c11 != BOSMINER_AF08_CLASS11_INSN {
        return Err("0xbc00bc is not MOVZ W20,#0xb");
    }
    let c10 = engine88_le_u32(blob, BOSMINER_AF08_CLASS10_VA)
        .ok_or("bosminer shorter than size-class 10")?;
    if c10 != BOSMINER_AF08_CLASS10_INSN {
        return Err("0xbc00c4 is not MOVZ W20,#0xa");
    }
    Ok(())
}

/// `0x2faf08` is a rustc size-class threshold, not a worker_new tail payload.
pub fn refuse_2faf08_as_worker_new_tail() -> Result<(), &'static str> {
    Err(
        "0x2faf08 is MOVZ+MOVK then CMP at 0xbc00ac (class 10 vs 11); 4 first-LOAD hits; HashMap entry|8+0x10 stores it; 876 +0x15F8 is X0, +0x1600 is BL 0xbf33a4 return",
    )
}

/// factory4 `+0x1600` is `#0x1209`, not 876 arg0.
pub fn refuse_factory4_1600_as_876_arg0() -> Result<(), &'static str> {
    Err(
        "factory4 STR X9,#0x1600 after MOVZ W9,#0x1209; 876 STR X21,#0x1600 from [SP,#0x5f0] call return; do not merge",
    )
}

/// Factory X23 is factory X0 (self); Worker::new X0 is that self; `FUN_00bf33a4` boxes 0x70.
pub fn admit_bosminer_factory_x23_is_self_and_bf33a4_is_70_box(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FACTORY_MOV_X0_X23_INSN != BOSMINER_FACTORY_WORKER_NEW_DEST_INSN {
        return Err("factory MOV X0,X23 must stay worker_new dest MOV");
    }
    if BOSMINER_WORKER_NEW_876_CALL_TGT != 0x00BF_33A4 {
        return Err("876 call target is FUN_00bf33a4");
    }
    if BOSMINER_BF33A4_SIZE != 0x70 {
        return Err("box size is 0x70");
    }
    if BOSMINER_WORKER_NEW_FACTORY4_1209 != BOSMINER_WORKER_NEW_COPY1208 + 1 {
        return Err("0x1209 is 0x1208+1");
    }
    let s876 = engine88_le_u32(blob, BOSMINER_FACTORY_876_MOV_X23_X0_VA)
        .ok_or("bosminer shorter than 876 MOV X23,X0")?;
    let s4 = engine88_le_u32(blob, BOSMINER_FACTORY4_MOV_X23_X0_VA)
        .ok_or("bosminer shorter than factory4 MOV X23,X0")?;
    if s876 != BOSMINER_FACTORY_MOV_X23_X0_INSN || s4 != BOSMINER_FACTORY_MOV_X23_X0_INSN {
        return Err("both factories MOV X23,X0");
    }
    let d876 = engine88_le_u32(blob, BOSMINER_FACTORY_WORKER_NEW_DEST_VA)
        .ok_or("bosminer shorter than 876 MOV X0,X23")?;
    let d4 = engine88_le_u32(blob, BOSMINER_FACTORY4_MOV_X0_X23_VA)
        .ok_or("bosminer shorter than factory4 MOV X0,X23")?;
    if d876 != BOSMINER_FACTORY_MOV_X0_X23_INSN || d4 != BOSMINER_FACTORY_MOV_X0_X23_INSN {
        return Err("both factories MOV X0,X23 before Worker::new");
    }
    let fr = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_CALL_TGT)
        .ok_or("bosminer shorter than FUN_00bf33a4")?;
    if fr != BOSMINER_BF33A4_FRAME_INSN {
        return Err("0xbf33a4 is not SUB SP,#0x80");
    }
    let sz =
        engine88_le_u32(blob, BOSMINER_BF33A4_SIZE_VA).ok_or("bosminer shorter than MOVZ #0x70")?;
    if sz != BOSMINER_BF33A4_SIZE_INSN {
        return Err("0xbf33e4 is not MOVZ W0,#0x70");
    }
    let al =
        engine88_le_u32(blob, BOSMINER_BF33A4_ALIGN_VA).ok_or("bosminer shorter than MOVZ #8")?;
    if al != BOSMINER_BF33A4_ALIGN_INSN {
        return Err("0xbf33e8 is not MOVZ W1,#8");
    }
    let ab = engine88_le_u32(blob, BOSMINER_BF33A4_ALLOC_BL_VA)
        .ok_or("bosminer shorter than alloc BL")?;
    if ab != BOSMINER_BF33A4_ALLOC_BL_INSN {
        return Err("0xbf3400 is not BL 0x5f4a78");
    }
    let st = engine88_le_u32(blob, BOSMINER_BF33A4_STR20_VA)
        .ok_or("bosminer shorter than STR [X0,#0x20]")?;
    if st != BOSMINER_BF33A4_STR20_INSN {
        return Err("0xbf3424 is not STR X23,[X0,#0x20]");
    }
    let rt = engine88_le_u32(blob, BOSMINER_BF33A4_RET_VA)
        .ok_or("bosminer shorter than FUN_00bf33a4 RET")?;
    if rt != BOSMINER_BF33A4_RET_INSN {
        return Err("0xbf3448 is not RET");
    }
    let z876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_MOVZ_1209_VA)
        .ok_or("bosminer shorter than 876 MOVZ #0x1209")?;
    if z876 != BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN {
        return Err("0x903f2c is not MOVZ W9,#0x1209");
    }
    let a876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_ADD_1209_VA)
        .ok_or("bosminer shorter than 876 ADD X0,X22,X9")?;
    if a876 != BOSMINER_WORKER_NEW_876_ADD_1209_INSN {
        return Err("0x903f34 is not ADD X0,X22,X9");
    }
    let c876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_MOVZ_1208_VA)
        .ok_or("bosminer shorter than 876 MOVZ #0x1208")?;
    let c4 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1208_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x1208")?;
    if c876 != BOSMINER_WORKER_NEW_COPY1208_INSN || c4 != BOSMINER_WORKER_NEW_COPY1208_INSN {
        return Err("both worker_new MOVZ W8,#0x1208");
    }
    let a4 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_ADD_1209_VA)
        .ok_or("bosminer shorter than factory4 ADD X0,X21,X9")?;
    if a4 != BOSMINER_WORKER_NEW_FACTORY4_ADD_1209_INSN {
        return Err("0x904e78 is not ADD X0,X21,X9");
    }
    Ok(())
}

/// `FUN_00bf33a4` is a 0x70 box of arg0, not identity `.text`.
pub fn refuse_bf33a4_as_identity() -> Result<(), &'static str> {
    Err(
        "FUN_00bf33a4 MOVZ #0x70/#8 BL alloc 0x5f4a78; STR arg0 at [box+0x20]; RET X0=box; 876 +0x1600 is that pointer",
    )
}

/// 0x70 box fields: +0x10=X3, +0x18=W4, +0x20=self, +0x48=(X8,0), +0x60=(X1,X2); Q0 at +0.
pub fn admit_bosminer_bf33a4_box_fields_and_1208_header(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_BF33A4_BL_HITS != 6 {
        return Err("FUN_00bf33a4 has 6 BL callers");
    }
    if BOSMINER_WORKER_NEW_COPY1AF_HITS != 6 {
        return Err("MOVZ W2,#0x1af census is 6");
    }
    if BOSMINER_FACTORY_SELF_X23_LDR_HITS != 0 {
        return Err("factory bodies have 0 LDR [X23,#off]");
    }
    if BOSMINER_FACTORY_DIRECT_BL_HITS != 0 {
        return Err("0 direct BL to either factory");
    }
    if BOSMINER_WORKER_NEW_COPY1AF != 0x1AF {
        return Err("memcpy size is 0x1af not 0x1208");
    }
    let s10 = engine88_le_u32(blob, BOSMINER_BF33A4_STR10_VA)
        .ok_or("bosminer shorter than STR [X0,#0x10]")?;
    if s10 != BOSMINER_BF33A4_STR10_INSN {
        return Err("0xbf3414 is not STR X22,[X0,#0x10]");
    }
    let b18 = engine88_le_u32(blob, BOSMINER_BF33A4_STRB18_VA)
        .ok_or("bosminer shorter than STRB [X0,#0x18]")?;
    if b18 != BOSMINER_BF33A4_STRB18_INSN {
        return Err("0xbf341c is not STRB W21,[X0,#0x18]");
    }
    let s20 = engine88_le_u32(blob, BOSMINER_BF33A4_STR20_VA)
        .ok_or("bosminer shorter than STR [X0,#0x20]")?;
    if s20 != BOSMINER_BF33A4_STR20_INSN {
        return Err("0xbf3424 is not STR X23,[X0,#0x20]");
    }
    let p60 = engine88_le_u32(blob, BOSMINER_BF33A4_STP60_VA)
        .ok_or("bosminer shorter than STP [X0,#0x60]")?;
    if p60 != BOSMINER_BF33A4_STP60_INSN {
        return Err("0xbf342c is not STP X20,X19,[X0,#0x60]");
    }
    let p48 = engine88_le_u32(blob, BOSMINER_BF33A4_STP48_VA)
        .ok_or("bosminer shorter than STP [X0,#0x48]")?;
    if p48 != BOSMINER_BF33A4_STP48_INSN {
        return Err("0xbf3440 is not STP X8,XZR,[X0,#0x48]");
    }
    let q0 = engine88_le_u32(blob, BOSMINER_BF33A4_STRQ0_VA)
        .ok_or("bosminer shorter than STR Q0 [X0]")?;
    if q0 != BOSMINER_BF33A4_STRQ0_INSN {
        return Err("0xbf3438 is not STR Q0,[X0]");
    }
    let f4bl = engine88_le_u32(blob, BOSMINER_BF33A4_FACTORY4_BL_VA)
        .ok_or("bosminer shorter than factory4 BL FUN_00bf33a4")?;
    if f4bl != BOSMINER_BF33A4_FACTORY4_BL_INSN {
        return Err("0x904758 is not BL FUN_00bf33a4");
    }
    let f4st = engine88_le_u32(blob, BOSMINER_BF33A4_FACTORY4_STR_SP610_VA)
        .ok_or("bosminer shorter than factory4 STR [SP,#0x610]")?;
    if f4st != BOSMINER_BF33A4_FACTORY4_STR_SP610_INSN {
        return Err("0x904764 is not STR X0,[SP,#0x610]");
    }
    let c876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_COPY1AF_VA)
        .ok_or("bosminer shorter than 876 MOVZ #0x1af")?;
    let c4 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_COPY1AF_VA)
        .ok_or("bosminer shorter than factory4 MOVZ #0x1af")?;
    if c876 != BOSMINER_WORKER_NEW_COPY1AF_INSN || c4 != BOSMINER_WORKER_NEW_COPY1AF_INSN {
        return Err("both worker_new MOVZ W2,#0x1af");
    }
    let src876 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_SRC840_VA)
        .ok_or("bosminer shorter than ADD X1,SP,#0x840")?;
    if src876 != BOSMINER_WORKER_NEW_876_SRC840_INSN {
        return Err("0x903f30 is not ADD X1,SP,#0x840");
    }
    let src4 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_SRC860_VA)
        .ok_or("bosminer shorter than ADD X1,SP,#0x860")?;
    if src4 != BOSMINER_WORKER_NEW_FACTORY4_SRC860_INSN {
        return Err("0x904e58 is not ADD X1,SP,#0x860");
    }
    let z11 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_11E0_VA)
        .ok_or("bosminer shorter than STR XZR #0x11e0")?;
    if z11 != BOSMINER_WORKER_NEW_876_STR_11E0_INSN {
        return Err("0x903f48 is not STR XZR,[X22,#0x11e0]");
    }
    let p12 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STR_1200_VA)
        .ok_or("bosminer shorter than STR #0x1200")?;
    if p12 != BOSMINER_WORKER_NEW_876_STR_1200_INSN {
        return Err("0x903f54 is not STR X25,[X22,#0x1200]");
    }
    let sb = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_STRB_1208_VA)
        .ok_or("bosminer shorter than STRB [X22,X8]")?;
    if sb != BOSMINER_WORKER_NEW_876_STRB_1208_INSN {
        return Err("0x903f58 is not STRB W19,[X22,X8]");
    }
    Ok(())
}

/// `#0x1208` is a header/STRB offset, not a 0x1208-byte object-base memcpy.
pub fn refuse_1208_as_object_base_memcpy() -> Result<(), &'static str> {
    Err(
        "memcpy is MOVZ W2,#0x1af dest=obj+0x1209 src=SP+0x840/0x860; #0x1208 is STRB index and header at +0x11e0..+0x1200; 0 factory LDR [X23,#off]",
    )
}

/// Factory self cannot be named HashChain from field loads: 0 LDR [X23,#off].
pub fn refuse_factory_self_as_hashchain_ldr() -> Result<(), &'static str> {
    Err(
        "both factories 0 LDR/STR [X23,#off]; 0 BL to 0x876ca8/0x877d40; self is only MOV X23,X0 / Worker::new X0 / box+0x20",
    )
}

/// `FUN_011f26f8` zeros dest and stores tag `(arg<<1)` at `+0x20`; arg=1 ⇒ tag 2.
/// `0x1af` blob is 7-byte prefix + `0x1a8` memcpy to `blob+7`.
pub fn admit_bosminer_11f26f8_zeros_tag2_and_1af_is_7_plus_1a8(
    blob: &[u8],
) -> Result<(), &'static str> {
    if u32::from(BOSMINER_WORKER_NEW_1AF_PREFIX) + u32::from(BOSMINER_WORKER_NEW_876_COPY1A8)
        != u32::from(BOSMINER_WORKER_NEW_COPY1AF)
    {
        return Err("0x1af is 7+0x1a8");
    }
    if u32::from(BOSMINER_BF33A4_INIT_ARG) << 1 != u32::from(BOSMINER_BF33A4_INIT_TAG) {
        return Err("arg 1 LSL#1 is tag 2");
    }
    if BOSMINER_FACTORY4_610_LDR_HITS != 3 {
        return Err("factory4 SP+#0x610 has 3 LDRs");
    }
    let lsr = engine88_le_u32(blob, BOSMINER_F11F26F8_FN_VA)
        .ok_or("bosminer shorter than FUN_011f26f8")?;
    if lsr != BOSMINER_F11F26F8_LSR_INSN {
        return Err("0x11f26f8 is not LSR X9,X0,#61");
    }
    let lsl = engine88_le_u32(blob, BOSMINER_F11F26F8_LSL_VA)
        .ok_or("bosminer shorter than LSL X9,X0,#1")?;
    if lsl != BOSMINER_F11F26F8_LSL_INSN {
        return Err("0x11f2700 is not LSL X9,X0,#1");
    }
    let stp = engine88_le_u32(blob, BOSMINER_F11F26F8_STP0_VA)
        .ok_or("bosminer shorter than STP XZR,XZR")?;
    if stp != BOSMINER_F11F26F8_STP0_INSN {
        return Err("0x11f2704 is not STP XZR,XZR,[X8]");
    }
    let t20 = engine88_le_u32(blob, BOSMINER_F11F26F8_STR20_VA)
        .ok_or("bosminer shorter than STR [X8,#0x20]")?;
    if t20 != BOSMINER_F11F26F8_STR20_INSN {
        return Err("0x11f2710 is not STR X9,[X8,#0x20]");
    }
    let rt = engine88_le_u32(blob, BOSMINER_F11F26F8_RET_VA)
        .ok_or("bosminer shorter than FUN_011f26f8 RET")?;
    if rt != BOSMINER_F11F26F8_RET_INSN {
        return Err("0x11f2714 is not RET");
    }
    let add8 = engine88_le_u32(blob, BOSMINER_BF33A4_INIT_DEST_ADD_VA)
        .ok_or("bosminer shorter than ADD X8,SP,#0x28")?;
    if add8 != BOSMINER_BF33A4_INIT_DEST_ADD_INSN {
        return Err("0xbf33c8 is not ADD X8,SP,#0x28");
    }
    let arg = engine88_le_u32(blob, BOSMINER_BF33A4_INIT_ARG_VA)
        .ok_or("bosminer shorter than MOVZ #1")?;
    if arg != BOSMINER_BF33A4_INIT_ARG_INSN {
        return Err("0xbf33cc is not MOVZ W0,#1");
    }
    let q0 = engine88_le_u32(blob, BOSMINER_BF33A4_LDURQ0_VA)
        .ok_or("bosminer shorter than LDUR Q0 [SP,#0x28]")?;
    if q0 != BOSMINER_BF33A4_LDURQ0_INSN {
        return Err("0xbf33d4 is not LDUR Q0,[SP,#0x28]");
    }
    let q1 = engine88_le_u32(blob, BOSMINER_BF33A4_LDURQ1_VA)
        .ok_or("bosminer shorter than LDUR Q1 [SP,#0x38]")?;
    if q1 != BOSMINER_BF33A4_LDURQ1_INSN {
        return Err("0xbf33d8 is not LDUR Q1,[SP,#0x38]");
    }
    let b840 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_876_BLOB840_VA)
        .ok_or("bosminer shorter than ADD X8,SP,#0x840")?;
    if b840 != BOSMINER_WORKER_NEW_876_BLOB840_INSN {
        return Err("0x903e60 is not ADD X8,SP,#0x840");
    }
    let p7 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_BLOB_PLUS7_VA)
        .ok_or("bosminer shorter than ADD X0,X8,#7")?;
    if p7 != BOSMINER_WORKER_NEW_BLOB_PLUS7_INSN {
        return Err("0x903e64 is not ADD X0,X8,#7");
    }
    let b860 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_BLOB860_VA)
        .ok_or("bosminer shorter than ADD X8,SP,#0x860")?;
    if b860 != BOSMINER_WORKER_NEW_FACTORY4_BLOB860_INSN {
        return Err("0x904d7c is not ADD X8,SP,#0x860");
    }
    let dadd = engine88_le_u32(blob, BOSMINER_FACTORY4_610_DROP_ADD_VA)
        .ok_or("bosminer shorter than ADD X0,SP,#0x610")?;
    if dadd != BOSMINER_FACTORY4_610_DROP_ADD_INSN {
        return Err("0x9051c0 is not ADD X0,SP,#0x610");
    }
    let dbl = engine88_le_u32(blob, BOSMINER_FACTORY4_610_DROP_BL_VA)
        .ok_or("bosminer shorter than drop BL")?;
    if dbl != BOSMINER_FACTORY4_610_DROP_BL_INSN {
        return Err("0x9051c4 is not BL 0xb41d80");
    }
    Ok(())
}

/// Q0/Q1 are zero-fills from `FUN_011f26f8`, not named identity `.text`.
pub fn refuse_q0q1_as_identity_text() -> Result<(), &'static str> {
    Err(
        "FUN_011f26f8 STP XZR,XZR / STR XZR #0x10 / STRB 0; LDUR Q0 [SP,#0x28] and Q1 [SP,#0x38] are those zeros; tag 2 at helper+0x20 becomes box+0x48",
    )
}

/// `0x1af` is not an opaque ASIC frame; it is 7 + the existing `0x1a8` copy.
pub fn refuse_1af_as_asic_frame() -> Result<(), &'static str> {
    Err(
        "0x1af memcpy src is SP+#0x840/#0x860 after memcpy 0x1a8 to blob+7; not a BM1366 wire frame",
    )
}

/// `FUN_00b41d80` drops a 0x70/align-8 box via heap thunk0; Q2 is `LDP Q1,Q2,[SP]`.
pub fn admit_bosminer_b41d80_is_70_drop_and_q2_from_sp(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_B41D80_FN_VA != BOSMINER_FACTORY4_610_DROP_TGT {
        return Err("drop target must stay FUN_00b41d80");
    }
    if BOSMINER_B41D80_BL_HITS != 54 {
        return Err("FUN_00b41d80 has 54 BL callers");
    }
    if BOSMINER_876_BLOB840_STR_HITS != 0 {
        return Err("876 has 0 STR to SP+#0x840");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_B41D80_LDR_SLOT_VA)
        .ok_or("bosminer shorter than LDR [X0]")?;
    if ldr != BOSMINER_B41D80_LDR_SLOT_INSN {
        return Err("0xb41d88 is not LDR X19,[X0]");
    }
    let sz = engine88_le_u32(blob, BOSMINER_B41D80_SIZE_VA)
        .ok_or("bosminer shorter than MOVZ W1,#0x70")?;
    if sz != BOSMINER_B41D80_SIZE_INSN {
        return Err("0xb41ddc is not MOVZ W1,#0x70");
    }
    let al = engine88_le_u32(blob, BOSMINER_B41D80_ALIGN_VA)
        .ok_or("bosminer shorter than MOVZ W2,#8")?;
    if al != BOSMINER_B41D80_ALIGN_INSN {
        return Err("0xb41de4 is not MOVZ W2,#8");
    }
    let b = engine88_le_u32(blob, BOSMINER_B41D80_B_DEALLOC_VA)
        .ok_or("bosminer shorter than B thunk0")?;
    if b != BOSMINER_B41D80_B_DEALLOC_INSN {
        return Err("0xb41dec is not B 0x5f4a7c");
    }
    let ldp = engine88_le_u32(blob, BOSMINER_BF33A4_LDP_Q12_VA)
        .ok_or("bosminer shorter than LDP Q1,Q2,[SP]")?;
    if ldp != BOSMINER_BF33A4_LDP_Q12_INSN {
        return Err("0xbf340c is not LDP Q1,Q2,[SP]");
    }
    let q2 = engine88_le_u32(blob, BOSMINER_BF33A4_STURQ2_VA)
        .ok_or("bosminer shorter than STUR Q2 [X0,#0x38]")?;
    if q2 != BOSMINER_BF33A4_STURQ2_INSN {
        return Err("0xbf343c is not STUR Q2,[X0,#0x38]");
    }
    let pld = engine88_le_u32(blob, BOSMINER_FACTORY4_PREFIX_LDR_VA)
        .ok_or("bosminer shorter than LDR [SP,#0xec8]")?;
    if pld != BOSMINER_FACTORY4_PREFIX_LDR_INSN {
        return Err("0x904c98 is not LDR X9,[SP,#0xec8]");
    }
    let pst = engine88_le_u32(blob, BOSMINER_FACTORY4_PREFIX_STR_VA)
        .ok_or("bosminer shorter than STR [SP,#0x840]")?;
    if pst != BOSMINER_FACTORY4_PREFIX_STR_INSN {
        return Err("0x904ca8 is not STR X9,[SP,#0x840]");
    }
    let e8 = engine88_le_u32(blob, BOSMINER_876_EC8_STR_VA)
        .ok_or("bosminer shorter than STR [SP,#0xec8]")?;
    if e8 != BOSMINER_876_EC8_STR_INSN {
        return Err("0x903e24 is not STR X1,[SP,#0xec8]");
    }
    Ok(())
}

/// The 7-byte prefix is not a `55 AA 21 36` work header.
pub fn refuse_7byte_prefix_as_55aa_header() -> Result<(), &'static str> {
    Err(
        "876 has 0 STR to SP+#0x840; factory4 STR [SP+#0xec8] as 8 B at blob (low 7 survive); memcpy 0x1a8 starts at blob+7; not 55 AA 21 36",
    )
}

/// Q2 at box+0x38 is `LDP Q1,Q2,[SP]` then `STUR`, not identity `.text`.
pub fn refuse_q2_as_identity_text() -> Result<(), &'static str> {
    Err(
        "0xbf340c LDP Q1,Q2,[SP]; 0xbf343c STUR Q2,[box,#0x38]; FUN_00b41d80 is 0x70/8 Box drop via thunk0 0x5f4a7c",
    )
}

/// factory4 7-byte prefix is `FUN_00887c34` 0x98 box; Q2 is helper dest+0x10 zeros.
pub fn admit_bosminer_887c34_is_98_box_and_q2_is_zero_shuffle(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_887C34_SIZE != 0x98 {
        return Err("FUN_00887c34 alloc size is 0x98");
    }
    if BOSMINER_887C34_BL_HITS != 5 {
        return Err("FUN_00887c34 has 5 BL callers");
    }
    if BOSMINER_BBD3DC_BL_HITS != 11 {
        return Err("FUN_00bbd3dc has 11 BL callers");
    }
    let fr =
        engine88_le_u32(blob, BOSMINER_887C34_FN_VA).ok_or("bosminer shorter than FUN_00887c34")?;
    if fr != BOSMINER_887C34_FRAME_INSN {
        return Err("0x887c34 is not SUB SP,#0xb0");
    }
    let sz = engine88_le_u32(blob, BOSMINER_887C34_SIZE_VA)
        .ok_or("bosminer shorter than MOVZ W0,#0x98")?;
    if sz != BOSMINER_887C34_SIZE_INSN {
        return Err("0x887c70 is not MOVZ W0,#0x98");
    }
    let al = engine88_le_u32(blob, BOSMINER_887C34_ALIGN_VA)
        .ok_or("bosminer shorter than MOVZ W1,#8")?;
    if al != BOSMINER_887C34_ALIGN_INSN {
        return Err("0x887c44 is not MOVZ W1,#8");
    }
    let ab = engine88_le_u32(blob, BOSMINER_887C34_ALLOC_BL_VA)
        .ok_or("bosminer shorter than BL thunk1")?;
    if ab != BOSMINER_887C34_ALLOC_BL_INSN {
        return Err("0x887c8c is not BL 0x5f4a78");
    }
    let mv = engine88_le_u32(blob, BOSMINER_887C34_MOV_X1_X0_VA)
        .ok_or("bosminer shorter than MOV X1,X0")?;
    if mv != BOSMINER_887C34_MOV_X1_X0_INSN {
        return Err("0x887cdc is not MOV X1,X0");
    }
    let rt =
        engine88_le_u32(blob, BOSMINER_887C34_RET_VA).ok_or("bosminer shorter than 887c34 RET")?;
    if rt != BOSMINER_887C34_RET_INSN {
        return Err("0x887ce4 is not RET");
    }
    let z4 = engine88_le_u32(blob, BOSMINER_FACTORY4_XZR_VA)
        .ok_or("bosminer shorter than factory4 MOV X0,XZR")?;
    if z4 != BOSMINER_FACTORY4_XZR_INSN {
        return Err("0x9046d0 is not MOV X0,XZR");
    }
    let b4 = engine88_le_u32(blob, BOSMINER_FACTORY4_887C34_BL_VA)
        .ok_or("bosminer shorter than factory4 BL 887c34")?;
    if b4 != BOSMINER_FACTORY4_887C34_BL_INSN {
        return Err("0x9046d4 is not BL 0x887c34");
    }
    let s6 = engine88_le_u32(blob, BOSMINER_FACTORY4_STR600_VA)
        .ok_or("bosminer shorter than STR [SP,#0x600]")?;
    if s6 != BOSMINER_FACTORY4_STR600_INSN {
        return Err("0x9046e4 is not STR X0,[SP,#0x600]");
    }
    let l6 = engine88_le_u32(blob, BOSMINER_FACTORY4_LDR600_VA)
        .ok_or("bosminer shorter than LDR [SP,#0x600]")?;
    if l6 != BOSMINER_FACTORY4_LDR600_INSN {
        return Err("0x904aa8 is not LDR X8,[SP,#0x600]");
    }
    let se = engine88_le_u32(blob, BOSMINER_FACTORY4_STR_EC8_FROM600_VA)
        .ok_or("bosminer shorter than STR [SP,#0xec8] from 0x600")?;
    if se != BOSMINER_FACTORY4_STR_EC8_FROM600_INSN {
        return Err("0x904ab0 is not STR X8,[SP,#0xec8]");
    }
    let z8 =
        engine88_le_u32(blob, BOSMINER_876_XZR_VA).ok_or("bosminer shorter than 876 MOV X0,XZR")?;
    if z8 != BOSMINER_876_XZR_INSN {
        return Err("0x9036d0 is not MOV X0,XZR");
    }
    let b8 = engine88_le_u32(blob, BOSMINER_876_887C34_BL_VA)
        .ok_or("bosminer shorter than 876 BL 887c34")?;
    if b8 != BOSMINER_876_887C34_BL_INSN {
        return Err("0x9036d4 is not BL 0x887c34");
    }
    let s5 = engine88_le_u32(blob, BOSMINER_876_STR5E0_VA)
        .ok_or("bosminer shorter than STR [SP,#0x5e0]")?;
    if s5 != BOSMINER_876_STR5E0_INSN {
        return Err("0x9036e8 is not STR X0,[SP,#0x5e0]");
    }
    let cl =
        engine88_le_u32(blob, BOSMINER_BBD3DC_FN_VA).ok_or("bosminer shorter than FUN_00bbd3dc")?;
    if cl != BOSMINER_BBD3DC_LDR_INSN {
        return Err("0xbbd3dc is not LDR X0,[X0]");
    }
    let lx = engine88_le_u32(blob, BOSMINER_BBD3DC_LDAXR_VA)
        .ok_or("bosminer shorter than LDAXR [X0]")?;
    if lx != BOSMINER_BBD3DC_LDAXR_INSN {
        return Err("0xbbd3e0 is not LDAXR X8,[X0]");
    }
    let a48 = engine88_le_u32(blob, BOSMINER_BBD3DC_ADD48_VA)
        .ok_or("bosminer shorter than ADD X8,X0,#0x48")?;
    if a48 != BOSMINER_BBD3DC_ADD48_INSN {
        return Err("0xbbd3f4 is not ADD X8,X0,#0x48");
    }
    let l1 = engine88_le_u32(blob, BOSMINER_BBD3DC_LDAXR1_VA)
        .ok_or("bosminer shorter than LDAXR X1,[X8]")?;
    if l1 != BOSMINER_BBD3DC_LDAXR1_INSN {
        return Err("0xbbd3f8 is not LDAXR X1,[X8]");
    }
    let cr =
        engine88_le_u32(blob, BOSMINER_BBD3DC_RET_VA).ok_or("bosminer shorter than bbd3dc RET")?;
    if cr != BOSMINER_BBD3DC_RET_INSN {
        return Err("0xbbd408 is not RET");
    }
    let c8 = engine88_le_u32(blob, BOSMINER_876_BBD3DC_BL_VA)
        .ok_or("bosminer shorter than 876 BL bbd3dc")?;
    if c8 != BOSMINER_876_BBD3DC_BL_INSN {
        return Err("0x903e14 is not BL 0xbbd3dc");
    }
    let e0 = engine88_le_u32(blob, BOSMINER_876_STR_EC0_VA)
        .ok_or("bosminer shorter than STR [SP,#0xec0]")?;
    if e0 != BOSMINER_876_STR_EC0_INSN {
        return Err("0x903e1c is not STR X0,[SP,#0xec0]");
    }
    let cf = engine88_le_u32(blob, BOSMINER_FACTORY4_BBD3DC_BL_VA)
        .ok_or("bosminer shorter than factory4 BL bbd3dc")?;
    if cf != BOSMINER_FACTORY4_BBD3DC_BL_INSN {
        return Err("0x904d30 is not BL 0xbbd3dc");
    }
    let ee0 = engine88_le_u32(blob, BOSMINER_FACTORY4_STR_EE0_VA)
        .ok_or("bosminer shorter than STR [SP,#0xee0]")?;
    if ee0 != BOSMINER_FACTORY4_STR_EE0_INSN {
        return Err("0x904d38 is not STR X0,[SP,#0xee0]");
    }
    let ee8 = engine88_le_u32(blob, BOSMINER_FACTORY4_STR_EE8_VA)
        .ok_or("bosminer shorter than STR [SP,#0xee8]")?;
    if ee8 != BOSMINER_FACTORY4_STR_EE8_INSN {
        return Err("0x904d40 is not STR X1,[SP,#0xee8]");
    }
    let q0s = engine88_le_u32(blob, BOSMINER_BF33A4_STRQ0_SP_VA)
        .ok_or("bosminer shorter than STR Q0,[SP]")?;
    if q0s != BOSMINER_BF33A4_STRQ0_SP_INSN {
        return Err("0xbf33ec is not STR Q0,[SP]");
    }
    let q1s = engine88_le_u32(blob, BOSMINER_BF33A4_STRQ1_SP10_VA)
        .ok_or("bosminer shorter than STR Q1,[SP,#0x10]")?;
    if q1s != BOSMINER_BF33A4_STRQ1_SP10_INSN {
        return Err("0xbf33f4 is not STR Q1,[SP,#0x10]");
    }
    let q1b = engine88_le_u32(blob, BOSMINER_BF33A4_STURQ1_28_VA)
        .ok_or("bosminer shorter than STUR Q1,[X0,#0x28]")?;
    if q1b != BOSMINER_BF33A4_STURQ1_28_INSN {
        return Err("0xbf3434 is not STUR Q1,[X0,#0x28]");
    }
    Ok(())
}

/// factory4 7-byte prefix is the 0x98 box, not the `FUN_00bbd3dc` pair.
pub fn refuse_factory4_prefix_as_bbd3dc_pair() -> Result<(), &'static str> {
    Err(
        "factory4 BL 0xbbd3dc stores (X0,X1) at SP+#0xee0/#0xee8; prefix is FUN_00887c34 box via SP+#0x600",
    )
}

/// 876 `SP+#0xec8` is `FUN_00bbd3dc` X1 (old [ptr+0x48]), not the 0x840 blob prefix.
pub fn refuse_876_ec8_as_840_prefix() -> Result<(), &'static str> {
    Err(
        "876 STR X1,[SP,#0xec8] is FUN_00bbd3dc X1 after BL 0x903e14; 0 STR to SP+#0x840; 887c34 box goes to SP+#0x5e0",
    )
}

/// 0x98 box is ArcInner: +0 strong (zero then LDAXR+1); arg at +0x58; three `#8`.
pub fn admit_bosminer_887c34_arcinner_fields(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_887C34_ARG_OFF != 0x58 {
        return Err("incoming X0 is stored at +0x58");
    }
    if BOSMINER_887C34_USIZE8_OFFS != [0x20, 0x40, 0x68] {
        return Err("three usize 8 slots are +0x20/+0x40/+0x68");
    }
    let z8 = engine88_le_u32(blob, BOSMINER_887C34_MOVZ8_VA)
        .ok_or("bosminer shorter than MOVZ W8,#8")?;
    if z8 != BOSMINER_887C34_MOVZ8_INSN {
        return Err("0x887c4c is not MOVZ W8,#8");
    }
    let q0 = engine88_le_u32(blob, BOSMINER_887C34_STRQ0_VA)
        .ok_or("bosminer shorter than STR Q0,[SP]")?;
    if q0 != BOSMINER_887C34_STRQ0_INSN {
        return Err("0x887c5c is not STR Q0,[SP] (strong/weak zeros)");
    }
    let s20 = engine88_le_u32(blob, BOSMINER_887C34_STP20_VA)
        .ok_or("bosminer shorter than STP [SP,#0x18]")?;
    if s20 != BOSMINER_887C34_STP20_INSN {
        return Err("0x887c64 is not STP XZR,X8,[SP,#0x18]");
    }
    let s40 = engine88_le_u32(blob, BOSMINER_887C34_STP40_VA)
        .ok_or("bosminer shorter than STP [SP,#0x38]")?;
    if s40 != BOSMINER_887C34_STP40_INSN {
        return Err("0x887c68 is not STP XZR,X8,[SP,#0x38]");
    }
    let s58 = engine88_le_u32(blob, BOSMINER_887C34_STP58_VA)
        .ok_or("bosminer shorter than STP [SP,#0x58]")?;
    if s58 != BOSMINER_887C34_STP58_INSN {
        return Err("0x887c6c is not STP X0,XZR,[SP,#0x58]");
    }
    let s68 = engine88_le_u32(blob, BOSMINER_887C34_STR68_VA)
        .ok_or("bosminer shorter than STR [SP,#0x68]")?;
    if s68 != BOSMINER_887C34_STR68_INSN {
        return Err("0x887c74 is not STR X8,[SP,#0x68]");
    }
    let lx = engine88_le_u32(blob, BOSMINER_887C34_LDAXR_VA)
        .ok_or("bosminer shorter than LDAXR [box]")?;
    if lx != BOSMINER_887C34_LDAXR_INSN {
        return Err("0x887cc4 is not LDAXR X8,[X0] (strong +1)");
    }
    let s90 = engine88_le_u32(blob, BOSMINER_887C34_STR90_VA)
        .ok_or("bosminer shorter than STR [box,#0x90]")?;
    if s90 != BOSMINER_887C34_STR90_INSN {
        return Err("0x887cac is not STR X8,[X0,#0x90]");
    }
    Ok(())
}

/// The 7-byte prefix is not the +0x58 argument field.
pub fn refuse_98_arg58_as_7byte_prefix() -> Result<(), &'static str> {
    Err(
        "0x887c6c STP X0,XZR,[SP,#0x58] is a field inside the 0x98 Arc; factory4 0x1af blob is SP+#0x860, not +0x58",
    )
}

/// 0x1af 7-byte prefix is unwritten stack; three `8`s are `Layout { size:0, align:8 }`.
pub fn admit_bosminer_1af_prefix_unwritten_and_8_is_layout_align(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FACTORY4_BLOB_SLOT - BOSMINER_FACTORY4_ARC_SLOT != BOSMINER_FACTORY4_ARC_BLOB_GAP {
        return Err("factory4 Arc #0x840 is 0x20 before blob #0x860");
    }
    if BOSMINER_FACTORY4_BLOB860_STR_HITS != 0 {
        return Err("factory4 worker_new has 0 STR to SP+#0x860");
    }
    if BOSMINER_876_BLOB840_STR_HITS != 0 {
        return Err("876 worker_new has 0 STR to SP+#0x840");
    }
    if BOSMINER_887C34_LAYOUT_ALIGN != 8 {
        return Err("Layout.align immediate is 8");
    }
    if BOSMINER_887C34_LAYOUT_SIZE_OFFS != [0x18, 0x38, 0x60] {
        return Err("Layout size halves are +0x18/+0x38/+0x60");
    }
    if BOSMINER_887C34_USIZE8_OFFS != [0x20, 0x40, 0x68] {
        return Err("Layout align halves are +0x20/+0x40/+0x68");
    }
    let plus7 = engine88_le_u32(blob, BOSMINER_FACTORY4_BLOB_PLUS7_VA)
        .ok_or("bosminer shorter than factory4 ADD #7")?;
    if plus7 != BOSMINER_FACTORY4_BLOB_PLUS7_INSN {
        return Err("0x904d80 is not ADD X0,X8,#7");
    }
    let src = engine88_le_u32(blob, BOSMINER_FACTORY4_1AF_SRC_VA)
        .ok_or("bosminer shorter than factory4 ADD X1,SP,#0x860")?;
    if src != BOSMINER_FACTORY4_1AF_SRC_INSN {
        return Err("0x904e58 is not ADD X1,SP,#0x860");
    }
    let b860 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_BLOB860_VA)
        .ok_or("bosminer shorter than ADD X8,SP,#0x860")?;
    if b860 != BOSMINER_WORKER_NEW_FACTORY4_BLOB860_INSN {
        return Err("0x904d7c is not ADD X8,SP,#0x860");
    }
    let arc = engine88_le_u32(blob, BOSMINER_FACTORY4_PREFIX_STR_VA)
        .ok_or("bosminer shorter than STR [SP,#0x840]")?;
    if arc != BOSMINER_FACTORY4_PREFIX_STR_INSN {
        return Err("0x904ca8 is not STR X9,[SP,#0x840]");
    }
    let z8 = engine88_le_u32(blob, BOSMINER_887C34_MOVZ8_VA)
        .ok_or("bosminer shorter than MOVZ W8,#8")?;
    if z8 != BOSMINER_887C34_MOVZ8_INSN {
        return Err("0x887c4c is not MOVZ W8,#8");
    }
    let s18 = engine88_le_u32(blob, BOSMINER_887C34_STP20_VA)
        .ok_or("bosminer shorter than STP Layout0")?;
    if s18 != BOSMINER_887C34_STP20_INSN {
        return Err("0x887c64 is not STP XZR,X8,[SP,#0x18]");
    }
    Ok(())
}

/// factory4 7-byte prefix is not the FUN_00887c34 Arc pointer ( overclaim).
pub fn refuse_factory4_prefix_as_887c34_arc() -> Result<(), &'static str> {
    Err(
        "factory4 0x1af src is SP+#0x860; Arc STR is SP+#0x840 (gap 0x20); 0 STR to #0x860; not Vec/niche",
    )
}

/// The three usize 8s are Layout.align, not Vec capacity.
pub fn refuse_8_as_vec_capacity() -> Result<(), &'static str> {
    Err("STP XZR,X8 at +0x18/+0x38 and +0x60=0/+0x68=8 are Layout {size:0, align:8}, not Vec cap")
}

/// 0x1af is 7-byte padding after the u8 at +0x1208 plus the 0x1a8 payload at +0x1210.
pub fn admit_bosminer_1af_is_pad7_then_aligned_1a8(blob: &[u8]) -> Result<(), &'static str> {
    if u32::from(BOSMINER_WORKER_NEW_COPY1208) + 1 + u32::from(BOSMINER_WORKER_NEW_1AF_PREFIX)
        != u32::from(BOSMINER_WORKER_NEW_1AF_ALIGNED)
    {
        return Err("0x1208 + 1 + 7 must be 0x1210");
    }
    if u32::from(BOSMINER_WORKER_NEW_1AF_ALIGNED) & 7 != 0 {
        return Err("0x1210 must be 8-aligned");
    }
    if u32::from(BOSMINER_WORKER_NEW_1AF_ALIGNED) + u32::from(BOSMINER_WORKER_NEW_876_COPY1A8)
        != u32::from(BOSMINER_WORKER_NEW_1AF_END)
    {
        return Err("0x1210 + 0x1a8 must be 0x13b8");
    }
    if u32::from(BOSMINER_WORKER_NEW_FACTORY4_1209) + u32::from(BOSMINER_WORKER_NEW_COPY1AF)
        != u32::from(BOSMINER_WORKER_NEW_1AF_END)
    {
        return Err("0x1209 + 0x1af must be 0x13b8");
    }
    if u32::from(BOSMINER_WORKER_NEW_1AF_END) & 7 != 0 {
        return Err("0x13b8 must be 8-aligned");
    }
    let z9 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_VA)
        .ok_or("bosminer shorter than MOVZ #0x1209")?;
    if z9 != BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN {
        return Err("0x904e6c is not MOVZ W9,#0x1209");
    }
    let z8 = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1208_VA)
        .ok_or("bosminer shorter than MOVZ #0x1208")?;
    if z8 != BOSMINER_WORKER_NEW_COPY1208_INSN {
        return Err("0x904e74 is not MOVZ W8,#0x1208");
    }
    let ad = engine88_le_u32(blob, BOSMINER_FACTORY4_DEST1209_ADD_VA)
        .ok_or("bosminer shorter than ADD X0,X21,X9")?;
    if ad != BOSMINER_FACTORY4_DEST1209_ADD_INSN {
        return Err("0x904e78 is not ADD X0,X21,X9");
    }
    let sb = engine88_le_u32(blob, BOSMINER_FACTORY4_STRB_1208_VA)
        .ok_or("bosminer shorter than STRB +0x1208")?;
    if sb != BOSMINER_FACTORY4_STRB_1208_INSN {
        return Err("0x904e84 is not STRB W20,[X21,X8]");
    }
    let e4 = engine88_le_u32(blob, BOSMINER_FACTORY4_STR_13B8_VA)
        .ok_or("bosminer shorter than STR #0x13b8")?;
    if e4 != BOSMINER_FACTORY4_STR_13B8_INSN {
        return Err("0x904ea4 is not STR X9,[X21,#0x13b8]");
    }
    let e8 = engine88_le_u32(blob, BOSMINER_876_STR_13B8_VA)
        .ok_or("bosminer shorter than 876 STR #0x13b8")?;
    if e8 != BOSMINER_876_STR_13B8_INSN {
        return Err("0x903f78 is not STR X9,[X22,#0x13b8]");
    }
    let sz = engine88_le_u32(blob, BOSMINER_WORKER_NEW_FACTORY4_COPY1AF_VA)
        .ok_or("bosminer shorter than MOVZ #0x1af")?;
    if sz != BOSMINER_WORKER_NEW_COPY1AF_INSN {
        return Err("0x904e5c is not MOVZ W2,#0x1af");
    }
    Ok(())
}

/// 0x1af is not a 7-byte wire header or Vec length.
pub fn refuse_1af_as_wire_header_or_vec_len() -> Result<(), &'static str> {
    Err(
        "0x1af is 7 pad after STRB +0x1208 plus 0x1a8 payload at +0x1210; next field STR #0x13b8; not 55 AA / not Vec len",
    )
}

/// Worker+0x1208 u8 is `*(arg1+0xC8)` via bf33a4 box+0x18; 0x1a8 src is the Worker::new local.
pub fn admit_bosminer_1208_is_arg1_c8_and_1a8_is_local(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_WORKER_NEW_ARG1_C8 != 0xC8 {
        return Err("arg1 byte offset is 0xC8");
    }
    if BOSMINER_WORKER_NEW_ARG1_158 != 0x158 {
        return Err("arg1 sibling pointer offset is 0x158");
    }
    if BOSMINER_BF33A4_STRB18_INSN == 0 {
        return Err("box+0x18 STRB must stay pinned");
    }
    let c8 = engine88_le_u32(blob, BOSMINER_876_LDRB_ARG1_C8_VA)
        .ok_or("bosminer shorter than LDRB [X25,#0xC8]")?;
    if c8 != BOSMINER_876_LDRB_ARG1_C8_INSN {
        return Err("0x90373c is not LDRB W26,[X25,#0xC8]");
    }
    let mv = engine88_le_u32(blob, BOSMINER_876_MOV_W4_W26_VA)
        .ok_or("bosminer shorter than MOV W4,W26")?;
    if mv != BOSMINER_876_MOV_W4_W26_INSN {
        return Err("0x903758 is not MOV W4,W26");
    }
    let f4c8 = engine88_le_u32(blob, BOSMINER_FACTORY4_LDRB_ARG1_C8_VA)
        .ok_or("bosminer shorter than LDRB [X24,#0xC8]")?;
    if f4c8 != BOSMINER_FACTORY4_LDRB_ARG1_C8_INSN {
        return Err("0x904740 is not LDRB W4,[X24,#0xC8]");
    }
    let st = engine88_le_u32(blob, BOSMINER_876_BOX_STR_5F0_VA)
        .ok_or("bosminer shorter than STR [SP,#0x5f0]")?;
    if st != BOSMINER_876_BOX_STR_5F0_INSN {
        return Err("0x903768 is not STR X0,[SP,#0x5f0]");
    }
    let ld = engine88_le_u32(blob, BOSMINER_876_BOX_LDR_5F0_VA)
        .ok_or("bosminer shorter than LDR [SP,#0x5f0]")?;
    if ld != BOSMINER_876_BOX_LDR_5F0_INSN {
        return Err("0x903de0 is not LDR X8,[SP,#0x5f0]");
    }
    let b18 = engine88_le_u32(blob, BOSMINER_876_LDRB_BOX18_VA)
        .ok_or("bosminer shorter than LDRB [X8,#0x18]")?;
    if b18 != BOSMINER_876_LDRB_BOX18_INSN {
        return Err("0x903e04 is not LDRB W19,[X8,#0x18]");
    }
    let f418 = engine88_le_u32(blob, BOSMINER_FACTORY4_LDRB_BOX18_VA)
        .ok_or("bosminer shorter than factory4 LDRB #0x18")?;
    if f418 != BOSMINER_FACTORY4_LDRB_BOX18_INSN {
        return Err("0x904d28 is not LDRB W22,[X8,#0x18]");
    }
    let mw = engine88_le_u32(blob, BOSMINER_FACTORY4_MOV_W20_W22_VA)
        .ok_or("bosminer shorter than MOV W20,W22")?;
    if mw != BOSMINER_FACTORY4_MOV_W20_W22_INSN {
        return Err("0x904de4 is not MOV W20,W22");
    }
    let s876 = engine88_le_u32(blob, BOSMINER_876_1A8_SRC_VA)
        .ok_or("bosminer shorter than ADD X1,SP,#0x350")?;
    if s876 != BOSMINER_876_1A8_SRC_INSN {
        return Err("0x903e50 is not ADD X1,SP,#0x350");
    }
    let s4 = engine88_le_u32(blob, BOSMINER_FACTORY4_1A8_SRC_VA)
        .ok_or("bosminer shorter than ADD X1,SP,#0x370")?;
    if s4 != BOSMINER_FACTORY4_1A8_SRC_INSN {
        return Err("0x904d68 is not ADD X1,SP,#0x370");
    }
    Ok(())
}

/// +0x1208 is not midstate-log, work-type, or a 55 AA opcode.
pub fn refuse_1208_u8_as_midstate_or_55aa() -> Result<(), &'static str> {
    Err(
        "Worker+0x1208 is *(arg1+0xC8) via bf33a4 box+0x18; arg1+0x158 is the HashChain inline sibling; not midstate log / not 55 AA",
    )
}

/// HashChain+0xC8 is a u8 state tag (match 1/2/3; CMP #3 dominates); 0x1a8 is Registry wrap.
pub fn admit_bosminer_c8_is_state_tag_and_1a8_is_registry(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHCHAIN_C8_CMP3_HITS != 77 {
        return Err("LDRB #0xC8 then CMP #3 is 77 first-LOAD hits");
    }
    if BOSMINER_HASHCHAIN_C8_CMP1_HITS != 11 {
        return Err("LDRB #0xC8 then CMP #1 is 11 first-LOAD hits");
    }
    if BOSMINER_REGISTRY_WRAP_FN_VA != 0x00BF_7798 {
        return Err("Registry wrap must stay FUN_00bf7798");
    }
    let ld = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_MATCH_LDRB_VA)
        .ok_or("bosminer shorter than HashChain LDRB #0xC8")?;
    if ld != BOSMINER_HASHCHAIN_C8_MATCH_LDRB_INSN {
        return Err("0x8d6858 is not LDRB W8,[X0,#0xC8]");
    }
    let c1 = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_CMP1_VA)
        .ok_or("bosminer shorter than CMP #1")?;
    if c1 != BOSMINER_HASHCHAIN_C8_CMP1_INSN {
        return Err("0x8d6864 is not CMP W8,#1");
    }
    let c3 = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_CMP3_VA)
        .ok_or("bosminer shorter than CMP #3")?;
    if c3 != BOSMINER_HASHCHAIN_C8_CMP3_INSN {
        return Err("0x8d689c is not CMP W8,#3");
    }
    let c2 = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_CMP2_VA)
        .ok_or("bosminer shorter than CMP #2")?;
    if c2 != BOSMINER_HASHCHAIN_C8_CMP2_INSN {
        return Err("0x8d68b0 is not CMP W8,#2");
    }
    let s1 = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_SET1_VA)
        .ok_or("bosminer shorter than MOVZ #1")?;
    if s1 != BOSMINER_HASHCHAIN_C8_SET1_INSN {
        return Err("0x8d69bc is not MOVZ W8,#1");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_STR1_VA)
        .ok_or("bosminer shorter than STRB #0xC8")?;
    if st != BOSMINER_HASHCHAIN_C8_STR_INSN {
        return Err("0x8d69c0 is not STRB W8,[X19,#0xC8]");
    }
    let s3 = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_SET3_VA)
        .ok_or("bosminer shorter than MOVZ #3")?;
    if s3 != BOSMINER_HASHCHAIN_C8_SET3_INSN {
        return Err("0x8d69dc is not MOVZ W8,#3");
    }
    let s2 = engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_SET2_VA)
        .ok_or("bosminer shorter than MOVZ #2")?;
    if s2 != BOSMINER_HASHCHAIN_C8_SET2_INSN {
        return Err("0x8d6a84 is not MOVZ W8,#2");
    }
    let d876 = engine88_le_u32(blob, BOSMINER_876_REGISTRY_WRAP_DEST_VA)
        .ok_or("bosminer shorter than ADD X19,SP,#0x350")?;
    if d876 != BOSMINER_876_REGISTRY_WRAP_DEST_INSN {
        return Err("0x903678 is not ADD X19,SP,#0x350");
    }
    let bl = engine88_le_u32(blob, BOSMINER_876_REGISTRY_WRAP_BL_VA)
        .ok_or("bosminer shorter than BL Registry wrap")?;
    if bl != BOSMINER_876_REGISTRY_WRAP_BL_INSN {
        return Err("0x90367c is not BL FUN_00bf7798");
    }
    let d4 = engine88_le_u32(blob, BOSMINER_FACTORY4_REGISTRY_WRAP_DEST_VA)
        .ok_or("bosminer shorter than factory4 ADD X19,SP,#0x370")?;
    if d4 != BOSMINER_FACTORY4_REGISTRY_WRAP_DEST_INSN {
        return Err("0x904674 is not ADD X19,SP,#0x370");
    }
    let src =
        engine88_le_u32(blob, BOSMINER_876_1A8_SRC_VA).ok_or("bosminer shorter than 0x1a8 src")?;
    if src != BOSMINER_876_1A8_SRC_INSN {
        return Err("0x1a8 memcpy src is the Registry wrap dest SP+#0x350");
    }
    Ok(())
}

/// HashChain+0xC8 is not a bool (tags 2/3/4/5 stored).
pub fn refuse_c8_as_bool() -> Result<(), &'static str> {
    Err(
        "HashChain+0xC8 is a u8 state tag: FUN_008d6858 match CMP #1/#2/#3; setters MOVZ #1/#2/#3; 77 CMP #3 tests; not a bool",
    )
}

/// rustc async Future discriminant names for Worker/arg1 `+0xC8`.
pub fn bosminer_c8_async_tag_name(tag: u8) -> Option<&'static str> {
    match tag {
        BOSMINER_C8_TAG_UNRESUMED => Some("Unresumed"),
        BOSMINER_C8_TAG_COMPLETED => Some("Completed"),
        BOSMINER_C8_TAG_PANICKED => Some("Panicked"),
        BOSMINER_C8_TAG_SUSPENDED => Some("Suspended"),
        _ => None,
    }
}

/// +0xC8 tags 1/2/3 are rustc async poll states of `command.rs:700`.
pub fn admit_bosminer_c8_tags_are_command_rs_async_poll(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HAL_COMMAND_RS.len() != BOSMINER_HAL_COMMAND_RS_LEN {
        return Err("command.rs path length drifted");
    }
    if BOSMINER_C8_ASYNC_FN_LINE != 700 || BOSMINER_C8_ASYNC_FN_COL != 51 {
        return Err("command.rs:700:51 loc drifted");
    }
    if BOSMINER_C8_NESTED_ASYNC_LINE != 719 || BOSMINER_C8_NESTED_ASYNC_COL != 12 {
        return Err("command.rs:719:12 loc drifted");
    }
    if BOSMINER_ASYNC_DONE_MSG.len() != BOSMINER_ASYNC_DONE_MSG_LEN {
        return Err("completed-resume panic string length drifted");
    }
    if BOSMINER_ASYNC_PANIC_MSG.len() != BOSMINER_ASYNC_PANIC_MSG_LEN {
        return Err("panicked-resume panic string length drifted");
    }
    if BOSMINER_C8_TAG_COMPLETED != 1
        || BOSMINER_C8_TAG_PANICKED != 2
        || BOSMINER_C8_TAG_SUSPENDED != 3
    {
        return Err("async tag values drifted");
    }
    let cbnz = engine88_le_u32(blob, BOSMINER_C8_TAG1_CBNZ_VA)
        .ok_or("bosminer shorter than tag==1 CBNZ")?;
    if cbnz != BOSMINER_C8_TAG1_CBNZ_INSN {
        return Err("0x8d686c is not CBNZ W8,0x8d69f8");
    }
    let bne = engine88_le_u32(blob, BOSMINER_C8_TAG_NE3_B_VA)
        .ok_or("bosminer shorter than tag!=3 B.NE")?;
    if bne != BOSMINER_C8_TAG_NE3_B_INSN {
        return Err("0x8d68a0 is not B.NE 0x8d6a04");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_C8_ASYNC_DONE_ADRP_VA)
        .ok_or("bosminer shorter than completed ADRP")?;
    if adrp != BOSMINER_C8_ASYNC_DONE_ADRP_INSN {
        return Err("0x8d69f8 is not ADRP loc page 0x19c7000");
    }
    let add = engine88_le_u32(blob, BOSMINER_C8_ASYNC_DONE_ADD_VA)
        .ok_or("bosminer shorter than completed ADD #0x190")?;
    if add != BOSMINER_C8_ASYNC_DONE_ADD_INSN {
        return Err("0x8d69fc is not ADD X0,#0x190 (loc 0x19c7190)");
    }
    let bl_done = engine88_le_u32(blob, BOSMINER_C8_ASYNC_DONE_BL_VA)
        .ok_or("bosminer shorter than BL 0x453c40")?;
    if bl_done != BOSMINER_C8_ASYNC_DONE_BL_INSN {
        return Err("0x8d6a00 is not BL FUN_00453c40");
    }
    let bl_panic = engine88_le_u32(blob, BOSMINER_C8_ASYNC_PANIC_BL_VA)
        .ok_or("bosminer shorter than BL 0x453c74")?;
    if bl_panic != BOSMINER_C8_ASYNC_PANIC_BL_INSN {
        return Err("0x8d6a0c is not BL FUN_00453c74");
    }
    let nest = engine88_le_u32(blob, BOSMINER_C8_NESTED_ADD_VA)
        .ok_or("bosminer shorter than nested ADD #0x160")?;
    if nest != BOSMINER_C8_NESTED_ADD_INSN {
        return Err("0x8d6a1c is not ADD X0,#0x160 (loc 0x19c7160)");
    }
    let done_add = engine88_le_u32(blob, BOSMINER_ASYNC_DONE_HELPER_ADD_VA)
        .ok_or("bosminer shorter than helper ADD #0x470")?;
    if done_add != BOSMINER_ASYNC_DONE_HELPER_ADD_INSN {
        return Err("0x453c50 is not ADD X8,#0x470 (done-msg table)");
    }
    let panic_add = engine88_le_u32(blob, BOSMINER_ASYNC_PANIC_HELPER_ADD_VA)
        .ok_or("bosminer shorter than helper ADD #0x480")?;
    if panic_add != BOSMINER_ASYNC_PANIC_HELPER_ADD_INSN {
        return Err("0x453c84 is not ADD X8,#0x480 (panic-msg table)");
    }
    let ret0 = engine88_le_u32(blob, BOSMINER_C8_COMPLETE_RET_VA)
        .ok_or("bosminer shorter than MOV W0,WZR")?;
    if ret0 != BOSMINER_C8_COMPLETE_RET_INSN {
        return Err("0x8d69b8 is not MOV W0,WZR before SET1 Completed");
    }
    let ret1 = engine88_le_u32(blob, BOSMINER_C8_PENDING_RET_VA)
        .ok_or("bosminer shorter than MOVZ W0,#1")?;
    if ret1 != BOSMINER_C8_PENDING_RET_INSN {
        return Err("0x8d69e0 is not MOVZ W0,#1 before SET3 Suspended");
    }
    let set1 =
        engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_SET1_VA).ok_or("bosminer shorter than SET1")?;
    if set1 != BOSMINER_HASHCHAIN_C8_SET1_INSN {
        return Err("0x8d69bc is not MOVZ W8,#1 (Completed)");
    }
    let set2 =
        engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_SET2_VA).ok_or("bosminer shorter than SET2")?;
    if set2 != BOSMINER_HASHCHAIN_C8_SET2_INSN {
        return Err("0x8d6a84 is not MOVZ W8,#2 (Panicked)");
    }
    let set3 =
        engine88_le_u32(blob, BOSMINER_HASHCHAIN_C8_SET3_VA).ok_or("bosminer shorter than SET3")?;
    if set3 != BOSMINER_HASHCHAIN_C8_SET3_INSN {
        return Err("0x8d69dc is not MOVZ W8,#3 (Suspended)");
    }
    Ok(())
}

/// +0xC8 is not a HashChain Running/Starting lifecycle enum.
pub fn refuse_c8_as_hashchain_running_or_starting() -> Result<(), &'static str> {
    Err(
        "FUN_008d684c loc is command.rs:700:51; tag1 panics `async fn resumed after completion`; tag2 panics `async fn resumed after panicking`; tag3 is Suspended; not HashChain Running/Starting",
    )
}

/// command.rs:700 Future is polled only from 6 hashchain-driver BLs.
pub fn admit_bosminer_c8_async_polled_from_hashchain_drivers(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_C8_POLL_BL_HITS != 6 {
        return Err("FUN_008d684c first-LOAD BL census must stay 6");
    }
    if BOSMINER_C8_POLL_BM1366_LINE != 127 || BOSMINER_C8_POLL_BM136X_LINE != 107 {
        return Err("bm1366.rs:127 / bm136x.rs:107 caller lines drifted");
    }
    if BOSMINER_C8_POLL_BM1397_LINE != 147 {
        return Err("bm1397.rs:147 caller line drifted");
    }
    if BOSMINER_BM136X_FIELDSET_MSG.len() != BOSMINER_BM136X_FIELDSET_MSG_LEN {
        return Err("FieldSet assert string length drifted");
    }
    if BOSMINER_C8_FUTURE_OFF_BM1366 != 0x30
        || BOSMINER_C8_FUTURE_OFF_BM136X != 0x70
        || BOSMINER_C8_FUTURE_OFF_BM1397 != 0x18
    {
        return Err("inline Future offsets drifted");
    }
    for i in 0..6 {
        let bl = engine88_le_u32(blob, BOSMINER_C8_POLL_BL_VAS[i])
            .ok_or("bosminer shorter than command.rs:700 poll BL")?;
        if bl != BOSMINER_C8_POLL_BL_INSNS[i] {
            return Err("a first-LOAD BL is not FUN_008d684c");
        }
    }
    let ldr = engine88_le_u32(blob, BOSMINER_C8_POLL_VT230_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if ldr != BOSMINER_C8_POLL_VT230_LDR_INSN {
        return Err("0x8dd098 is not LDR X8,[X8,#0x230]");
    }
    let add10 = engine88_le_u32(blob, BOSMINER_C8_POLL_VT10_ADD_VA)
        .ok_or("bosminer shorter than ADD #0x10")?;
    if add10 != BOSMINER_C8_POLL_VT10_ADD_INSN {
        return Err("0x8dd0a4 is not ADD X8,X8,#0x10");
    }
    let a30 = engine88_le_u32(blob, BOSMINER_C8_POLL_ADD30_VA)
        .ok_or("bosminer shorter than ADD #0x30")?;
    if a30 != BOSMINER_C8_POLL_ADD30_INSN {
        return Err("0x8dd0b0 is not ADD X0,X19,#0x30");
    }
    let a70 = engine88_le_u32(blob, BOSMINER_C8_POLL_ADD70_VA)
        .ok_or("bosminer shorter than ADD #0x70")?;
    if a70 != BOSMINER_C8_POLL_ADD70_INSN {
        return Err("0x8ddcf4 is not ADD X0,X19,#0x70");
    }
    let a18 = engine88_le_u32(blob, BOSMINER_C8_POLL_ADD18_VA)
        .ok_or("bosminer shorter than ADD #0x18")?;
    if a18 != BOSMINER_C8_POLL_ADD18_INSN {
        return Err("0x8df6b0 is not ADD X0,X19,#0x18");
    }
    let l127 = engine88_le_u32(blob, BOSMINER_C8_POLL_BM1366_ADD_VA)
        .ok_or("bosminer shorter than bm1366.rs:127 ADD")?;
    if l127 != BOSMINER_C8_POLL_BM1366_ADD_INSN {
        return Err("0x8dd040 is not ADD #0xee8 (bm1366.rs:127)");
    }
    let l107 = engine88_le_u32(blob, BOSMINER_C8_POLL_BM136X_ADD_VA)
        .ok_or("bosminer shorter than bm136x.rs:107 ADD")?;
    if l107 != BOSMINER_C8_POLL_BM136X_ADD_INSN {
        return Err("0x8ddd38 is not ADD #0xc58 (bm136x.rs:107)");
    }
    let l147 = engine88_le_u32(blob, BOSMINER_C8_POLL_BM1397_ADD_VA)
        .ok_or("bosminer shorter than bm1397.rs:147 ADD")?;
    if l147 != BOSMINER_C8_POLL_BM1397_ADD_INSN {
        return Err("0x8df798 is not ADD #0x150 (bm1397.rs:147)");
    }
    Ok(())
}

/// No rust ident `write_register`/`send_command` at command.rs:700.
pub fn refuse_c8_async_as_named_write_register() -> Result<(), &'static str> {
    Err(
        "command.rs:700 is the Future polled from bm1366.rs:127 / bm136x.rs:107 / bm1397.rs:147; :108 is FieldSet corrupted; no write_register/send_command ident in-corpus",
    )
}

/// +0x230 is a pointer on `*(async_self+8)`; Future+0xC8 is zeroed at construct.
pub fn admit_bosminer_plus230_is_ctx_ptr_and_1a8_wrap_fields(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_C8_FUTURE_OFF_BM1366 + BOSMINER_WORKER_NEW_ARG1_C8 != BOSMINER_C8_FUT_PLUS_C8_BM1366
    {
        return Err("0x30+0xC8 must be caller +0xF8");
    }
    if BOSMINER_C8_FUTURE_OFF_BM136X + BOSMINER_WORKER_NEW_ARG1_C8 != BOSMINER_C8_FUT_PLUS_C8_BM136X
    {
        return Err("0x70+0xC8 must be caller +0x138");
    }
    if BOSMINER_C8_FUTURE_OFF_BM1397 + BOSMINER_WORKER_NEW_ARG1_C8 != BOSMINER_C8_FUT_PLUS_C8_BM1397
    {
        return Err("0x18+0xC8 must be caller +0xE0");
    }
    if BOSMINER_REGISTRY_WRAP_LINE != 109 || BOSMINER_REGISTRY_WRAP_COL != 32 {
        return Err("wrap loc must stay registry.rs:109:32");
    }
    if BOSMINER_REGISTRY_1A8_OFF_110 != 0x110 || BOSMINER_REGISTRY_1A8_OFF_168 != 0x168 {
        return Err("0x1a8 interior offsets drifted");
    }
    let ctx = engine88_le_u32(blob, BOSMINER_C8_CTX8_LDR_VA)
        .ok_or("bosminer shorter than LDR [X19,#8]")?;
    if ctx != BOSMINER_C8_CTX8_LDR_INSN {
        return Err("0x8dd094 is not LDR X8,[X19,#8]");
    }
    let p230 = engine88_le_u32(blob, BOSMINER_C8_POLL_VT230_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if p230 != BOSMINER_C8_POLL_VT230_LDR_INSN {
        return Err("0x8dd098 is not LDR X8,[X8,#0x230]");
    }
    let z0 = engine88_le_u32(blob, BOSMINER_C8_FUT_ZERO_VA)
        .ok_or("bosminer shorter than STR XZR Future+0")?;
    if z0 != BOSMINER_C8_FUT_ZERO_INSN {
        return Err("0x8dd09c is not STR XZR,[X19,#0x30]");
    }
    let imm = engine88_le_u32(blob, BOSMINER_C8_FUT_IMM_STR_VA)
        .ok_or("bosminer shorter than STR W23 Future+8")?;
    if imm != BOSMINER_C8_FUT_IMM_STR_INSN {
        return Err("0x8dd0a0 is not STR W23,[X19,#0x38]");
    }
    let add10 = engine88_le_u32(blob, BOSMINER_C8_POLL_VT10_ADD_VA)
        .ok_or("bosminer shorter than ADD #0x10")?;
    if add10 != BOSMINER_C8_POLL_VT10_ADD_INSN {
        return Err("0x8dd0a4 is not ADD X8,#0x10");
    }
    let zc8 = engine88_le_u32(blob, BOSMINER_C8_STATE_ZERO_F8_VA)
        .ok_or("bosminer shorter than STRB +0xF8")?;
    if zc8 != BOSMINER_C8_STATE_ZERO_F8_INSN {
        return Err("0x8dd0a8 is not STRB WZR,[X19,#0xF8]");
    }
    let f10 = engine88_le_u32(blob, BOSMINER_C8_FUT10_STR_VA)
        .ok_or("bosminer shorter than STR Future+0x10")?;
    if f10 != BOSMINER_C8_FUT10_STR_INSN {
        return Err("0x8dd0ac is not STR X8,[X19,#0x40]");
    }
    let z138 = engine88_le_u32(blob, BOSMINER_C8_STATE_ZERO_138_VA)
        .ok_or("bosminer shorter than STRB +0x138")?;
    if z138 != BOSMINER_C8_STATE_ZERO_138_INSN {
        return Err("0x8ddc34 is not STRB WZR,[X19,#0x138]");
    }
    let ze0 = engine88_le_u32(blob, BOSMINER_C8_STATE_ZERO_E0_VA)
        .ok_or("bosminer shorter than STRB +0xE0")?;
    if ze0 != BOSMINER_C8_STATE_ZERO_E0_INSN {
        return Err("0x8df6a8 is not STRB WZR,[X19,#0xE0]");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_REGISTRY_WRAP_LOC_ADRP_VA)
        .ok_or("bosminer shorter than wrap ADRP")?;
    if adrp != BOSMINER_REGISTRY_WRAP_LOC_ADRP_INSN {
        return Err("0xbf77e4 is not ADRP loc page");
    }
    let add = engine88_le_u32(blob, BOSMINER_REGISTRY_WRAP_LOC_ADD_VA)
        .ok_or("bosminer shorter than wrap ADD #0x1e0")?;
    if add != BOSMINER_REGISTRY_WRAP_LOC_ADD_INSN {
        return Err("0xbf77e8 is not ADD #0x1e0 (registry.rs:109)");
    }
    let bl = engine88_le_u32(blob, BOSMINER_REGISTRY_WRAP_NEW_BL_VA)
        .ok_or("bosminer shorter than BL Registry::new")?;
    if bl != BOSMINER_REGISTRY_WRAP_NEW_BL_INSN {
        return Err("0xbf77f8 is not BL FUN_00be6244");
    }
    let s110 = engine88_le_u32(blob, BOSMINER_REGISTRY_WRAP_STR110_VA)
        .ok_or("bosminer shorter than STR #0x110")?;
    if s110 != BOSMINER_REGISTRY_WRAP_STR110_INSN {
        return Err("0xbf796c is not STR [X23,#0x110]");
    }
    let a118 = engine88_le_u32(blob, BOSMINER_REGISTRY_WRAP_ADD118_VA)
        .ok_or("bosminer shorter than ADD #0x118")?;
    if a118 != BOSMINER_REGISTRY_WRAP_ADD118_INSN {
        return Err("0xbf7958 is not ADD X9,X23,#0x118");
    }
    let a168 = engine88_le_u32(blob, BOSMINER_REGISTRY_WRAP_ADD168_VA)
        .ok_or("bosminer shorter than ADD #0x168")?;
    if a168 != BOSMINER_REGISTRY_WRAP_ADD168_INSN {
        return Err("0xbf797c is not ADD X9,X23,#0x168");
    }
    let s1a8 = engine88_le_u32(blob, BOSMINER_REGISTRY_WRAP_STR1A8_VA)
        .ok_or("bosminer shorter than STR #0x1a8")?;
    if s1a8 != BOSMINER_REGISTRY_WRAP_STR1A8_INSN {
        return Err("0xbf7980 is not STR [X23,#0x1a8] exclusive end");
    }
    let mz = engine88_le_u32(blob, BOSMINER_REGISTRY_1E9_MOVZ_VA)
        .ok_or("bosminer shorter than 1e9 MOVZ")?;
    if mz != BOSMINER_REGISTRY_1E9_MOVZ_INSN {
        return Err("0xc0d4b8 is not MOVZ #0xca00");
    }
    let mk = engine88_le_u32(blob, BOSMINER_REGISTRY_1E9_MOVK_VA)
        .ok_or("bosminer shorter than 1e9 MOVK")?;
    if mk != BOSMINER_REGISTRY_1E9_MOVK_INSN {
        return Err("0xc0d4c0 is not MOVK #0x3b9a");
    }
    Ok(())
}

/// +0x230 is not a rust vtable; dest+0x1a8 store is not inside the 0x1a8 prefix.
pub fn refuse_plus230_as_vtable_or_1a8_end_as_interior() -> Result<(), &'static str> {
    Err(
        "+0x230 is a pointer on *(async_self+8); +0x10 of that pointer is stored at Future+0x10 and Future+0xC8 is zeroed. Wrap STR #0x1a8 is the exclusive end of the 0x1a8 Worker prefix, not an interior field. FUN_00c0d4ac 1e9 is a wrap temp, not the dest identity",
    )
}

/// HashChain+0x230 is constructed as usize 0x10; wrap +0x118/+0x168 are 32 B SIMD copies.
pub fn admit_bosminer_plus230_init_usize10_and_wrap_simd(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HC_PLUS230_INIT_LINE != 323 || BOSMINER_HC_PLUS230_INIT_COL != 73 {
        return Err("hashchain.rs:323:73 loc drifted");
    }
    if BOSMINER_HC_PLUS230_INIT_VALUE != 0x10 {
        return Err("HashChain+0x230 init value must stay 0x10");
    }
    if BOSMINER_HC_PLUS240_1E8 != 0x05F5_E100 {
        return Err("HashChain+0x240 1e8 immediate drifted");
    }
    if BOSMINER_WRAP_SIMD_118_LEN != 32 || BOSMINER_WRAP_SIMD_168_LEN != 32 {
        return Err("wrap SIMD copy lengths must stay 32");
    }
    if BOSMINER_WRAP_STP158_LEN != 16 {
        return Err("dest+0x158 STP pair must stay 16");
    }
    let mz = engine88_le_u32(blob, BOSMINER_HC_PLUS230_MOVZ10_VA)
        .ok_or("bosminer shorter than MOVZ #0x10")?;
    if mz != BOSMINER_HC_PLUS230_MOVZ10_INSN {
        return Err("0x836bec is not MOVZ W8,#0x10");
    }
    let st = engine88_le_u32(blob, BOSMINER_HC_PLUS230_STR_VA)
        .ok_or("bosminer shorter than STR #0x230")?;
    if st != BOSMINER_HC_PLUS230_STR_INSN {
        return Err("0x836bf8 is not STR X8,[X10,#0x230]");
    }
    let z238 = engine88_le_u32(blob, BOSMINER_HC_PLUS238_ZERO_VA)
        .ok_or("bosminer shorter than STR XZR #0x238")?;
    if z238 != BOSMINER_HC_PLUS238_ZERO_INSN {
        return Err("0x836c24 is not STR XZR,[X10,#0x238]");
    }
    let s240 = engine88_le_u32(blob, BOSMINER_HC_PLUS240_STR_VA)
        .ok_or("bosminer shorter than STR W #0x240")?;
    if s240 != BOSMINER_HC_PLUS240_STR_INSN {
        return Err("0x836c0c is not STR W8,[X10,#0x240]");
    }
    let mk = engine88_le_u32(blob, BOSMINER_HC_PLUS240_MOVK_VA)
        .ok_or("bosminer shorter than MOVK #0x5f5")?;
    if mk != BOSMINER_HC_PLUS240_MOVK_INSN {
        return Err("0x836c04 is not MOVK W8,#0x5f5");
    }
    let slf = engine88_le_u32(blob, BOSMINER_HC_PLUS258_SELF_VA)
        .ok_or("bosminer shorter than STR self #0x258")?;
    if slf != BOSMINER_HC_PLUS258_SELF_INSN {
        return Err("0x836c30 is not STR X10,[X10,#0x258]");
    }
    let ladd = engine88_le_u32(blob, BOSMINER_HC_PLUS230_LOC_ADD_VA)
        .ok_or("bosminer shorter than loc ADD #0xad0")?;
    if ladd != BOSMINER_HC_PLUS230_LOC_ADD_INSN {
        return Err("0x836cb0 is not ADD #0xad0 (hashchain.rs:323)");
    }
    let ldp118 = engine88_le_u32(blob, BOSMINER_WRAP_SIMD_118_LDP_VA)
        .ok_or("bosminer shorter than LDP X22+0")?;
    if ldp118 != BOSMINER_WRAP_SIMD_118_LDP_INSN {
        return Err("0xbf7968 is not LDP Q from X22+0");
    }
    let stp118 = engine88_le_u32(blob, BOSMINER_WRAP_SIMD_118_STP_VA)
        .ok_or("bosminer shorter than STP dest+0x118")?;
    if stp118 != BOSMINER_WRAP_SIMD_118_STP_INSN {
        return Err("0xbf7974 is not STP Q [X9,#0] (dest+0x118)");
    }
    let ldp168 = engine88_le_u32(blob, BOSMINER_WRAP_SIMD_168_LDP_VA)
        .ok_or("bosminer shorter than LDP SP+#0x230")?;
    if ldp168 != BOSMINER_WRAP_SIMD_168_LDP_INSN {
        return Err("0xbf798c is not LDP Q from SP+#0x230");
    }
    let stp168 = engine88_le_u32(blob, BOSMINER_WRAP_SIMD_168_STP_VA)
        .ok_or("bosminer shorter than STP dest+0x168")?;
    if stp168 != BOSMINER_WRAP_SIMD_168_STP_INSN {
        return Err("0xbf7998 is not STP Q [X9,#0] (dest+0x168)");
    }
    let p158 =
        engine88_le_u32(blob, BOSMINER_WRAP_STP158_VA).ok_or("bosminer shorter than STP #0x158")?;
    if p158 != BOSMINER_WRAP_STP158_INSN {
        return Err("0xbf7960 is not STP X21,X20,[X23,#0x158]");
    }
    Ok(())
}

/// HashChain+0x230 is not a named io/command pointer; dest+0x168 is not Registry::new.
pub fn refuse_plus230_as_named_io_ptr_or_168_as_registry_new() -> Result<(), &'static str> {
    Err(
        "hashchain.rs:323 stores usize 0x10 at HashChain+0x230 (not an io/command ident). dest+0x168 is a 32-byte copy of the FUN_00c0d4ac 1e9 temp at SP+#0x230, not Registry::new (sret SP+#0x278)",
    )
}

/// Poll-time `*(Future+8)+0x230` is the HashChain usize-0x10 field; wrap +0x188 is unwritten.
pub fn admit_bosminer_poll_230_is_hc_usize10_and_188_unwritten(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_HC_PLUS230_INIT_VALUE + 0x10 != BOSMINER_POLL_230_PLUS10_SUM {
        return Err("0x10+0x10 must be 0x20");
    }
    if BOSMINER_REGISTRY_1A8_OFF_168 as usize + BOSMINER_WRAP_SIMD_168_LEN
        != BOSMINER_WRAP_1A8_UNWRITTEN_OFF as usize
    {
        return Err("0x168+32 must be the unwritten start 0x188");
    }
    if BOSMINER_WRAP_1A8_UNWRITTEN_OFF as usize + BOSMINER_WRAP_1A8_UNWRITTEN_LEN != 0x1A8 {
        return Err("0x188+32 must be exclusive end 0x1a8");
    }
    if BOSMINER_WRAP_188_STORE_HITS != 0 {
        return Err("wrap dest+0x188 store census must stay 0");
    }
    if BOSMINER_POLL_STATE_OFF != 0x2A {
        return Err("bm1366.rs:127 state is +0x2a, not command +0xC8");
    }
    let l0 = engine88_le_u32(blob, BOSMINER_POLL_FUT0_LDR_VA)
        .ok_or("bosminer shorter than LDR Future+0")?;
    if l0 != BOSMINER_POLL_FUT0_LDR_INSN {
        return Err("0x8dd020 is not LDR X9,[X19,#0]");
    }
    let s8 = engine88_le_u32(blob, BOSMINER_POLL_FUT8_STR_VA)
        .ok_or("bosminer shorter than STR Future+8")?;
    if s8 != BOSMINER_POLL_FUT8_STR_INSN {
        return Err("0x8dd02c is not STR X9,[X19,#8]");
    }
    let l8 = engine88_le_u32(blob, BOSMINER_C8_CTX8_LDR_VA)
        .ok_or("bosminer shorter than LDR Future+8")?;
    if l8 != BOSMINER_C8_CTX8_LDR_INSN {
        return Err("0x8dd094 is not LDR X8,[X19,#8]");
    }
    let p230 = engine88_le_u32(blob, BOSMINER_C8_POLL_VT230_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if p230 != BOSMINER_C8_POLL_VT230_LDR_INSN {
        return Err("0x8dd098 is not LDR [X8,#0x230]");
    }
    let add = engine88_le_u32(blob, BOSMINER_C8_POLL_VT10_ADD_VA)
        .ok_or("bosminer shorter than ADD #0x10")?;
    if add != BOSMINER_C8_POLL_VT10_ADD_INSN {
        return Err("0x8dd0a4 is not ADD #0x10");
    }
    let st = engine88_le_u32(blob, BOSMINER_HC_PLUS230_STR_VA)
        .ok_or("bosminer shorter than HashChain STR #0x230")?;
    if st != BOSMINER_HC_PLUS230_STR_INSN {
        return Err("0x836bf8 is not HashChain STR #0x230 = 0x10");
    }
    let stt = engine88_le_u32(blob, BOSMINER_POLL_STATE_LDRB_VA)
        .ok_or("bosminer shorter than LDRB +0x2a")?;
    if stt != BOSMINER_POLL_STATE_LDRB_INSN {
        return Err("0x8dcfcc is not LDRB [X0,#0x2a]");
    }
    Ok(())
}

/// Poll-time +0x230 is not a heap-pointer field projection.
pub fn refuse_poll_230_as_heap_ptr_projection() -> Result<(), &'static str> {
    Err(
        "Future+8 is a copy of Future+0; LDR +0x230 is HashChain usize 0x10; ADD #0x10 stores 0x20 at nested Future+0x10; command poll does not LDR that +0x10; not a heap pointer projection",
    )
}

/// dest+0x168 is the 32 B NANOS_PER_SEC prefix of `FUN_00c0d4ac`
/// (`SystemTime::now` + 1e9 stamps). HashChain+0x230 stays a usize 0x10.
pub fn admit_bosminer_230_usize_not_time_and_168_is_now_scale_prefix(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_NANOS_PER_SEC != 1_000_000_000 {
        return Err("NANOS_PER_SEC must stay 1e9");
    }
    if BOSMINER_CLOCK_REALTIME != 0 {
        return Err("CLOCK_REALTIME must stay 0");
    }
    if BOSMINER_DURATION_NEW_LINE != 201 || BOSMINER_DURATION_NEW_COL != 18 {
        return Err("Duration::new loc must stay time.rs:201:18");
    }
    if BOSMINER_TIMESPEC_NOW_LINE_137 != 137 || BOSMINER_TIMESPEC_NOW_COL_137 != 68 {
        return Err("Timespec::now loc must stay unix/time.rs:137:68");
    }
    if BOSMINER_TIMESPEC_NOW_LINE_139 != 139 || BOSMINER_TIMESPEC_NOW_COL_139 != 58 {
        return Err("Timespec::now loc must stay unix/time.rs:139:58");
    }
    if (BOSMINER_C0D4AC_NOW_OFF as usize) < BOSMINER_WRAP_SIMD_168_LEN {
        return Err("SystemTime at +0x28 must sit outside the dest+0x168 32 B copy");
    }
    if BOSMINER_HC_PLUS230_INIT_VALUE != 0x10 {
        return Err("HashChain+0x230 must stay usize 0x10");
    }
    if BOSMINER_DURATION_NEW_BL_HITS != 8 {
        return Err("Duration::new first-LOAD BL census must stay 8");
    }
    let bl = engine88_le_u32(blob, BOSMINER_C0D4AC_NOW_BL_VA)
        .ok_or("bosminer shorter than c0d4ac BL SystemTime::now")?;
    if bl != BOSMINER_C0D4AC_NOW_BL_INSN {
        return Err("0xc0d4b4 is not BL FUN_0129a108");
    }
    let s8 = engine88_le_u32(blob, BOSMINER_C0D4AC_STR8_VA)
        .ok_or("bosminer shorter than c0d4ac STR #8")?;
    if s8 != BOSMINER_C0D4AC_STR8_INSN {
        return Err("0xc0d4cc is not STR W 1e9 at dest+0x08");
    }
    let s18 = engine88_le_u32(blob, BOSMINER_C0D4AC_STR18_VA)
        .ok_or("bosminer shorter than c0d4ac STR #0x18")?;
    if s18 != BOSMINER_C0D4AC_STR18_INSN {
        return Err("0xc0d4d0 is not STR W 1e9 at dest+0x18");
    }
    let s30 = engine88_le_u32(blob, BOSMINER_C0D4AC_STR30_VA)
        .ok_or("bosminer shorter than c0d4ac STR #0x30")?;
    if s30 != BOSMINER_C0D4AC_STR30_INSN {
        return Err("0xc0d4c4 is not STR W1 nsec at dest+0x30");
    }
    let stp = engine88_le_u32(blob, BOSMINER_C0D4AC_STP20_VA)
        .ok_or("bosminer shorter than c0d4ac STP #0x20")?;
    if stp != BOSMINER_C0D4AC_STP20_INSN {
        return Err("0xc0d4d4 is not STP XZR,X0 at dest+0x20 (secs at +0x28)");
    }
    let w0 = engine88_le_u32(blob, BOSMINER_SYSNOW_W0_VA)
        .ok_or("bosminer shorter than SystemTime::now W0")?;
    if w0 != BOSMINER_SYSNOW_W0_INSN {
        return Err("0x129a110 is not MOV W0,WZR (CLOCK_REALTIME)");
    }
    let bnow = engine88_le_u32(blob, BOSMINER_SYSNOW_B_VA)
        .ok_or("bosminer shorter than SystemTime::now B")?;
    if bnow != BOSMINER_SYSNOW_B_INSN {
        return Err("0x129a118 is not B Timespec::now");
    }
    let mz = engine88_le_u32(blob, BOSMINER_TIMESPEC_1E9_MOVZ_VA)
        .ok_or("bosminer shorter than Timespec 1e9 MOVZ")?;
    if mz != BOSMINER_TIMESPEC_1E9_MOVZ_INSN {
        return Err("0x129ef30 is not MOVZ #0xca00");
    }
    let mk = engine88_le_u32(blob, BOSMINER_TIMESPEC_1E9_MOVK_VA)
        .ok_or("bosminer shorter than Timespec 1e9 MOVK")?;
    if mk != BOSMINER_TIMESPEC_1E9_MOVK_INSN {
        return Err("0x129ef34 is not MOVK #0x3b9a");
    }
    let dmv = engine88_le_u32(blob, BOSMINER_DURATION_NEW_1E9_MOVZ_VA)
        .ok_or("bosminer shorter than Duration::new 1e9 MOVZ")?;
    if dmv != BOSMINER_DURATION_NEW_1E9_MOVZ_INSN {
        return Err("0x129f02c is not Duration::new MOVZ #0xca00");
    }
    let dmk = engine88_le_u32(blob, BOSMINER_DURATION_NEW_1E9_MOVK_VA)
        .ok_or("bosminer shorter than Duration::new 1e9 MOVK")?;
    if dmk != BOSMINER_DURATION_NEW_1E9_MOVK_INSN {
        return Err("0x129f034 is not Duration::new MOVK #0x3b9a");
    }
    let dstr = engine88_le_u32(blob, BOSMINER_DURATION_NEW_STR10_VA)
        .ok_or("bosminer shorter than Duration::new STR #0x10")?;
    if dstr != BOSMINER_DURATION_NEW_STR10_INSN {
        return Err("0x129f070 is not STR W at Duration dest+0x10");
    }
    let p260 = engine88_le_u32(blob, BOSMINER_HC_PLUS260_MOVZ_VA)
        .ok_or("bosminer shorter than +0x260 MOVZ #1")?;
    if p260 != BOSMINER_HC_PLUS260_MOVZ_INSN {
        return Err("0x89b720 is not MOVZ W0,#1");
    }
    let pret = engine88_le_u32(blob, BOSMINER_HC_PLUS260_RET_VA)
        .ok_or("bosminer shorter than +0x260 RET")?;
    if pret != BOSMINER_HC_PLUS260_RET_INSN {
        return Err("0x89b724 is not RET");
    }
    let s260 = engine88_le_u32(blob, BOSMINER_HC_PLUS260_STR_VA)
        .ok_or("bosminer shorter than STR #0x260")?;
    if s260 != BOSMINER_HC_PLUS260_STR_INSN {
        return Err("0x836c34 is not STR +0x260 const-true fn");
    }
    Ok(())
}

/// HashChain+0x230 is not Instant/SystemTime/Duration; dest+0x168 is not Instant.
pub fn refuse_230_or_168_as_instant_or_duration() -> Result<(), &'static str> {
    Err(
        "HashChain+0x230 is usize 0x10 (poll ADD 0x10+0x10=0x20), not Instant/SystemTime/Duration. dest+0x168 is the 32 B NANOS_PER_SEC prefix of FUN_00c0d4ac; SystemTime::now (CLOCK_REALTIME=0) lands at +0x28/+0x30, outside that copy. Instant uses CLOCK_MONOTONIC=1",
    )
}

/// `FUN_00c0d4ac` is a 0x48 object; 37 first-LOAD BLs split 6 FPGA / 25 UART / 6 wrap.
pub fn admit_bosminer_c0d4ac_is_48_and_37_split_fpga_uart_wrap(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_C0D4AC_SIZE != 0x48 {
        return Err("c0d4ac object size must stay 0x48");
    }
    if BOSMINER_C0D4AC_FPGA_SECOND_DEST - BOSMINER_C0D4AC_FPGA_FIRST_DEST != BOSMINER_C0D4AC_SIZE {
        return Err("FPGA dest stride 0x110-0xc8 must be 0x48");
    }
    if BOSMINER_C0D4AC_FPGA_LAST_DEST - BOSMINER_C0D4AC_FPGA_FIRST_DEST != BOSMINER_C0D4AC_SIZE * 5
    {
        return Err("FPGA last dest 0x230 must be first+5*0x48");
    }
    if BOSMINER_C0D4AC_BL_HITS != 37
        || BOSMINER_C0D4AC_FPGA_HITS != 6
        || BOSMINER_C0D4AC_UART_HITS != 25
        || BOSMINER_C0D4AC_WRAP_HITS != 6
    {
        return Err("37 BL split must stay 6 FPGA + 25 UART + 6 wrap");
    }
    if BOSMINER_C0D4AC_UART_HITS != BOSMINER_C0D4AC_UART_CLUSTERS * 5 {
        return Err("UART hits must stay 5 clusters of 5");
    }
    if BOSMINER_WRAP_SIMD_168_LEN >= BOSMINER_C0D4AC_SIZE as usize {
        return Err("dest+0x168 32 B copy must be smaller than the 0x48 object");
    }
    if BOSMINER_C0D4AC_WRAP_SECOND_DEST - 0x230 != BOSMINER_C0D4AC_SIZE {
        return Err("wrap dest 0x278-0x230 must be 0x48");
    }
    if BOSMINER_C0D478_SIBLING_SIZE != 0x20 {
        return Err("c0d478 sibling must stay 0x20");
    }
    let a = engine88_le_u32(blob, BOSMINER_C0D4AC_FPGA_ADD_C8_VA)
        .ok_or("bosminer shorter than FPGA ADD #0xc8")?;
    if a != BOSMINER_C0D4AC_FPGA_ADD_C8_INSN {
        return Err("0x8af910 is not ADD X8,SP,#0xc8");
    }
    let bl = engine88_le_u32(blob, BOSMINER_C0D4AC_FPGA_BL0_VA)
        .ok_or("bosminer shorter than FPGA first c0d4ac BL")?;
    if bl != BOSMINER_C0D4AC_FPGA_BL0_INSN {
        return Err("0x8af914 is not first FPGA BL FUN_00c0d4ac");
    }
    let last = engine88_le_u32(blob, BOSMINER_C0D4AC_FPGA_ADD_230_VA)
        .ok_or("bosminer shorter than FPGA ADD #0x230")?;
    if last != BOSMINER_C0D4AC_FPGA_ADD_230_INSN {
        return Err("0x8af938 is not ADD X8,SP,#0x230");
    }
    let sib = engine88_le_u32(blob, BOSMINER_C0D478_FPGA_BL_VA)
        .ok_or("bosminer shorter than FPGA BL c0d478")?;
    if sib != BOSMINER_C0D478_FPGA_BL_INSN {
        return Err("0x8af90c is not BL FUN_00c0d478 sibling");
    }
    let ubl = engine88_le_u32(blob, BOSMINER_C0D4AC_UART_BL0_VA)
        .ok_or("bosminer shorter than UART first c0d4ac BL")?;
    if ubl != BOSMINER_C0D4AC_UART_BL0_INSN {
        return Err("0x8f836c is not first UART BL FUN_00c0d4ac");
    }
    let wadd = engine88_le_u32(blob, BOSMINER_C0D4AC_WRAP_ADD230_VA)
        .ok_or("bosminer shorter than wrap ADD #0x230")?;
    if wadd != BOSMINER_C0D4AC_WRAP_ADD230_INSN {
        return Err("0xbf78a4 is not ADD X8,SP,#0x230");
    }
    let wbl = engine88_le_u32(blob, BOSMINER_C0D4AC_WRAP_BL0_VA)
        .ok_or("bosminer shorter than wrap first c0d4ac BL")?;
    if wbl != BOSMINER_C0D4AC_WRAP_BL0_INSN {
        return Err("0xbf78a8 is not first wrap BL FUN_00c0d4ac");
    }
    Ok(())
}

/// dest+0x168 is not the full c0d4ac object; FPGA 6 is not a UART-only helper.
pub fn refuse_168_as_full_c0d4ac_or_fpga_as_uart_only() -> Result<(), &'static str> {
    Err(
        "dest+0x168 copies 32 B of a 0x48 FUN_00c0d4ac object (SystemTime at +0x28 sits in the uncopied tail). 37 first-LOAD BLs are 6 FPGA + 25 UART + 6 wrap, not UART-only",
    )
}

/// 0x48 cell is a SystemTime::now + dual-NANOS_PER_SEC object in FPGA
/// `FUN_008af670` / UART `worker.rs:68` / registry wrap. Not a 16-byte time type.
pub fn admit_bosminer_c0d4ac_is_now_scale_cell_not_timespec(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_C0D4AC_SIZE == BOSMINER_TIMESPEC_SIZE
        || BOSMINER_C0D4AC_SIZE == BOSMINER_INSTANT_SIZE
        || BOSMINER_C0D4AC_SIZE == BOSMINER_SYSTEMTIME_SIZE
        || BOSMINER_C0D4AC_SIZE == BOSMINER_DURATION_SIZE
    {
        return Err("0x48 cell must not collapse to a 16-byte time type");
    }
    if BOSMINER_C0D4AC_UART_WORKER_LINE != 68 || BOSMINER_C0D4AC_UART_WORKER_COL != 18 {
        return Err("UART worker.rs:68:18 loc drifted");
    }
    if BOSMINER_C0D4AC_FPGA_HOST_VA != BOSMINER_FPGA_DIV_CALLER_VA {
        return Err("FPGA host of c0d4ac must stay FUN_008af670");
    }
    if BOSMINER_HC_PLUS230_INIT_VALUE != BOSMINER_TIMESPEC_SIZE {
        return Err("numeric 0x10 coincidence with Timespec size must stay visible");
    }
    if BOSMINER_POLL_230_PLUS10_SUM != BOSMINER_TIMESPEC_SIZE * 2 {
        return Err("poll still stores usize 0x20, not a Timespec");
    }
    let stp = engine88_le_u32(blob, BOSMINER_C0D4AC_FPGA_HOST_VA)
        .ok_or("bosminer shorter than FPGA host STP")?;
    if stp != BOSMINER_C0D4AC_FPGA_HOST_STP_INSN {
        return Err("0x8af670 is not STP X29,X30 FPGA host prologue");
    }
    let sub = engine88_le_u32(blob, BOSMINER_C0D4AC_FPGA_HOST_SUB_VA)
        .ok_or("bosminer shorter than FPGA SUB SP")?;
    if sub != BOSMINER_C0D4AC_FPGA_HOST_SUB_INSN {
        return Err("0x8af688 is not SUB SP,#0x380");
    }
    let bl0 = engine88_le_u32(blob, BOSMINER_C0D4AC_FPGA_BL0_VA)
        .ok_or("bosminer shorter than FPGA c0d4ac BL0")?;
    if bl0 != BOSMINER_C0D4AC_FPGA_BL0_INSN {
        return Err("FPGA host does not BL c0d4ac at 0x8af914");
    }
    let ubl = engine88_le_u32(blob, BOSMINER_C0D4AC_UART_BL0_VA)
        .ok_or("bosminer shorter than UART c0d4ac BL0")?;
    if ubl != BOSMINER_C0D4AC_UART_BL0_INSN {
        return Err("UART worker body does not BL c0d4ac at 0x8f836c");
    }
    let wbl = engine88_le_u32(blob, BOSMINER_C0D4AC_WRAP_BL0_VA)
        .ok_or("bosminer shorter than wrap c0d4ac BL0")?;
    if wbl != BOSMINER_C0D4AC_WRAP_BL0_INSN {
        return Err("registry wrap does not BL c0d4ac at 0xbf78a8");
    }
    let mz = engine88_le_u32(blob, BOSMINER_HC_PLUS230_MOVZ10_VA)
        .ok_or("bosminer shorter than +0x230 MOVZ #0x10")?;
    if mz != BOSMINER_HC_PLUS230_MOVZ10_INSN {
        return Err("HashChain+0x230 is still MOVZ #0x10");
    }
    let add = engine88_le_u32(blob, BOSMINER_C8_POLL_VT10_ADD_VA)
        .ok_or("bosminer shorter than poll ADD #0x10")?;
    if add != BOSMINER_C8_POLL_VT10_ADD_INSN {
        return Err("poll still ADDs #0x10 to the usize, not a Timespec field");
    }
    Ok(())
}

/// HashChain+0x230 is not size_of::<Timespec>(); c0d4ac is not Timespec/Instant/Duration.
pub fn refuse_c0d4ac_or_plus230_as_timespec_size() -> Result<(), &'static str> {
    Err(
        "FUN_00c0d4ac is 0x48 (SystemTime::now + dual NANOS_PER_SEC) in FPGA FUN_008af670 / UART worker.rs:68 / registry wrap — not Timespec/Instant/SystemTime/Duration (16). HashChain+0x230 is a usize 0x10 whose poll path ADDs 0x10 and stores 0x20 in a Future; that is not size_of::<Timespec>() memcpy length and not a Timespec value. No Timespec ident in the binary",
    )
}

/// +0x230 is constructed in hashchain.rs:323 whose resume also hits command.rs:647.
/// The 0x48 cell is not Metrics.stop_watch / perf_time / HashesTimeMean.
pub fn admit_bosminer_230_owner_nests_command_647_and_48_not_stop_watch(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_HC_PLUS230_NESTED_CMD_LINE != 647 || BOSMINER_HC_PLUS230_NESTED_CMD_COL != 21 {
        return Err("command.rs:647:21 loc drifted");
    }
    if BOSMINER_METRICS_223_LINE != 223 || BOSMINER_METRICS_223_COL != 43 {
        return Err("metrics.rs:223:43 loc drifted");
    }
    if BOSMINER_HASHES_TIME_MEAN_ELEMENTS != 2 {
        return Err("HashesTimeMean must stay a 2-element serde type");
    }
    if BOSMINER_METRICS_223_BL_TGT == BOSMINER_REGISTRY_1E9_INIT_FN_VA {
        return Err("metrics.rs:223 must not be FUN_00c0d4ac");
    }
    if BOSMINER_C0D4AC_SIZE == 16 {
        return Err("0x48 cell must stay larger than a 2-word time type");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_HC_PLUS230_NESTED_CMD_ADRP_VA)
        .ok_or("bosminer shorter than command.rs:647 ADRP")?;
    if adrp != BOSMINER_HC_PLUS230_NESTED_CMD_ADRP_INSN {
        return Err("0x836cdc is not ADRP for command.rs:647");
    }
    let add = engine88_le_u32(blob, BOSMINER_HC_PLUS230_NESTED_CMD_ADD_VA)
        .ok_or("bosminer shorter than command.rs:647 ADD")?;
    if add != BOSMINER_HC_PLUS230_NESTED_CMD_ADD_INSN {
        return Err("0x836ce0 is not ADD #0x40 (command.rs:647)");
    }
    let bl = engine88_le_u32(blob, BOSMINER_HC_PLUS230_NESTED_CMD_BL_VA)
        .ok_or("bosminer shorter than command.rs:647 BL")?;
    if bl != BOSMINER_HC_PLUS230_NESTED_CMD_BL_INSN {
        return Err("0x836ce4 is not BL async-resume helper");
    }
    let mz = engine88_le_u32(blob, BOSMINER_HC_PLUS230_MOVZ10_VA)
        .ok_or("bosminer shorter than +0x230 MOVZ")?;
    if mz != BOSMINER_HC_PLUS230_MOVZ10_INSN {
        return Err("hashchain.rs:323 still stores usize 0x10");
    }
    let madrp = engine88_le_u32(blob, BOSMINER_METRICS_223_ADRP_VA)
        .ok_or("bosminer shorter than metrics.rs:223 ADRP")?;
    if madrp != BOSMINER_METRICS_223_ADRP_INSN {
        return Err("0x41eaa4 is not ADRP metrics.rs:223");
    }
    let madd = engine88_le_u32(blob, BOSMINER_METRICS_223_ADD_VA)
        .ok_or("bosminer shorter than metrics.rs:223 ADD")?;
    if madd != BOSMINER_METRICS_223_ADD_INSN {
        return Err("0x41eaa8 is not ADD #0x180 (metrics.rs:223)");
    }
    let mbl = engine88_le_u32(blob, BOSMINER_METRICS_223_BL_VA)
        .ok_or("bosminer shorter than metrics.rs:223 BL")?;
    if mbl != BOSMINER_METRICS_223_BL_INSN {
        return Err("0x41eab0 is not BL 0xf2a35c (fmt, not c0d4ac)");
    }
    Ok(())
}

/// 0x48 cell is not Metrics.stop_watch / perf_time / HashesTimeMean.
pub fn refuse_c0d4ac_as_metrics_stop_watch_or_hashes_time_mean() -> Result<(), &'static str> {
    Err(
        "stop_watch/perf_time are Metrics fields in bosminer-hal/src/metrics.rs; metrics.rs:223 is BL 0xf2a35c fmt (0 c0d4ac). HashesTimeMean is a 2-element serde type. The 0x48 SystemTime::now cell is not those idents. HashChain+0x230 is a usize in hashchain.rs:323 whose resume also panics at command.rs:647",
    )
}

/// 0x48 cell is Copy; rustc drop/v0 typeinfo is absent; workpair.rs sits before wrap.
pub fn admit_bosminer_c0d4ac_is_copy_and_workpair_is_wrap_sibling(
    blob: &[u8],
) -> Result<(), &'static str> {
    if !BOSMINER_C0D4AC_IS_COPY {
        return Err("0x48 cell must stay Copy");
    }
    if BOSMINER_DROP_IN_PLACE_HITS != 0 || BOSMINER_RUSTC_V0_RNV_HITS != 0 {
        return Err("drop_in_place / rustc v0 must stay absent");
    }
    if BOSMINER_WORKPAIR_C0D4AC_BL_HITS != 0 {
        return Err("workpair.rs must not BL FUN_00c0d4ac");
    }
    if BOSMINER_WORKPAIR_LINE_110 != 110 || BOSMINER_WORKPAIR_COL_110 != 22 {
        return Err("workpair.rs:110:22 loc drifted");
    }
    if BOSMINER_C0D4E0_BL_HITS != 1 {
        return Err("byte-swap sibling 0xc0d4e0 must stay 1 BL");
    }
    if BOSMINER_WRAP_FN_START_VA <= BOSMINER_WORKPAIR_RET_VA {
        return Err("wrap must start after workpair RET");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_WORKPAIR_110_ADRP_VA)
        .ok_or("bosminer shorter than workpair.rs:110 ADRP")?;
    if adrp != BOSMINER_WORKPAIR_110_ADRP_INSN {
        return Err("0xbf65d0 is not ADRP workpair.rs:110");
    }
    let add = engine88_le_u32(blob, BOSMINER_WORKPAIR_110_ADD_VA)
        .ok_or("bosminer shorter than workpair.rs:110 ADD")?;
    if add != BOSMINER_WORKPAIR_110_ADD_INSN {
        return Err("0xbf65d4 is not ADD workpair.rs:110");
    }
    let ret = engine88_le_u32(blob, BOSMINER_WORKPAIR_RET_VA)
        .ok_or("bosminer shorter than workpair RET")?;
    if ret != BOSMINER_WORKPAIR_RET_INSN {
        return Err("0xbf7568 is not workpair RET");
    }
    let wrap =
        engine88_le_u32(blob, BOSMINER_WRAP_FN_START_VA).ok_or("bosminer shorter than wrap STP")?;
    if wrap != 0xA9BA_7BFD {
        return Err("0xbf7798 is not wrap STP prologue");
    }
    let sw = engine88_le_u32(blob, BOSMINER_C0D4E0_SWAP_FN_VA)
        .ok_or("bosminer shorter than 0xc0d4e0 LDRB")?;
    if sw != BOSMINER_C0D4E0_LDRB_INSN {
        return Err("0xc0d4e0 is not LDRB swap start");
    }
    let sbl =
        engine88_le_u32(blob, BOSMINER_C0D4E0_BL_VA).ok_or("bosminer shorter than 0xc0d4e0 BL")?;
    if sbl != BOSMINER_C0D4E0_BL_INSN {
        return Err("0x4238a0 is not the unique BL 0xc0d4e0");
    }
    Ok(())
}

/// Drop/typeinfo cannot name the 0x48 cell WorkPair.
pub fn refuse_c0d4ac_as_workpair_or_named_from_drop_glue() -> Result<(), &'static str> {
    Err(
        "0x48 cell is Copy: 0 drop_in_place strings, 0 rustc v0 _RNv names, next fn 0xc0d4e0 is a 1-BL byte-swap not a drop. workpair.rs:110 sits before wrap RET/STP but workpair first-LOAD BLs to c0d4ac are 0 — not WorkPair",
    )
}

/// +0x230 is the X0 usize to `(+0x238).vtable[+0x40]`; poll ADD lands at Future+0x40;
/// hashchain.rs:323:73 after RET is the resume pad; ticket-mask log is :298 later.
pub fn admit_bosminer_230_is_vt40_x0_and_poll_stores_fut40(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_HC_PLUS230_VT_OFF != BOSMINER_POLL_FUT40_OFF {
        return Err("+0x238 vtable slot and Future store off must stay 0x40");
    }
    if BOSMINER_HASHCHAIN_TICKET_LINE != 298 || BOSMINER_HASHCHAIN_TICKET_COL != 9 {
        return Err("ticket-mask log must stay hashchain.rs:298:9");
    }
    if BOSMINER_HC_PLUS230_INIT_LINE != 323 {
        return Err("resume pad line must stay 323");
    }
    if BOSMINER_HC_PLUS230_RET_VA >= BOSMINER_HC_PLUS230_LOC_ADD_VA {
        return Err("hashchain.rs:323 loc must sit after FUN_00836934 RET");
    }
    if BOSMINER_HASHCHAIN_TICKET_ADRP_VA <= BOSMINER_HC_PLUS230_CONSUMER_BLR_VA {
        return Err("ticket-mask :298 must be a later jump-table state than the +0x230 BLR");
    }
    if BOSMINER_TICKET_MASK_STRB_FN_VA != 0x0083_6934 {
        return Err("FUN_00836934 ticket-mask future VA drifted");
    }
    if BOSMINER_C8_FUT10_STR_VA != BOSMINER_POLL_FUT40_STR_VA
        || BOSMINER_C8_FUT10_STR_INSN != BOSMINER_POLL_FUT40_STR_INSN
    {
        return Err("Wave-186 FUT10 STR is the Future+0x40 store");
    }
    let mov = engine88_le_u32(blob, BOSMINER_HC_PLUS230_X10_FROM_X19_VA)
        .ok_or("bosminer shorter than MOV X10,X19")?;
    if mov != BOSMINER_HC_PLUS230_X10_FROM_X19_INSN {
        return Err("0x836bd8 is not MOV X10,X19");
    }
    let mz = engine88_le_u32(blob, BOSMINER_HC_PLUS230_MOVZ10_VA)
        .ok_or("bosminer shorter than MOVZ #0x10")?;
    if mz != BOSMINER_HC_PLUS230_MOVZ10_INSN {
        return Err("0x836bec is not MOVZ W8,#0x10");
    }
    let st = engine88_le_u32(blob, BOSMINER_HC_PLUS230_STR_VA)
        .ok_or("bosminer shorter than STR #0x230")?;
    if st != BOSMINER_HC_PLUS230_STR_INSN {
        return Err("0x836bf8 is not STR X8,[X10,#0x230]");
    }
    let ret = engine88_le_u32(blob, BOSMINER_HC_PLUS230_RET_VA)
        .ok_or("bosminer shorter than set-baud RET")?;
    if ret != BOSMINER_HC_PLUS230_RET_INSN {
        return Err("0x836ca8 is not RET");
    }
    let br =
        engine88_le_u32(blob, BOSMINER_JUMP_TABLE_BR_VA).ok_or("bosminer shorter than BR X10")?;
    if br != BOSMINER_JUMP_TABLE_BR_INSN {
        return Err("0x836e78 is not BR X10 jump table");
    }
    let l238 = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_LDR238_VA)
        .ok_or("bosminer shorter than LDR #0x238")?;
    if l238 != BOSMINER_HC_PLUS230_CONSUMER_LDR238_INSN {
        return Err("0x836e8c is not LDR X9,[X8,#0x238]");
    }
    let l230 = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_LDR230_VA)
        .ok_or("bosminer shorter than consumer LDR #0x230")?;
    if l230 != BOSMINER_HC_PLUS230_CONSUMER_LDR230_INSN {
        return Err("0x836e90 is not LDR X0,[X8,#0x230]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_VT40_VA)
        .ok_or("bosminer shorter than LDR [X9,#0x40]")?;
    if vt != BOSMINER_HC_PLUS230_CONSUMER_VT40_INSN {
        return Err("0x836e94 is not LDR X8,[X9,#0x40]");
    }
    let blr = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_BLR_VA)
        .ok_or("bosminer shorter than BLR X8")?;
    if blr != BOSMINER_HC_PLUS230_CONSUMER_BLR_INSN {
        return Err("0x836e98 is not BLR X8");
    }
    let p230 = engine88_le_u32(blob, BOSMINER_C8_POLL_VT230_LDR_VA)
        .ok_or("bosminer shorter than poll LDR #0x230")?;
    if p230 != BOSMINER_C8_POLL_VT230_LDR_INSN {
        return Err("0x8dd098 is not LDR [X8,#0x230]");
    }
    let add = engine88_le_u32(blob, BOSMINER_C8_POLL_VT10_ADD_VA)
        .ok_or("bosminer shorter than poll ADD #0x10")?;
    if add != BOSMINER_C8_POLL_VT10_ADD_INSN {
        return Err("0x8dd0a4 is not ADD #0x10");
    }
    let f40 = engine88_le_u32(blob, BOSMINER_POLL_FUT40_STR_VA)
        .ok_or("bosminer shorter than STR Future+0x40")?;
    if f40 != BOSMINER_POLL_FUT40_STR_INSN {
        return Err("0x8dd0ac is not STR X8,[X19,#0x40]");
    }
    let tadrp = engine88_le_u32(blob, BOSMINER_HASHCHAIN_TICKET_ADRP_VA)
        .ok_or("bosminer shorter than :298 ADRP")?;
    if tadrp != BOSMINER_HASHCHAIN_TICKET_ADRP_INSN {
        return Err("0x838008 is not ADRP hashchain.rs:298");
    }
    let tadd = engine88_le_u32(blob, BOSMINER_HASHCHAIN_TICKET_ADD_VA)
        .ok_or("bosminer shorter than :298 ADD")?;
    if tadd != BOSMINER_HASHCHAIN_TICKET_ADD_INSN {
        return Err("0x83800c is not ADD #0x4f0 (hashchain.rs:298)");
    }
    let tbl = engine88_le_u32(blob, BOSMINER_HASHCHAIN_TICKET_BL_VA)
        .ok_or("bosminer shorter than :298 BL")?;
    if tbl != BOSMINER_HASHCHAIN_TICKET_BL_INSN {
        return Err("0x838014 is not BL 0x4536b0 (ticket-mask loc)");
    }
    Ok(())
}

/// +0x230 is not TicketMaskReg, not work_time, and poll does not mutate HashChain+0x230.
pub fn refuse_230_as_ticket_mask_or_work_time_or_poll_mutating_hc() -> Result<(), &'static str> {
    Err(
        "ticket-mask log is hashchain.rs:298:9 at 0x838008 (later jump-table, BL 0x4536b0), not the FUN_00836934 STR #0x230. work_time strings live in other modules; sibling +0x240 is the 1e8 cell. Poll LDR +0x230 then ADD #0x10 stores 0x20 at Future+0x40 (0x8dd0ac), not back into HashChain+0x230. rust field ident of the usize remains unbound",
    )
}

/// +0x230/+0x238 is a rust fat pointer; clone memcpy 0x230 then STR X0/X1;
/// jump table calls 7 vtable slots with X0=data, X9=vtable.
pub fn admit_bosminer_238_is_fat_vtable_and_clone_installs_pair(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FAT_VT_SLOT_HITS != 7 || BOSMINER_FAT_VT_SLOTS.len() != 7 {
        return Err("fat vtable slot census must stay 7");
    }
    if BOSMINER_FAT_VT_SLOTS != [0x28, 0x30, 0x38, 0x40, 0x48, 0x50, 0x78] {
        return Err("fat vtable slots drifted");
    }
    if BOSMINER_CLONE_MEMCPY_SIZE != 0x230 {
        return Err("clone memcpy size must stay 0x230");
    }
    if BOSMINER_CMD_472_LINE != 472 || BOSMINER_CMD_472_COL != 36 {
        return Err("command.rs:472:36 loc drifted");
    }
    if BOSMINER_HC_PLUS230_VT_OFF != 0x40 {
        return Err("Wave-195 slot +0x40 must remain one of the 7");
    }
    let blr = engine88_le_u32(blob, BOSMINER_FAT_BLR_VA).ok_or("bosminer shorter than BLR X23")?;
    if blr != BOSMINER_FAT_BLR_INSN {
        return Err("0x835308 is not BLR X23");
    }
    let mx0 = engine88_le_u32(blob, BOSMINER_FAT_MOV_X24_X0_VA)
        .ok_or("bosminer shorter than MOV X24,X0")?;
    if mx0 != BOSMINER_FAT_MOV_X24_X0_INSN {
        return Err("0x83530c is not MOV X24,X0");
    }
    let mx1 = engine88_le_u32(blob, BOSMINER_FAT_MOV_X23_X1_VA)
        .ok_or("bosminer shorter than MOV X23,X1")?;
    if mx1 != BOSMINER_FAT_MOV_X23_X1_INSN {
        return Err("0x835310 is not MOV X23,X1");
    }
    let mz = engine88_le_u32(blob, BOSMINER_CLONE_MEMCPY_MOVZ_VA)
        .ok_or("bosminer shorter than MOVZ #0x230")?;
    if mz != BOSMINER_CLONE_MEMCPY_MOVZ_INSN {
        return Err("0x835320 is not MOVZ W2,#0x230");
    }
    let mbl = engine88_le_u32(blob, BOSMINER_CLONE_MEMCPY_BL_VA)
        .ok_or("bosminer shorter than memcpy BL")?;
    if mbl != BOSMINER_CLONE_MEMCPY_BL_INSN {
        return Err("0x835324 is not BL FUN_00bc8fe0");
    }
    let entry = engine88_le_u32(blob, BOSMINER_CLONE_MEMCPY_FN_VA)
        .ok_or("bosminer shorter than memcpy entry")?;
    if entry != BOSMINER_CLONE_MEMCPY_ENTRY_INSN {
        return Err("0xbc8fe0 is not ADD X4,X1,X2 (memcpy)");
    }
    let s230 = engine88_le_u32(blob, BOSMINER_FAT_PAIR_STR230_VA)
        .ok_or("bosminer shorter than STR fat data")?;
    if s230 != BOSMINER_FAT_PAIR_STR230_INSN {
        return Err("0x83532c is not STR X24,[X20,#0x230]");
    }
    let s238 = engine88_le_u32(blob, BOSMINER_FAT_PAIR_STR238_VA)
        .ok_or("bosminer shorter than STR fat vtable")?;
    if s238 != BOSMINER_FAT_PAIR_STR238_INSN {
        return Err("0x835330 is not STR X23,[X20,#0x238]");
    }
    let z238 = engine88_le_u32(blob, BOSMINER_HC_PLUS238_ZERO_VA)
        .ok_or("bosminer shorter than construct STR XZR #0x238")?;
    if z238 != BOSMINER_HC_PLUS238_ZERO_INSN {
        return Err("0x836c24 is not construct STR XZR #0x238");
    }
    let s28 = engine88_le_u32(blob, BOSMINER_VT_SLOT_28_LDR_VA)
        .ok_or("bosminer shorter than vt +0x28")?;
    if s28 != BOSMINER_VT_SLOT_28_LDR_INSN {
        return Err("0x8389f8 is not LDR [X9,#0x28]");
    }
    let s30 = engine88_le_u32(blob, BOSMINER_VT_SLOT_30_LDR_VA)
        .ok_or("bosminer shorter than vt +0x30")?;
    if s30 != BOSMINER_VT_SLOT_30_LDR_INSN {
        return Err("0x837bc8 is not LDR [X9,#0x30]");
    }
    let s38 = engine88_le_u32(blob, BOSMINER_VT_SLOT_38_LDR_VA)
        .ok_or("bosminer shorter than vt +0x38")?;
    if s38 != BOSMINER_VT_SLOT_38_LDR_INSN {
        return Err("0x837668 is not LDR [X9,#0x38]");
    }
    let s40 = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_VT40_VA)
        .ok_or("bosminer shorter than vt +0x40")?;
    if s40 != BOSMINER_HC_PLUS230_CONSUMER_VT40_INSN {
        return Err("0x836e94 is not LDR [X9,#0x40]");
    }
    let s48 = engine88_le_u32(blob, BOSMINER_VT_SLOT_48_LDR_VA)
        .ok_or("bosminer shorter than vt +0x48")?;
    if s48 != BOSMINER_VT_SLOT_48_LDR_INSN {
        return Err("0x83862c is not LDR [X9,#0x48]");
    }
    let s50 = engine88_le_u32(blob, BOSMINER_VT_SLOT_50_LDR_VA)
        .ok_or("bosminer shorter than vt +0x50")?;
    if s50 != BOSMINER_VT_SLOT_50_LDR_INSN {
        return Err("0x8376fc is not LDR [X9,#0x50]");
    }
    let s78 = engine88_le_u32(blob, BOSMINER_VT_SLOT_78_LDR_VA)
        .ok_or("bosminer shorter than vt +0x78")?;
    if s78 != BOSMINER_VT_SLOT_78_LDR_INSN {
        return Err("0x837dd8 is not LDR [X9,#0x78]");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_CMD_472_ADRP_VA)
        .ok_or("bosminer shorter than command.rs:472 ADRP")?;
    if adrp != BOSMINER_CMD_472_ADRP_INSN {
        return Err("0x834ed4 is not ADRP command.rs:472");
    }
    let add = engine88_le_u32(blob, BOSMINER_CMD_472_ADD_VA)
        .ok_or("bosminer shorter than command.rs:472 ADD")?;
    if add != BOSMINER_CMD_472_ADD_INSN {
        return Err("0x834ed8 is not ADD #0xfe8 (command.rs:472)");
    }
    let shuf = engine88_le_u32(blob, BOSMINER_FUTURE_SHUFFLE_STR238_VA)
        .ok_or("bosminer shorter than Future STR #0x238")?;
    if shuf != BOSMINER_FUTURE_SHUFFLE_STR238_INSN {
        return Err("0x8dc5a4 is not Future-local STR #0x238");
    }
    Ok(())
}

/// +0x238 is not a single callback; call-time X0 is not the construct usize 0x10.
pub fn refuse_238_as_single_callback_or_x0_as_construct_usize10() -> Result<(), &'static str> {
    Err(
        "+0x238 is the vtable half of a fat pointer (data at +0x230). Clone memcpy 0x230 then STR X0/X1. Jump table calls 7 slots (0x28..0x78), not one +0x40 callback. Call-time X0 is the data half, not FUN_00836934's construct-time MOVZ #0x10. 0x8dc5a4 shuffles a Future, not this fill. Trait rust ident (Command vs Hashchip) still unbound",
    )
}

/// 6 slots STP (X0,X1); +0x50 is sret; +0x30 takes X1; command.rs:119 is the divider.
pub fn admit_bosminer_fat_slots_pair_sret_and_cmd119_is_div(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FAT_PAIR_RETURN_HITS != 6 || BOSMINER_FAT_SRET_HITS != 1 {
        return Err("fat slot return split must stay 6 pair + 1 sret");
    }
    if BOSMINER_CMD_119_LINE != 119 || BOSMINER_CMD_119_COL != 22 {
        return Err("command.rs:119:22 loc drifted");
    }
    if BOSMINER_HASHCHAIN_336_LINE != 336 || BOSMINER_HASHCHAIN_336_COL != 84 {
        return Err("hashchain.rs:336:84 loc drifted");
    }
    if BOSMINER_PACKING_40_LINE != 40 || BOSMINER_PACKING_40_COL != 23 {
        return Err("packing.rs:40:23 loc drifted");
    }
    if BOSMINER_CMD_119_ADRP_VA >= BOSMINER_WORK_RESP_DIV_FN_VA {
        return Err("command.rs:119 loc must sit before FUN_00bf3264");
    }
    if BOSMINER_HAL_COMMAND_MODULE != "bosminer_hal::command" {
        return Err("bosminer_hal::command module drifted");
    }
    if !BOSMINER_HASHCHIP_LABEL.starts_with("Hashchip") {
        return Err("Hashchip error label drifted");
    }
    if BOSMINER_READ_REGISTER_LABEL != "read_register" {
        return Err("read_register label drifted");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_X1_LDR_VA)
        .ok_or("bosminer shorter than slot+0x30 X1")?;
    if x1 != BOSMINER_FAT_SLOT30_X1_LDR_INSN {
        return Err("0x837bbc is not LDR X1,[X19,#0x10]");
    }
    let sret = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_SRET_ADD_VA)
        .ok_or("bosminer shorter than slot+0x50 sret")?;
    if sret != BOSMINER_FAT_SLOT50_SRET_ADD_INSN {
        return Err("0x837700 is not ADD X8,SP,#0x160");
    }
    let stp28 = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_STP_VA)
        .ok_or("bosminer shorter than slot+0x28 STP")?;
    if stp28 != BOSMINER_FAT_STP_28_INSN {
        return Err("0x838a00 is not STP X0,X1,[X19,#0x28]");
    }
    let stp40 = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_STP_VA)
        .ok_or("bosminer shorter than slot+0x40 STP")?;
    if stp40 != BOSMINER_FAT_STP_28_INSN {
        return Err("0x836e9c is not STP X0,X1,[X19,#0x28]");
    }
    let stp48 = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_STP_VA)
        .ok_or("bosminer shorter than slot+0x48 STP")?;
    if stp48 != BOSMINER_FAT_STP_40_INSN {
        return Err("0x838634 is not STP X0,X1,[X19,#0x40]");
    }
    let pad = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_PACK_ADRP_VA)
        .ok_or("bosminer shorter than packing.rs ADRP")?;
    if pad != BOSMINER_FAT_SLOT28_PACK_ADRP_INSN {
        return Err("0x838a10 is not ADRP packing.rs:40");
    }
    let padd = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_PACK_ADD_VA)
        .ok_or("bosminer shorter than packing.rs ADD")?;
    if padd != BOSMINER_FAT_SLOT28_PACK_ADD_INSN {
        return Err("0x838a14 is not ADD packing.rs:40");
    }
    let a336 = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_336_ADRP_VA)
        .ok_or("bosminer shorter than hashchain.rs:336 ADRP")?;
    if a336 != BOSMINER_FAT_SLOT78_336_ADRP_INSN {
        return Err("0x837e04 is not ADRP hashchain.rs:336");
    }
    let d336 = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_336_ADD_VA)
        .ok_or("bosminer shorter than hashchain.rs:336 ADD")?;
    if d336 != BOSMINER_FAT_SLOT78_336_ADD_INSN {
        return Err("0x837e08 is not ADD #0xb08 (hashchain.rs:336)");
    }
    let c119 = engine88_le_u32(blob, BOSMINER_CMD_119_ADRP_VA)
        .ok_or("bosminer shorter than command.rs:119 ADRP")?;
    if c119 != BOSMINER_CMD_119_ADRP_INSN {
        return Err("0xbf320c is not ADRP command.rs:119");
    }
    let cadd = engine88_le_u32(blob, BOSMINER_CMD_119_ADD_VA)
        .ok_or("bosminer shorter than command.rs:119 ADD")?;
    if cadd != BOSMINER_CMD_119_ADD_INSN {
        return Err("0xbf3210 is not ADD command.rs:119");
    }
    let div = engine88_le_u32(blob, BOSMINER_WORK_RESP_DIV_FN_VA)
        .ok_or("bosminer shorter than FUN_00bf3264")?;
    if div != BOSMINER_WORK_RESP_DIV_LDR_INSN {
        return Err("0xbf3264 is not LDR X8,[X0] work-resp divider");
    }
    Ok(())
}

/// Slots are not named Hashchip/Command methods; tuner write_reg is not this trait.
pub fn refuse_fat_slots_as_named_hashchip_methods() -> Result<(), &'static str> {
    Err(
        "no dyn Command / dyn Hashchip / impl Hashchip strings. Hashchip: and read_register(reg=) are command.rs error labels, not slot names. write_reg/soft_reset/reset_counters is bosminer-plus-tuner api.rs. command.rs:119 is FUN_00bf3264 work-resp divider, not the fat-pointer trait. 7 slots stay unnamed methods (6 STP pair + 1 X8 sret)",
    )
}

/// The 6 STP pairs are dyn Futures polled at vtable+0x18, not command.rs:700.
pub fn admit_bosminer_fat_pairs_are_dyn_future_poll18_not_cmd700(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_JUMP_TABLE_CMD700_BL_HITS != 0 {
        return Err("hashchain jump table must not BL FUN_008d684c");
    }
    if BOSMINER_DYN_FUT_POLL_HITS != 6 || BOSMINER_DYN_FUT_POLL_VAS.len() != 6 {
        return Err("dyn Future poll+0x18 census must stay 6");
    }
    if BOSMINER_C8_POLL_BL_HITS != 6 {
        return Err("command.rs:700 first-LOAD BL census must stay 6");
    }
    if BOSMINER_C8_POLL_FN_VA != 0x008D_684C {
        return Err("FUN_008d684c VA drifted");
    }
    if BOSMINER_DYN_FUT_POLL18_OFF != 0x18 {
        return Err("dyn Future poll slot must stay +0x18");
    }
    if BOSMINER_DYN_FUT_SRET_INSN != BOSMINER_FAT_SLOT50_SRET_ADD_INSN {
        return Err("poll sret ADD must match slot+0x50 SP+#0x160");
    }
    for &va in &BOSMINER_C8_POLL_BL_VAS {
        if (0x0083_6000..0x0083_A000).contains(&va) {
            return Err("a command.rs:700 BL sits inside the hashchain jump table");
        }
    }
    for &va in &BOSMINER_DYN_FUT_POLL_VAS {
        let ldr = engine88_le_u32(blob, va).ok_or("bosminer shorter than dyn poll LDR")?;
        if ldr != BOSMINER_DYN_FUT_POLL18_INSN {
            return Err("a dyn-poll site is not LDR X9,[X1,#0x18]");
        }
        let nxt = engine88_le_u32(blob, va + 4).ok_or("bosminer shorter than dyn poll +4")?;
        let (sret_off, mov_off, blr_off) = if nxt == BOSMINER_DYN_FUT_SRET_INSN {
            (4, 8, 12)
        } else {
            // +0x28 join inserts LDUR between LDR and ADD
            (8, 12, 16)
        };
        let sret =
            engine88_le_u32(blob, va + sret_off).ok_or("bosminer shorter than dyn poll sret")?;
        if sret != BOSMINER_DYN_FUT_SRET_INSN {
            return Err("dyn-poll site is not ADD X8,SP,#0x160");
        }
        let mv = engine88_le_u32(blob, va + mov_off).ok_or("bosminer shorter than dyn poll MOV")?;
        if mv != BOSMINER_DYN_FUT_CX_MOV_INSN {
            return Err("dyn-poll site is not MOV X1,X21");
        }
        let br = engine88_le_u32(blob, va + blr_off).ok_or("bosminer shorter than dyn poll BLR")?;
        if br != BOSMINER_DYN_FUT_BLR_INSN {
            return Err("dyn-poll site is not BLR X9");
        }
    }
    let r28 = engine88_le_u32(blob, BOSMINER_FAT_PAIR_RELOAD28_VA)
        .ok_or("bosminer shorter than reload +0x28")?;
    if r28 != BOSMINER_FAT_PAIR_RELOAD28_INSN {
        return Err("0x837054 is not LDR X0,[X19,#0x28]");
    }
    let r58 = engine88_le_u32(blob, BOSMINER_FAT_PAIR_RELOAD58_VA)
        .ok_or("bosminer shorter than reload +0x58")?;
    if r58 != BOSMINER_FAT_PAIR_RELOAD58_INSN {
        return Err("0x83757c is not LDR X0,[X19,#0x58]");
    }
    let b28 = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_JOIN_B_VA)
        .ok_or("bosminer shorter than +0x28 join B")?;
    if b28 != BOSMINER_FAT_SLOT28_JOIN_B_INSN {
        return Err("0x838a04 is not B 0x836f60");
    }
    let b40 = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_JOIN_B_VA)
        .ok_or("bosminer shorter than +0x40 join B")?;
    if b40 != BOSMINER_FAT_SLOT40_JOIN_B_INSN {
        return Err("0x836ea0 is not B 0x836fe4");
    }
    Ok(())
}

/// Pairs are not Result tag-matches and not command.rs:700 poll.
pub fn refuse_fat_pairs_as_result_or_cmd700_poll() -> Result<(), &'static str> {
    Err(
        "0 BLs to FUN_008d684c in 0x836000-0x83a000; command.rs:700's 6 BLs stay bm1366.rs:127 / bm136x.rs:107 / bm1397.rs:147. After STP the 6 pairs are polled via LDR [X1,#0x18] (dyn Future poll slot after drop/size/align) + sret SP+#0x160 + Context X21. That is not a Result discriminant match on the pair",
    )
}

/// Poll sret is 0x20 B; word0==9 is Pending; Ready T is 24 B at +0x168.
pub fn admit_bosminer_poll_sret20_pending9_t_at_168(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_POLL_PENDING_TAG != 9 {
        return Err("Poll Pending tag must stay 9");
    }
    if BOSMINER_POLL_SRET_SIZE != 0x20 {
        return Err("Poll sret size must stay 0x20");
    }
    if BOSMINER_POLL_SRET_OFF + BOSMINER_POLL_T_OFF - BOSMINER_POLL_SRET_OFF != BOSMINER_POLL_T_OFF
    {
        return Err("T offset identity");
    }
    if BOSMINER_POLL_T_OFF != 0x168 || BOSMINER_POLL_T_LEN != 0x18 {
        return Err("Ready T must stay 24 B at +0x168");
    }
    if u32::from(BOSMINER_POLL_SRET_OFF) + u32::from(BOSMINER_POLL_SRET_SIZE) != 0x180 {
        return Err("sret 0x160+0x20 must end at 0x180");
    }
    if BOSMINER_POLL_CMP9_HITS != 6 || BOSMINER_POLL_LDR160_VAS.len() != 6 {
        return Err("CMP #9 after LDR #0x160 must stay 6");
    }
    if BOSMINER_FAT_SLOT_PRE_BLR_LOC_HITS != 0 {
        return Err("pre-fat-BLR loc census must stay 0");
    }
    if BOSMINER_DYN_FUT_POLL_HITS != 6 {
        return Err("dyn poll sites must stay 6");
    }
    for &va in &BOSMINER_POLL_LDR160_VAS {
        let ldr = engine88_le_u32(blob, va).ok_or("bosminer shorter than LDR #0x160")?;
        if ldr != BOSMINER_POLL_LDR160_X27_INSN && ldr != BOSMINER_POLL_LDR160_X24_INSN {
            return Err("post-poll is not LDR [SP,#0x160]");
        }
        let cmp = engine88_le_u32(blob, va + 4).ok_or("bosminer shorter than CMP #9")?;
        if cmp != BOSMINER_POLL_CMP9_X27_INSN && cmp != BOSMINER_POLL_CMP9_X24_INSN {
            return Err("post-poll is not CMP #9");
        }
    }
    let t168 = engine88_le_u32(blob, BOSMINER_POLL_T168_VA)
        .ok_or("bosminer shorter than Ready LDR #0x168")?;
    if t168 != BOSMINER_POLL_T168_LDR_INSN {
        return Err("0x837108 is not LDR X25,[SP,#0x168]");
    }
    let t170 = engine88_le_u32(blob, BOSMINER_POLL_T170_VA)
        .ok_or("bosminer shorter than Ready LDR Q #0x170")?;
    if t170 != BOSMINER_POLL_T170_Q_INSN {
        return Err("0x83710c is not LDR Q0,[SP,#0x170]");
    }
    let mz = engine88_le_u32(blob, 0x0083_6F84).ok_or("bosminer shorter than Pending MOVZ #9")?;
    if mz != BOSMINER_POLL_PENDING_MOVZ9_INSN {
        return Err("0x836f84 is not MOVZ W8,#9");
    }
    Ok(())
}

/// Poll is not (); Pending is not 0; 6 slots are not named methods.
pub fn refuse_poll_unit_or_pending0_or_named_slot_methods() -> Result<(), &'static str> {
    Err(
        "Poll sret is 0x20 B with Pending tag 9 at word0, not Poll<()> and not std Pending=0. Ready T is 24 B at +0x168/+0x170. 0 hashchain/command locs in 0xC0 before each fat LDR238 — slot rust method names stay unbound",
    )
}

/// Classify Poll word0: 8=Ready-continue, 9=Pending-return, else Ready-return-with-T.
pub fn s19k_bosminer_poll_word0_arm(tag: u64) -> &'static str {
    match tag {
        8 => "ready_ok_continue",
        9 => "pending_return",
        _ => "ready_other_return",
    }
}

/// Pending==9 writes outer sret and RETs; Ready==8 continues; other packages T and RETs.
pub fn admit_bosminer_poll_tag8_ok_tag9_pending_ret(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_POLL_READY_OK_TAG != 8 {
        return Err("Ready-continue tag must stay 8");
    }
    if BOSMINER_POLL_PENDING_TAG != 9 {
        return Err("Pending tag must stay 9");
    }
    if BOSMINER_POLL_SUSPEND_STATE_OFF != 0x21 {
        return Err("suspend STRB must stay X19+0x21");
    }
    if BOSMINER_POLL_CMP8_HITS != 7 || BOSMINER_POLL_CMP8_VAS.len() != 7 {
        return Err("CMP #8 census must stay 7");
    }
    if BOSMINER_CMD_LOC_LINE_HITS != 27 || BOSMINER_CMD_LOC_RECORD_HITS != 104 {
        return Err("command.rs loc census drifted");
    }
    if BOSMINER_CMD_EVENT_LINES != [594, 621, 656, 675] {
        return Err("command.rs event lines drifted");
    }
    if s19k_bosminer_poll_word0_arm(8) != "ready_ok_continue" {
        return Err("tag 8 arm");
    }
    if s19k_bosminer_poll_word0_arm(9) != "pending_return" {
        return Err("tag 9 arm");
    }
    if s19k_bosminer_poll_word0_arm(0) != "ready_other_return" {
        return Err("other-tag arm");
    }
    if !BOSMINER_RUSTC_VERSION.contains("1.87.0") {
        return Err("bosminer rustc must stay 1.87.0");
    }
    let strx = engine88_le_u32(blob, BOSMINER_POLL_PENDING_STR_X28_VA)
        .ok_or("bosminer shorter than Pending STR [X28]")?;
    if strx != BOSMINER_POLL_PENDING_STR_X28_INSN {
        return Err("0x836f88 is not STR X8,[X28]");
    }
    let mz8 = engine88_le_u32(blob, BOSMINER_POLL_PENDING_MOVZ8_VA)
        .ok_or("bosminer shorter than Pending MOVZ #8")?;
    if mz8 != BOSMINER_POLL_PENDING_MOVZ8_INSN {
        return Err("0x836f8c is not MOVZ W8,#8");
    }
    let bsus = engine88_le_u32(blob, BOSMINER_POLL_PENDING_B_SUSPEND_VA)
        .ok_or("bosminer shorter than Pending B suspend")?;
    if bsus != BOSMINER_POLL_PENDING_B_SUSPEND_INSN {
        return Err("0x836f90 is not B 0x838be8");
    }
    let strb = engine88_le_u32(blob, BOSMINER_POLL_SUSPEND_VA)
        .ok_or("bosminer shorter than suspend STRB")?;
    if strb != BOSMINER_POLL_SUSPEND_STRB_INSN {
        return Err("0x838be8 is not STRB W8,[X19,#0x21]");
    }
    let addsp = engine88_le_u32(blob, BOSMINER_POLL_SUSPEND_ADDSP_VA)
        .ok_or("bosminer shorter than suspend ADD SP")?;
    if addsp != BOSMINER_POLL_SUSPEND_ADDSP_INSN {
        return Err("0x838bec is not ADD SP,#0x340");
    }
    let ret = engine88_le_u32(blob, BOSMINER_POLL_SUSPEND_RET_VA)
        .ok_or("bosminer shorter than suspend RET")?;
    if ret != BOSMINER_POLL_SUSPEND_RET_INSN {
        return Err("0x838c08 is not RET");
    }
    for &va in &BOSMINER_POLL_CMP8_VAS {
        let cmp = engine88_le_u32(blob, va).ok_or("bosminer shorter than CMP #8")?;
        if cmp != BOSMINER_POLL_CMP8_X27_INSN && cmp != BOSMINER_POLL_CMP8_X24_INSN {
            return Err("CMP #8 site drifted");
        }
    }
    let bne = engine88_le_u32(blob, BOSMINER_POLL_READY28_BNE_VA)
        .ok_or("bosminer shorter than Ready B.NE")?;
    if bne != BOSMINER_POLL_READY28_BNE_INSN {
        return Err("0x83713c is not B.NE 0x838a08");
    }
    let ej = engine88_le_u32(blob, BOSMINER_POLL_ERR_JOIN_VA)
        .ok_or("bosminer shorter than Err join LDR")?;
    if ej != BOSMINER_POLL_ERR_JOIN_LDR_INSN {
        return Err("0x838a08 is not LDR Q0,[SP,#0x30]");
    }
    let ejb = engine88_le_u32(blob, BOSMINER_POLL_ERR_JOIN_B_VA)
        .ok_or("bosminer shorter than Err join B")?;
    if ejb != BOSMINER_POLL_ERR_JOIN_B_INSN {
        return Err("0x838a0c is not B 0x838cd8");
    }
    let stp = engine88_le_u32(blob, BOSMINER_POLL_ERR_PACK_VA)
        .ok_or("bosminer shorter than Err pack STP")?;
    if stp != BOSMINER_POLL_ERR_PACK_STP_INSN {
        return Err("0x838cd8 is not STP pack");
    }
    let mz1 = engine88_le_u32(blob, BOSMINER_POLL_ERR_PACK_MOVZ1_VA)
        .ok_or("bosminer shorter than Err MOVZ #1")?;
    if mz1 != BOSMINER_POLL_ERR_PACK_MOVZ1_INSN {
        return Err("0x838cdc is not MOVZ W8,#1");
    }
    let qst = engine88_le_u32(blob, BOSMINER_POLL_ERR_PACK_STRQ_VA)
        .ok_or("bosminer shorter than Err STR Q")?;
    if qst != BOSMINER_POLL_ERR_PACK_STRQ_INSN {
        return Err("0x838ce0 is not STR Q0");
    }
    let pb = engine88_le_u32(blob, BOSMINER_POLL_ERR_PACK_B_VA)
        .ok_or("bosminer shorter than Err B suspend")?;
    if pb != BOSMINER_POLL_ERR_PACK_B_INSN {
        return Err("0x838ce4 is not B 0x838be8");
    }
    Ok(())
}

/// Tag 9 is not an unbound niche mystery; slots are still unnamed; T is unnamed.
pub fn refuse_pending9_as_unknown_or_named_slot_methods() -> Result<(), &'static str> {
    Err(
        "Pending==9 writes 9 to *X28 then MOVZ #8 and RETs through 0x838be8 (STRB X19+0x21). Ready==8 continues after Future drop. Other word0 joins 0x838cd8, packages the 24 B T, stores state 1, and RETs. That is a 3-way Poll match (Pending / Ready-continue / Ready-return-with-T), not std Pending=0 and not an unnamed niche. Slot rust method names stay unbound (0 pre-BLR locs). command.rs:594/621/656/675 are tracing events, not those methods. T rust ident stays unbound — do not name Result<Specific,E>",
    )
}

/// 7 CMP #8 = 6 post-poll Ready-Ok + 1 slot-+0x28 prelude after MOVZ W27,#8.
pub fn admit_bosminer_cmp8_six_post_poll_one_slot28_prelude(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_POLL_CMP8_HITS != 7 {
        return Err("CMP #8 census must stay 7");
    }
    if BOSMINER_POLL_CMP8_POST_POLL_HITS != 6 || BOSMINER_POLL_CMP8_PRELUDE_HITS != 1 {
        return Err("CMP #8 split must stay 6+1");
    }
    if BOSMINER_POLL_CMP8_PRELUDE_VA != 0x0083_89E4 {
        return Err("prelude CMP #8 must stay 0x8389e4");
    }
    if BOSMINER_SLOT28_PRELUDE_BL_TARGET != 0x0083_1314 {
        return Err("prelude BL target must stay 0x831314");
    }
    if BOSMINER_CMD_PANIC_PAD_LINES != [418, 514, 693, 719] {
        return Err("command.rs panic-pad lines drifted");
    }
    if BOSMINER_VT_SLOT_28_LDR_VA <= BOSMINER_POLL_CMP8_PRELUDE_VA {
        return Err("slot +0x28 LDR must sit after prelude CMP #8");
    }
    if BOSMINER_VT_SLOT_28_LDR_VA - BOSMINER_POLL_CMP8_PRELUDE_VA != 0x14 {
        return Err("prelude CMP to slot+0x28 LDR must stay 0x14");
    }
    let mz = engine88_le_u32(blob, BOSMINER_SLOT28_PRELUDE_MOVZ8_VA)
        .ok_or("bosminer shorter than prelude MOVZ W27,#8")?;
    if mz != BOSMINER_SLOT28_PRELUDE_MOVZ8_INSN {
        return Err("0x8389d0 is not MOVZ W27,#8");
    }
    let bl = engine88_le_u32(blob, BOSMINER_SLOT28_PRELUDE_BL_VA)
        .ok_or("bosminer shorter than prelude BL")?;
    if bl != BOSMINER_SLOT28_PRELUDE_BL_INSN {
        return Err("0x8389e0 is not BL 0x831314");
    }
    let cmp = engine88_le_u32(blob, BOSMINER_POLL_CMP8_PRELUDE_VA)
        .ok_or("bosminer shorter than prelude CMP #8")?;
    if cmp != BOSMINER_POLL_CMP8_X27_INSN {
        return Err("0x8389e4 is not CMP X27,#8");
    }
    for &va in &BOSMINER_POLL_CMP8_POST_POLL_VAS {
        let w = engine88_le_u32(blob, va).ok_or("bosminer shorter than post-poll CMP #8")?;
        if w != BOSMINER_POLL_CMP8_X27_INSN && w != BOSMINER_POLL_CMP8_X24_INSN {
            return Err("post-poll CMP #8 drifted");
        }
        if va == BOSMINER_POLL_CMP8_PRELUDE_VA {
            return Err("prelude VA leaked into post-poll list");
        }
    }
    Ok(())
}

/// 7th CMP #8 is not a 7th poll; +0x28 is not ticket_mask / packing.rs.
pub fn refuse_seventh_cmp8_as_seventh_poll_or_named_slot28() -> Result<(), &'static str> {
    Err(
        "0x8389e4 CMP #8 sits after MOVZ W27,#8 + BL 0x831314 and 0x14 before fat LDR [X9,#0x28]. It is the slot-+0x28 prelude, not a 7th dyn-poll Ready check. hashchain.rs:298 ticket-mask is a later log (0x838008). packing.rs:40 is the post-+0x28 panic pad. command.rs:418/514/693/719 before that log are async panic pads, not slot method names",
    )
}

/// Classify `FUN_00831314` `*(u8*)(self+0x10)` arm.
pub fn s19k_bosminer_831314_tag_arm(tag: u8) -> &'static str {
    match tag {
        3 => "drop_pair_at_18",
        4 | 6 => "tail_831d18_plus40",
        5 => "tail_831668_plus18",
        _ => "ret_noop",
    }
}

/// `FUN_00831314` is a +0x10-tag drop dispatcher; 2 BLs both pass X22.
pub fn admit_bosminer_831314_is_tag10_drop_dispatcher(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FN831314_VA != BOSMINER_SLOT28_PRELUDE_BL_TARGET {
        return Err("831314 VA must stay the +0x28 prelude BL target");
    }
    if BOSMINER_FN831314_TAG_OFF != 0x10 {
        return Err("tag must stay +0x10");
    }
    if BOSMINER_FN831314_BL_HITS != 2 || BOSMINER_FN831314_BL_VAS.len() != 2 {
        return Err("first-LOAD BL census must stay 2");
    }
    if BOSMINER_FN831314_BODY_LOC_HITS != 0 {
        return Err("831314 body loc census must stay 0");
    }
    if BOSMINER_FN831314_TAG46_TARGET != 0x0083_1D18 {
        return Err("tag 4/6 tail must stay 0x831d18");
    }
    if BOSMINER_FN831314_TAG5_TARGET != 0x0083_1668 {
        return Err("tag 5 tail must stay 0x831668");
    }
    if s19k_bosminer_831314_tag_arm(3) != "drop_pair_at_18" {
        return Err("tag 3 arm");
    }
    if s19k_bosminer_831314_tag_arm(4) != "tail_831d18_plus40"
        || s19k_bosminer_831314_tag_arm(6) != "tail_831d18_plus40"
    {
        return Err("tag 4/6 arm");
    }
    if s19k_bosminer_831314_tag_arm(5) != "tail_831668_plus18" {
        return Err("tag 5 arm");
    }
    if s19k_bosminer_831314_tag_arm(0) != "ret_noop" {
        return Err("other-tag arm");
    }
    let ent =
        engine88_le_u32(blob, BOSMINER_FN831314_VA).ok_or("bosminer shorter than 831314 entry")?;
    if ent != BOSMINER_FN831314_ENTRY_INSN {
        return Err("0x831314 is not STR X30,[SP,#-0x20]!");
    }
    let stp = engine88_le_u32(blob, BOSMINER_FN831314_STP_VA)
        .ok_or("bosminer shorter than 831314 STP")?;
    if stp != BOSMINER_FN831314_STP_INSN {
        return Err("0x831318 is not STP X20,X19");
    }
    let ldb = engine88_le_u32(blob, BOSMINER_FN831314_LDRB10_VA)
        .ok_or("bosminer shorter than 831314 LDRB +0x10")?;
    if ldb != BOSMINER_FN831314_LDRB10_INSN {
        return Err("0x83131c is not LDRB [X0,#0x10]");
    }
    let c4 =
        engine88_le_u32(blob, BOSMINER_FN831314_CMP4_VA).ok_or("bosminer shorter than CMP #4")?;
    if c4 != BOSMINER_FN831314_CMP4_INSN {
        return Err("0x831320 is not CMP W8,#4");
    }
    let c3 =
        engine88_le_u32(blob, BOSMINER_FN831314_CMP3_VA).ok_or("bosminer shorter than CMP #3")?;
    if c3 != BOSMINER_FN831314_CMP3_INSN {
        return Err("0x831328 is not CMP W8,#3");
    }
    let add40 = engine88_le_u32(blob, BOSMINER_FN831314_TAG46_ADD40_VA)
        .ok_or("bosminer shorter than ADD #0x40")?;
    if add40 != BOSMINER_FN831314_TAG46_ADD40_INSN {
        return Err("0x83135c is not ADD X0,#0x40");
    }
    let b46 = engine88_le_u32(blob, BOSMINER_FN831314_TAG46_B_VA)
        .ok_or("bosminer shorter than B 0x831d18")?;
    if b46 != BOSMINER_FN831314_TAG46_B_INSN {
        return Err("0x831364 is not B 0x831d18");
    }
    let add18 = engine88_le_u32(blob, BOSMINER_FN831314_TAG5_ADD18_VA)
        .ok_or("bosminer shorter than ADD #0x18")?;
    if add18 != BOSMINER_FN831314_TAG5_ADD18_INSN {
        return Err("0x8313a8 is not ADD X0,#0x18");
    }
    let ret = engine88_le_u32(blob, BOSMINER_FN831314_RET_VA)
        .ok_or("bosminer shorter than 831314 RET")?;
    if ret != BOSMINER_FN831314_RET_INSN {
        return Err("0x8313a0 is not RET");
    }
    let bl1 = engine88_le_u32(blob, BOSMINER_FN831314_BL_VAS[0])
        .ok_or("bosminer shorter than prelude BL")?;
    if bl1 != BOSMINER_SLOT28_PRELUDE_BL_INSN {
        return Err("0x8389e0 is not BL 0x831314");
    }
    let mv1 = engine88_le_u32(blob, BOSMINER_FN831314_BL_VAS[0] - 4)
        .ok_or("bosminer shorter than prelude MOV X0,X22")?;
    if mv1 != BOSMINER_FN831314_MOV_X0_X22_INSN {
        return Err("0x8389dc is not MOV X0,X22");
    }
    let bl2 = engine88_le_u32(blob, BOSMINER_FN831314_BL_VAS[1])
        .ok_or("bosminer shorter than second BL")?;
    if bl2 != BOSMINER_FN831314_BL2_INSN {
        return Err("0x838b90 is not BL 0x831314");
    }
    let mv2 = engine88_le_u32(blob, BOSMINER_FN831314_MOV2_VA)
        .ok_or("bosminer shorter than second MOV X0,X22")?;
    if mv2 != BOSMINER_FN831314_MOV_X0_X22_INSN {
        return Err("0x838b8c is not MOV X0,X22");
    }
    Ok(())
}

/// 831314 is not the +0x28 slot method and not MaybeDone by string.
pub fn refuse_831314_as_slot28_method_or_named_maybedone() -> Result<(), &'static str> {
    Err(
        "FUN_00831314 is a drop dispatcher on *(u8*)(X0+0x10): tag3 drops the pair at +0x18; tag4/6 tail-call 0x831d18(X0+0x40); tag5 tail-call 0x831668(X0+0x18); else RET. Exactly 2 first-LOAD BLs, both MOV X0,X22. 0 locs in the body. MaybeDone is a futures-util string elsewhere, not a loc for this fn. It is not the fat slot +0x28 method, not ticket_mask, not send_work",
    )
}

/// Tag byte offset for a  drop sibling, or None if not one of them.
pub fn s19k_bosminer_drop_sib_tag_off(fn_va: u64) -> Option<u16> {
    if fn_va == BOSMINER_FN831D18_VA {
        Some(BOSMINER_FN831D18_TAG_OFF)
    } else if fn_va == BOSMINER_FN831668_VA {
        Some(BOSMINER_FN831668_TAG_OFF)
    } else {
        None
    }
}

/// 831d18 / 831668 are isomorphic drop helpers at different field offsets.
pub fn admit_bosminer_831d18_831668_are_drop_siblings(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FN831D18_VA != BOSMINER_FN831314_TAG46_TARGET {
        return Err("831d18 must stay the tag4/6 tail target");
    }
    if BOSMINER_FN831668_VA != BOSMINER_FN831314_TAG5_TARGET {
        return Err("831668 must stay the tag5 tail target");
    }
    if BOSMINER_FN831D18_TAG_OFF == BOSMINER_FN831668_TAG_OFF {
        return Err("siblings must not share a tag offset");
    }
    if BOSMINER_FN831D18_BL_HITS != 12 || BOSMINER_FN831668_BL_HITS != 6 {
        return Err("drop-sibling BL census drifted");
    }
    if BOSMINER_DROP_SIB_BODY_LOC_HITS != 0 {
        return Err("drop-sibling body loc census must stay 0");
    }
    if BOSMINER_FN831D18_HC68_HITS != 4 || BOSMINER_FN831D18_HC68_VAS.len() != 4 {
        return Err("HashChain+0x68 drop sites must stay 4");
    }
    if s19k_bosminer_drop_sib_tag_off(BOSMINER_FN831D18_VA) != Some(0x19) {
        return Err("831d18 tag off");
    }
    if s19k_bosminer_drop_sib_tag_off(BOSMINER_FN831668_VA) != Some(0x70) {
        return Err("831668 tag off");
    }
    if s19k_bosminer_drop_sib_tag_off(BOSMINER_FN831314_VA).is_some() {
        return Err("831314 is not a drop sibling");
    }
    for &(va, entry, ldrb, want_ldrb, cmp3, ldp, want_ldp, ldr, want_ldr, blh, want_blh, ret) in &[
        (
            BOSMINER_FN831D18_VA,
            BOSMINER_DROP_SIB_ENTRY_INSN,
            BOSMINER_FN831D18_VA + 8,
            BOSMINER_FN831D18_LDRB_INSN,
            BOSMINER_FN831D18_VA + 0x10,
            BOSMINER_FN831D18_VA + 0x20,
            BOSMINER_FN831D18_LDP_INSN,
            BOSMINER_FN831D18_VA + 0x48,
            BOSMINER_FN831D18_LDR0_INSN,
            BOSMINER_FN831D18_BL_HELPER_VA,
            BOSMINER_FN831D18_BL_HELPER_INSN,
            BOSMINER_FN831D18_RET_VA,
        ),
        (
            BOSMINER_FN831668_VA,
            BOSMINER_DROP_SIB_ENTRY_INSN,
            BOSMINER_FN831668_VA + 8,
            BOSMINER_FN831668_LDRB_INSN,
            BOSMINER_FN831668_VA + 0x10,
            BOSMINER_FN831668_VA + 0x20,
            BOSMINER_FN831668_LDP_INSN,
            BOSMINER_FN831668_VA + 0x48,
            BOSMINER_FN831668_LDR68_INSN,
            BOSMINER_FN831668_BL_HELPER_VA,
            BOSMINER_FN831668_BL_HELPER_INSN,
            BOSMINER_FN831668_RET_VA,
        ),
    ] {
        let e = engine88_le_u32(blob, va).ok_or("bosminer shorter than drop-sib entry")?;
        if e != entry {
            return Err("drop sibling entry is not STP X30,X21,[SP,#-0x20]!");
        }
        let lb = engine88_le_u32(blob, ldrb).ok_or("bosminer shorter than drop-sib LDRB")?;
        if lb != want_ldrb {
            return Err("drop sibling LDRB tag drifted");
        }
        let c3 = engine88_le_u32(blob, cmp3).ok_or("bosminer shorter than drop-sib CMP #3")?;
        if c3 != BOSMINER_DROP_SIB_CMP3_INSN {
            return Err("drop sibling CMP #3 drifted");
        }
        let c4 = engine88_le_u32(blob, cmp3 + 8).ok_or("bosminer shorter than drop-sib CMP #4")?;
        if c4 != BOSMINER_DROP_SIB_CMP4_INSN {
            return Err("drop sibling CMP #4 drifted");
        }
        let lp = engine88_le_u32(blob, ldp).ok_or("bosminer shorter than drop-sib LDP")?;
        if lp != want_ldp {
            return Err("drop sibling LDP pair drifted");
        }
        let ld = engine88_le_u32(blob, ldr).ok_or("bosminer shorter than drop-sib helper LDR")?;
        if ld != want_ldr {
            return Err("drop sibling helper LDR drifted");
        }
        let mz = engine88_le_u32(blob, ldr + 4).ok_or("bosminer shorter than MOVZ W1,#1")?;
        if mz != BOSMINER_DROP_SIB_MOVZ1_INSN {
            return Err("drop sibling is not MOVZ W1,#1");
        }
        let bh = engine88_le_u32(blob, blh).ok_or("bosminer shorter than BL 0x11f2764")?;
        if bh != want_blh {
            return Err("drop sibling is not BL 0x11f2764");
        }
        let rt = engine88_le_u32(blob, ret).ok_or("bosminer shorter than drop-sib RET")?;
        if rt != 0xD65F_03C0 {
            return Err("drop sibling RET drifted");
        }
    }
    for &va in &BOSMINER_FN831D18_HC68_VAS {
        let add = engine88_le_u32(blob, va - 4).ok_or("bosminer shorter than ADD #0x68")?;
        if add != BOSMINER_FN831D18_HC68_ADD_INSN {
            return Err("HashChain+0x68 site is not ADD X0,X19,#0x68");
        }
    }
    Ok(())
}

/// Siblings are not one function, not slot methods, not named Arc/drop_in_place.
pub fn refuse_drop_sibs_as_one_fn_or_named_slot_or_arc() -> Result<(), &'static str> {
    Err(
        "831d18 tags at +0x19 and drops the pair at +0x20 then 0x11f2764(*self); 831668 tags at +0x70 and drops the pair at +0x78 then 0x11f2764(*self+0x68). Same CMP #3/#4 shape, different field maps — not one function. 12 vs 6 first-LOAD BLs. 0 locs in either body. 0x11f2764 is a shared W1=#1 helper (CBZ X1 then LDXR), not a proven Arc::drop ident. Neither is a fat-slot Command method",
    )
}

/// 1e9 cap used by `FUN_0011f2764`'s overflow arm.
pub fn s19k_bosminer_refcount_overflow_cap() -> u32 {
    1_000_000_000
}

/// `FUN_0011f2764` is a refcount helper; jump-table +0x68 is `*(*X19)+0x240+0x10`.
pub fn admit_bosminer_11f2764_is_refcount_helper_jt68_from_240(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FN11F2764_VA != BOSMINER_DROP_SIB_HELPER_VA {
        return Err("11f2764 must stay the drop-sibling helper");
    }
    if BOSMINER_FN11F2764_BL_HITS != 557 {
        return Err("11f2764 BL census must stay 557");
    }
    if BOSMINER_FN11F2764_MOVZ1_PREV_HITS != 537 {
        return Err("MOVZ W1,#1 previous census must stay 537");
    }
    if BOSMINER_FN11F2764_MOVZ1_PREV_HITS > BOSMINER_FN11F2764_BL_HITS {
        return Err("prev-#1 hits cannot exceed BL hits");
    }
    if s19k_bosminer_refcount_overflow_cap() != 1_000_000_000 {
        return Err("overflow cap must stay 1e9");
    }
    if BOSMINER_REFCOUNT_OVERFLOW_MSG != "reference count overflow!" {
        return Err("overflow message drifted");
    }
    if BOSMINER_FN11F26F8_TO_764_DELTA != 0x6C {
        return Err("11f26f8 must stay 0x6c before 11f2764");
    }
    if BOSMINER_F11F26F8_FN_VA + u64::from(BOSMINER_FN11F26F8_TO_764_DELTA) != BOSMINER_FN11F2764_VA
    {
        return Err("11f26f8+0x6c must be 11f2764");
    }
    if BOSMINER_JT_PLUS108_OFF != 0x108 {
        return Err("+0x108 tag off drifted");
    }
    let cbz =
        engine88_le_u32(blob, BOSMINER_FN11F2764_VA).ok_or("bosminer shorter than 11f2764 CBZ")?;
    if cbz != BOSMINER_FN11F2764_CBZ_INSN {
        return Err("0x11f2764 is not CBZ X1,RET");
    }
    let ldx =
        engine88_le_u32(blob, BOSMINER_FN11F2764_LDXR_VA).ok_or("bosminer shorter than LDXR")?;
    if ldx != BOSMINER_FN11F2764_LDXR_INSN {
        return Err("0x11f2770 is not LDXR W8,[X0]");
    }
    let cbnz =
        engine88_le_u32(blob, BOSMINER_FN11F2764_CBNZ0_VA).ok_or("bosminer shorter than CBNZ")?;
    if cbnz != BOSMINER_FN11F2764_CBNZ0_INSN {
        return Err("0x11f277c is not CBNZ W8,overflow");
    }
    let mz1 = engine88_le_u32(blob, BOSMINER_FN11F2764_STXR1_VA)
        .ok_or("bosminer shorter than MOVZ #1")?;
    if mz1 != BOSMINER_FN11F2764_STXR1_MOVZ_INSN {
        return Err("0x11f2780 is not MOVZ W8,#1");
    }
    let stxr =
        engine88_le_u32(blob, BOSMINER_FN11F2764_STXR_VA).ok_or("bosminer shorter than STXR")?;
    if stxr != BOSMINER_FN11F2764_STXR_INSN {
        return Err("0x11f2784 is not STXR");
    }
    let ret = engine88_le_u32(blob, BOSMINER_FN11F2764_RET_VA)
        .ok_or("bosminer shorter than 11f2764 RET")?;
    if ret != BOSMINER_FN11F2764_RET_INSN {
        return Err("0x11f27ac is not RET");
    }
    let omz = engine88_le_u32(blob, BOSMINER_FN11F2764_OVF_MOVZ_VA)
        .ok_or("bosminer shorter than overflow MOVZ")?;
    if omz != BOSMINER_FN11F2764_OVF_MOVZ_INSN {
        return Err("0x11f27b4 is not MOVZ W2,#0xca00");
    }
    let omk = engine88_le_u32(blob, BOSMINER_FN11F2764_OVF_MOVK_VA)
        .ok_or("bosminer shorter than overflow MOVK")?;
    if omk != BOSMINER_FN11F2764_OVF_MOVK_INSN {
        return Err("0x11f27bc is not MOVK W2,#0x3b9a");
    }
    let obl = engine88_le_u32(blob, BOSMINER_FN11F2764_OVF_BL_VA)
        .ok_or("bosminer shorter than overflow BL")?;
    if obl != BOSMINER_FN11F2764_OVF_BL_INSN {
        return Err("0x11f27c0 is not BL 0x44e4a0");
    }
    let src = engine88_le_u32(blob, BOSMINER_JT_PLUS68_SRC240_VA)
        .ok_or("bosminer shorter than LDR #0x240")?;
    if src != BOSMINER_JT_PLUS68_SRC240_INSN {
        return Err("0x8385f4 is not LDR [X8,#0x240]");
    }
    let add = engine88_le_u32(blob, BOSMINER_JT_PLUS68_ADD10_VA)
        .ok_or("bosminer shorter than ADD #0x10")?;
    if add != BOSMINER_JT_PLUS68_ADD10_INSN {
        return Err("0x838600 is not ADD X0,#0x10");
    }
    let st = engine88_le_u32(blob, BOSMINER_JT_PLUS68_STR_VA)
        .ok_or("bosminer shorter than STR #0x68")?;
    if st != BOSMINER_JT_PLUS68_STR_INSN {
        return Err("0x838604 is not STR X0,[X19,#0x68]");
    }
    Ok(())
}

/// 11f2764 is not Arc::drop / increment_strong_count; +0x68 is not HashChain.
pub fn refuse_11f2764_as_named_arc_or_jt68_as_hashchain() -> Result<(), &'static str> {
    Err(
        "FUN_0011f2764 is a refcount helper (CBZ X1; LDXR [X0]; 0→STXR 1; else W2=1e9 BL 0x44e4a0). 557 BLs, 537 MOVZ W1,#1. That is not a proven Arc::drop or increment_strong_count ident — 0x121e588 (TLS/TPIDR) sits on both arms and is unnamed. FUN_011f26f8 is 0x6c earlier and zeros+tags, not this fn. 0x44e4a0's nearby loc is parking_lot.rs:363, not the overflow string. Jump-table X19+0x68 is *(*X19)+0x240+0x10, dropped when X19+0x108==3 — X19 is the jump-table frame, not a proven HashChain field",
    )
}

/// TLS slot offset for `FUN_0121e588` (`TPIDR_EL0 + 0x280`).
pub fn s19k_bosminer_121e588_tls_off() -> u16 {
    BOSMINER_FN121E588_TLS_OFF
}

/// `FUN_0121e588` is parking_lot TLS get; 11f2764 is not Arc inc/drop.
pub fn admit_bosminer_121e588_is_parking_lot_tls(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FN121E588_TLS_OFF != 0x280 {
        return Err("TLS offset must stay 0x280");
    }
    if BOSMINER_FN121E588_BL_HITS != 681 {
        return Err("121e588 BL census must stay 681");
    }
    if BOSMINER_PARK_1226_LINE != 1226 || BOSMINER_PARK_1226_COL != 58 {
        return Err("parking_lot.rs:1226:58 loc drifted");
    }
    if !BOSMINER_PARK_RS_SUFFIX.ends_with("parking_lot.rs") {
        return Err("parking_lot.rs suffix");
    }
    if BOSMINER_FN11F2764_TLS_BL_VA <= BOSMINER_FN11F2764_VA {
        return Err("TLS BL must sit inside 11f2764");
    }
    if s19k_bosminer_121e588_tls_off() != 0x280 {
        return Err("tls_off helper");
    }
    let ent = engine88_le_u32(blob, BOSMINER_FN121E588_VA)
        .ok_or("bosminer shorter than 121e588 entry")?;
    if ent != BOSMINER_FN121E588_ENTRY_INSN {
        return Err("0x121e588 entry drifted");
    }
    let mv = engine88_le_u32(blob, BOSMINER_FN121E588_MOV_X19_VA)
        .ok_or("bosminer shorter than MOV X19,X0")?;
    if mv != BOSMINER_FN121E588_MOV_X19_INSN {
        return Err("0x121e594 is not MOV X19,X0");
    }
    let mz =
        engine88_le_u32(blob, BOSMINER_FN121E588_MOVZ_VA).ok_or("bosminer shorter than MOVZ X0")?;
    if mz != BOSMINER_FN121E588_MOVZ_INSN {
        return Err("0x121e59c is not MOVZ X0,#0,LSL#16");
    }
    let mk = engine88_le_u32(blob, BOSMINER_FN121E588_MOVK_VA)
        .ok_or("bosminer shorter than MOVK #0x280")?;
    if mk != BOSMINER_FN121E588_MOVK_INSN {
        return Err("0x121e5a0 is not MOVK X0,#0x280");
    }
    let mrs = engine88_le_u32(blob, BOSMINER_FN121E588_MRS_VA)
        .ok_or("bosminer shorter than MRS TPIDR_EL0")?;
    if mrs != BOSMINER_FN121E588_MRS_INSN {
        return Err("0x121e5ac is not MRS X8,TPIDR_EL0");
    }
    let add = engine88_le_u32(blob, BOSMINER_FN121E588_ADD_VA)
        .ok_or("bosminer shorter than ADD X20,X8,X0")?;
    if add != BOSMINER_FN121E588_ADD_INSN {
        return Err("0x121e5b0 is not ADD X20,X8,X0");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_FN121E588_LDR_VA)
        .ok_or("bosminer shorter than LDR post #8")?;
    if ldr != BOSMINER_FN121E588_LDR_INSN {
        return Err("0x121e5b4 is not LDR X9,[X20],#8");
    }
    let c1 =
        engine88_le_u32(blob, BOSMINER_FN121E588_CMP1_VA).ok_or("bosminer shorter than CMP #1")?;
    if c1 != BOSMINER_FN121E588_CMP1_INSN {
        return Err("0x121e5b8 is not CMP X9,#1");
    }
    let c2 =
        engine88_le_u32(blob, BOSMINER_FN121E588_CMP2_VA).ok_or("bosminer shorter than CMP #2")?;
    if c2 != BOSMINER_FN121E588_CMP2_INSN {
        return Err("0x121e5c0 is not CMP X9,#2");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_PARK_1226_ADRP_VA)
        .ok_or("bosminer shorter than parking_lot ADRP")?;
    if adrp != BOSMINER_PARK_1226_ADRP_INSN {
        return Err("0x121e610 is not ADRP parking_lot.rs:1226");
    }
    let addl = engine88_le_u32(blob, BOSMINER_PARK_1226_ADD_VA)
        .ok_or("bosminer shorter than parking_lot ADD")?;
    if addl != BOSMINER_PARK_1226_ADD_INSN {
        return Err("0x121e614 is not ADD #0xc70");
    }
    let ret = engine88_le_u32(blob, BOSMINER_FN121E588_RET_VA)
        .ok_or("bosminer shorter than 121e588 RET")?;
    if ret != BOSMINER_FN121E588_RET_INSN {
        return Err("0x121e688 is not RET");
    }
    let bl = engine88_le_u32(blob, BOSMINER_FN11F2764_TLS_BL_VA)
        .ok_or("bosminer shorter than 11f2764→121e588 BL")?;
    if bl != BOSMINER_FN11F2764_TLS_BL_INSN {
        return Err("0x11f2790 is not BL 0x121e588");
    }
    Ok(())
}

/// 121e588 is not Arc inc/drop; 11f2764 is not Arc after the TLS bind.
pub fn refuse_121e588_as_arc_inc_or_drop() -> Result<(), &'static str> {
    Err(
        "FUN_0121e588 is parking_lot_core-0.9.10 TLS get: MRS TPIDR_EL0 + ADD #0x280, CMP TLS tag #1/#2, loc parking_lot.rs:1226:58, 681 BLs. That is ThreadData/Parker lookup, not Arc::increment_strong_count or Arc::drop. Therefore 11f2764 (0→1 STXR then BL 0x121e588) is lock-word/park family, not Arc inc/drop",
    )
}

/// Fat-slot +0x28 does not take an extra X1 argument.
pub fn s19k_bosminer_slot28_extra_x1() -> bool {
    BOSMINER_FAT_SLOT28_X1_WRITES != 0
}

/// +0x28 BLR is the unique zero-arg fat Future call in the jump table.
pub fn admit_bosminer_slot28_is_zero_arg_fat_future(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FAT_SLOT28_PATTERN_HITS != 1 {
        return Err("fat+0x28 pattern must stay unique in the jump table");
    }
    if BOSMINER_FAT_SLOT28_X1_WRITES != 0 {
        return Err("slot +0x28 must not write X1 before BLR");
    }
    if s19k_bosminer_slot28_extra_x1() {
        return Err("slot28 extra X1 helper");
    }
    if BOSMINER_FAT_SLOT28_JOIN_TARGET != 0x0083_6F60 {
        return Err("join target must stay 0x836f60");
    }
    if BOSMINER_FAT_SLOT28_BLR_VA != BOSMINER_VT_SLOT_28_LDR_VA + 4 {
        return Err("BLR must sit immediately after LDR [X9,#0x28]");
    }
    if BOSMINER_FAT_SLOT28_STP_VA != BOSMINER_FAT_SLOT28_BLR_VA + 4 {
        return Err("STP pair must sit immediately after BLR");
    }
    let slf = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_SELF_LDR_VA)
        .ok_or("bosminer shorter than LDR [X19]")?;
    if slf != BOSMINER_FAT_SLOT28_SELF_LDR_INSN {
        return Err("0x8389ec is not LDR X8,[X19]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_VT_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x238")?;
    if vt != BOSMINER_FAT_SLOT28_VT_LDR_INSN {
        return Err("0x8389f0 is not LDR X9,[X8,#0x238]");
    }
    let data = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_DATA_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if data != BOSMINER_FAT_SLOT28_DATA_LDR_INSN {
        return Err("0x8389f4 is not LDR X0,[X8,#0x230]");
    }
    let mth = engine88_le_u32(blob, BOSMINER_VT_SLOT_28_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x28")?;
    if mth != BOSMINER_VT_SLOT_28_LDR_INSN {
        return Err("0x8389f8 is not LDR X8,[X9,#0x28]");
    }
    let br =
        engine88_le_u32(blob, BOSMINER_FAT_SLOT28_BLR_VA).ok_or("bosminer shorter than BLR X8")?;
    if br != BOSMINER_FAT_SLOT28_BLR_INSN {
        return Err("0x8389fc is not BLR X8");
    }
    let stp = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_STP_VA)
        .ok_or("bosminer shorter than STP pair")?;
    if stp != BOSMINER_FAT_STP_28_INSN {
        return Err("0x838a00 is not STP X0,X1,[X19,#0x28]");
    }
    let join = engine88_le_u32(blob, BOSMINER_FAT_SLOT28_JOIN_B_VA)
        .ok_or("bosminer shorter than join B")?;
    if join != BOSMINER_FAT_SLOT28_JOIN_B_INSN {
        return Err("0x838a04 is not B 0x836f60");
    }
    Ok(())
}

/// +0x28 is not a named Command method; packing.rs:40 is the panic pad.
pub fn refuse_slot28_as_named_command_or_packing() -> Result<(), &'static str> {
    Err(
        "Fat-slot +0x28 is the unique +0x238/+0x230/+0x28/BLR call in 0x836000-0x83a000. X0 is fat data; 0 X1 writes before BLR — not the +0x30 method (that LDR X1 from Future+0x10). packing.rs:40:23 at 0x838a10 is the post-join panic pad, not the method. hashchain.rs:298 ticket-mask is a later log. No send_work/set_baud/ticket_mask loc at the BLR",
    )
}

/// Fat-slot +0x30 takes exactly one extra X1 argument from Future+0x10.
pub fn s19k_bosminer_slot30_extra_x1() -> bool {
    BOSMINER_FAT_SLOT30_X1_WRITES != 0
}

/// +0x30 BLR is the unique X1-taking fat Future call in the jump table.
pub fn admit_bosminer_slot30_is_x1_arg_fat_future(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FAT_SLOT30_PATTERN_HITS != 1 {
        return Err("fat+0x30 pattern must stay unique in the jump table");
    }
    if BOSMINER_FAT_SLOT30_X1_WRITES != 1 {
        return Err("slot +0x30 must write X1 once before BLR");
    }
    if !s19k_bosminer_slot30_extra_x1() {
        return Err("slot30 extra X1 helper");
    }
    if BOSMINER_FAT_SLOT30_JOIN_TARGET != BOSMINER_FAT_PAIR_RELOAD28_VA {
        return Err("join target must stay 0x837054");
    }
    if BOSMINER_FAT_SLOT30_BLR_VA != BOSMINER_VT_SLOT_30_LDR_VA + 4 {
        return Err("BLR must sit immediately after LDR [X9,#0x30]");
    }
    if BOSMINER_FAT_SLOT30_STP_VA != BOSMINER_FAT_SLOT30_BLR_VA + 4 {
        return Err("STP pair must sit immediately after BLR");
    }
    if BOSMINER_FAT_SLOT30_JOIN_B_VA != BOSMINER_FAT_SLOT30_STP_VA + 4 {
        return Err("join B must sit immediately after STP");
    }
    if BOSMINER_FAT_SLOT30_PRE_BLR_LOC_HITS != 0 {
        return Err("pre-BLR command.rs/hashchain.rs loc census drifted");
    }
    let slf = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_SELF_LDR_VA)
        .ok_or("bosminer shorter than LDR [X19]")?;
    if slf != BOSMINER_FAT_SLOT30_SELF_LDR_INSN {
        return Err("0x837bb8 is not LDR X8,[X19]");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_X1_LDR_VA)
        .ok_or("bosminer shorter than LDR X1 Future+0x10")?;
    if x1 != BOSMINER_FAT_SLOT30_X1_LDR_INSN {
        return Err("0x837bbc is not LDR X1,[X19,#0x10]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_VT_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x238")?;
    if vt != BOSMINER_FAT_SLOT30_VT_LDR_INSN {
        return Err("0x837bc0 is not LDR X9,[X8,#0x238]");
    }
    let data = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_DATA_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if data != BOSMINER_FAT_SLOT30_DATA_LDR_INSN {
        return Err("0x837bc4 is not LDR X0,[X8,#0x230]");
    }
    let mth = engine88_le_u32(blob, BOSMINER_VT_SLOT_30_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x30")?;
    if mth != BOSMINER_VT_SLOT_30_LDR_INSN {
        return Err("0x837bc8 is not LDR X8,[X9,#0x30]");
    }
    let br =
        engine88_le_u32(blob, BOSMINER_FAT_SLOT30_BLR_VA).ok_or("bosminer shorter than BLR X8")?;
    if br != BOSMINER_FAT_SLOT30_BLR_INSN {
        return Err("0x837bcc is not BLR X8");
    }
    let stp = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_STP_VA)
        .ok_or("bosminer shorter than STP pair")?;
    if stp != BOSMINER_FAT_STP_28_INSN {
        return Err("0x837bd0 is not STP X0,X1,[X19,#0x28]");
    }
    let join = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_JOIN_B_VA)
        .ok_or("bosminer shorter than join B")?;
    if join != BOSMINER_FAT_SLOT30_JOIN_B_INSN {
        return Err("0x837bd4 is not B 0x837054");
    }
    let reload = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_JOIN_TARGET)
        .ok_or("bosminer shorter than join reload")?;
    if reload != BOSMINER_FAT_PAIR_RELOAD28_INSN {
        return Err("0x837054 is not LDR X0,[X19,#0x28]");
    }
    let other = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_OTHER_LDR30_VA)
        .ok_or("bosminer shorter than other LDR #0x30")?;
    if other != BOSMINER_FAT_SLOT30_OTHER_LDR30_INSN {
        return Err("0x839d9c is not LDR X8,[X22,#0x30]");
    }
    Ok(())
}

/// +0x30 is not send_work/set_baud/write_register; 0x839d9c is not the fat slot.
pub fn refuse_slot30_as_named_send_work_or_other_ldr30() -> Result<(), &'static str> {
    Err(
        "Fat-slot +0x30 is the unique +0x238/+0x230/+0x30/BLR call in 0x836000-0x83a000. X0 is fat data; one X1 write is LDR X1,[X19,#0x10] (Future+0x10) — not the zero-arg +0x28 method. 0 command.rs/hashchain.rs locs in 0xC0 before the BLR. send_work/set_baud/write_register strings are absent. 0x839d9c is LDR X8,[X22,#0x30] then BLR, not the fat vtable slot",
    )
}

/// Jump-table poll-self frame+0x10 has no in-body STR writer.
pub fn s19k_bosminer_frame10_str_hits() -> usize {
    BOSMINER_FRAME10_STR_HITS
}

/// Slot +0x30 X1 is poll-self frame+0x10 (construct-time capture).
pub fn admit_bosminer_slot30_x1_is_poll_self_frame10(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FRAME10_STR_HITS != 0 {
        return Err("jump-table must keep 0 STR [X19,#0x10]");
    }
    if s19k_bosminer_frame10_str_hits() != 0 {
        return Err("frame10 STR helper");
    }
    if BOSMINER_FRAME10_ERR_TARGET != BOSMINER_POLL_ERR_PACK_VA {
        return Err("frame+0x10 Err consumer must join Wave-200 pack");
    }
    if BOSMINER_JT_POLL_X19_MOV_VA + 4 != BOSMINER_JUMP_TABLE_BR_VA {
        return Err("MOV X19,X0 must sit immediately before BR X10");
    }
    let cx = engine88_le_u32(blob, BOSMINER_JT_POLL_CX_MOV_VA)
        .ok_or("bosminer shorter than MOV X21,X1")?;
    if cx != BOSMINER_JT_POLL_CX_MOV_INSN {
        return Err("0x836e70 is not MOV X21,X1");
    }
    let slf = engine88_le_u32(blob, BOSMINER_JT_POLL_X19_MOV_VA)
        .ok_or("bosminer shorter than MOV X19,X0")?;
    if slf != BOSMINER_JT_POLL_X19_MOV_INSN {
        return Err("0x836e74 is not MOV X19,X0");
    }
    let br =
        engine88_le_u32(blob, BOSMINER_JUMP_TABLE_BR_VA).ok_or("bosminer shorter than BR X10")?;
    if br != BOSMINER_JUMP_TABLE_BR_INSN {
        return Err("0x836e78 is not BR X10");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_FAT_SLOT30_X1_LDR_VA)
        .ok_or("bosminer shorter than slot30 X1 LDR")?;
    if x1 != BOSMINER_FAT_SLOT30_X1_LDR_INSN {
        return Err("0x837bbc is not LDR X1,[X19,#0x10]");
    }
    let err = engine88_le_u32(blob, BOSMINER_FRAME10_ERR_LDR_VA)
        .ok_or("bosminer shorter than frame10 Err LDR")?;
    if err != BOSMINER_FRAME10_ERR_LDR_INSN {
        return Err("0x8371b8 is not LDR X25,[X19,#0x10]");
    }
    let jb = engine88_le_u32(blob, BOSMINER_FRAME10_ERR_B_VA)
        .ok_or("bosminer shorter than frame10 Err B")?;
    if jb != BOSMINER_FRAME10_ERR_B_INSN {
        return Err("0x8371bc is not B 0x838cd8");
    }
    let pack = engine88_le_u32(blob, BOSMINER_FRAME10_ERR_TARGET)
        .ok_or("bosminer shorter than Err pack")?;
    if pack != BOSMINER_POLL_ERR_PACK_STP_INSN {
        return Err("0x838cd8 is not the Wave-200 Err STP pack");
    }
    let hc = engine88_le_u32(blob, BOSMINER_HC_OBJ_STP10_VA)
        .ok_or("bosminer shorter than HashChain STP +0x10")?;
    if hc != BOSMINER_HC_OBJ_STP10_INSN {
        return Err("0x836b94 is not STP [X20,#0x10] HashChain object init");
    }
    let ret = engine88_le_u32(blob, BOSMINER_HC_PLUS230_RET_VA)
        .ok_or("bosminer shorter than HashChain-init RET")?;
    if ret != BOSMINER_HC_PLUS230_RET_INSN {
        return Err("0x836ca8 is not RET (HashChain init ends before jump table)");
    }
    if BOSMINER_POLL_FUT40_OFF != 0x40 {
        return Err("command.rs:700 nested Future +0x10 store is Future+0x40");
    }
    Ok(())
}

/// Frame+0x10 is not command.rs:700 Future+0x10 and not HashChain object+0x10.
pub fn refuse_frame10_as_cmd700_future10_or_hashchain10() -> Result<(), &'static str> {
    Err(
        "Slot +0x30 X1 is LDR [X19,#0x10] after MOV X19,X0 / BR X10 — poll-self of the hashchain.rs async Future. 0 STR [X19,#0x10] in 0x836000-0x83a000 (construct-time capture). command.rs:700 stores *(+0x230)+0x10 at Future+0x40, not frame+0x10. FUN_00836934 STP [X20,#0x10] @ 0x836b94 is HashChain object init and RETs at 0x836ca8 before the jump table. Do not name send_work/set_baud",
    )
}

/// Fat-slot +0x38 does not take an extra X1 argument.
pub fn s19k_bosminer_slot38_extra_x1() -> bool {
    BOSMINER_FAT_SLOT38_X1_WRITES != 0
}

/// +0x38 BLR is the unique zero-arg Family-B fat Future (STP +0x58, immediate poll).
pub fn admit_bosminer_slot38_is_zero_arg_family_b_fat_future(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FAT_SLOT38_PATTERN_HITS != 1 {
        return Err("fat+0x38 pattern must stay unique in the jump table");
    }
    if BOSMINER_FAT_SLOT38_X1_WRITES != 0 {
        return Err("slot +0x38 must not write X1 before BLR");
    }
    if s19k_bosminer_slot38_extra_x1() {
        return Err("slot38 extra X1 helper");
    }
    if BOSMINER_FAT_SLOT38_POLL_VA != BOSMINER_DYN_FUT_POLL_VAS[4] {
        return Err("immediate poll must stay DYN_FUT_POLL_VAS[4]");
    }
    if BOSMINER_FAT_SLOT38_BLR_VA != BOSMINER_VT_SLOT_38_LDR_VA + 4 {
        return Err("BLR must sit immediately after LDR [X9,#0x38]");
    }
    if BOSMINER_FAT_SLOT38_STP_VA != BOSMINER_FAT_SLOT38_BLR_VA + 4 {
        return Err("STP pair must sit immediately after BLR");
    }
    if BOSMINER_FAT_SLOT38_POLL_VA != BOSMINER_FAT_SLOT38_STP_VA + 4 {
        return Err("dyn-poll must sit immediately after STP");
    }
    if BOSMINER_FAT_SLOT38_PRE_BLR_LOC_HITS != 0 {
        return Err("pre-BLR loc census drifted");
    }
    let slf = engine88_le_u32(blob, BOSMINER_FAT_SLOT38_SELF_LDR_VA)
        .ok_or("bosminer shorter than LDR [X19]")?;
    if slf != BOSMINER_FAT_SLOT38_SELF_LDR_INSN {
        return Err("0x83763c is not LDR X8,[X19]");
    }
    let pre = engine88_le_u32(blob, BOSMINER_FAT_SLOT38_PRE_X1_LDR_VA)
        .ok_or("bosminer shorter than pre X1 LDR")?;
    if pre != BOSMINER_FAT_SLOT38_PRE_X1_LDR_INSN {
        return Err("0x837638 is not LDR X9,[X1,#0x10]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_FAT_SLOT38_VT_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x238")?;
    if vt != BOSMINER_FAT_SLOT38_VT_LDR_INSN {
        return Err("0x837660 is not LDR X9,[X8,#0x238]");
    }
    let data = engine88_le_u32(blob, BOSMINER_FAT_SLOT38_DATA_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if data != BOSMINER_FAT_SLOT38_DATA_LDR_INSN {
        return Err("0x837664 is not LDR X0,[X8,#0x230]");
    }
    let mth = engine88_le_u32(blob, BOSMINER_VT_SLOT_38_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x38")?;
    if mth != BOSMINER_VT_SLOT_38_LDR_INSN {
        return Err("0x837668 is not LDR X8,[X9,#0x38]");
    }
    let br =
        engine88_le_u32(blob, BOSMINER_FAT_SLOT38_BLR_VA).ok_or("bosminer shorter than BLR X8")?;
    if br != BOSMINER_FAT_SLOT38_BLR_INSN {
        return Err("0x83766c is not BLR X8");
    }
    let stp = engine88_le_u32(blob, BOSMINER_FAT_SLOT38_STP_VA)
        .ok_or("bosminer shorter than STP +0x58")?;
    if stp != BOSMINER_FAT_STP_58_INSN {
        return Err("0x837670 is not STP X0,X1,[X19,#0x58]");
    }
    let poll = engine88_le_u32(blob, BOSMINER_FAT_SLOT38_POLL_VA)
        .ok_or("bosminer shorter than immediate poll")?;
    if poll != BOSMINER_DYN_FUT_POLL18_INSN {
        return Err("0x837674 is not LDR X9,[X1,#0x18]");
    }
    Ok(())
}

/// +0x38 is not the X1-taking +0x30 sibling and not a named Command method.
pub fn refuse_slot38_as_x1_sibling_or_named_command() -> Result<(), &'static str> {
    Err(
        "Fat-slot +0x38 is the unique +0x238/+0x230/+0x38/BLR call. 0 X1 writes before BLR — not the +0x30 method. LDR X9,[X1,#0x10] @ 0x837638 is pre-call bookkeeping (reads incoming X1), not a slot argument. STP is at frame+0x58 with immediate dyn-poll, not +0x28/+0x30 join-B Family A. 0 locs in 0xC0 before the BLR. send_work/set_baud/write_register absent",
    )
}

/// Fat-slot +0x40 does not take an extra X1 argument.
pub fn s19k_bosminer_slot40_extra_x1() -> bool {
    BOSMINER_FAT_SLOT40_X1_WRITES != 0
}

/// +0x40 BLR is the unique first-after-entry fat Future (copy +0x18→+0).
pub fn admit_bosminer_slot40_is_zero_arg_copy18_fat_future(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FAT_SLOT40_PATTERN_HITS != 1 {
        return Err("fat+0x40 pattern must stay unique in the jump table");
    }
    if BOSMINER_FAT_SLOT48_PATTERN_HITS != 1 {
        return Err("fat+0x48 census must stay unique");
    }
    if BOSMINER_FAT_SLOT50_PATTERN_HITS != 0 {
        return Err("fat+0x50 must stay 0 exact +0x238/+0x230/+0x50/BLR hits");
    }
    if BOSMINER_FAT_SLOT78_PATTERN_HITS != 1 {
        return Err("fat+0x78 census must stay unique");
    }
    if BOSMINER_FAT_SLOT40_X1_WRITES != 0 {
        return Err("slot +0x40 must not write X1 before BLR");
    }
    if s19k_bosminer_slot40_extra_x1() {
        return Err("slot40 extra X1 helper");
    }
    if BOSMINER_FAT_SLOT40_JOIN_TARGET != BOSMINER_DYN_FUT_POLL_VAS[1] {
        return Err("join target must stay dyn-poll[1] 0x836fe4");
    }
    if BOSMINER_FAT_SLOT40_JOIN_B_VA != BOSMINER_FAT_SLOT40_STP_VA + 4 {
        return Err("join B must sit immediately after STP");
    }
    if BOSMINER_HC_PLUS230_CONSUMER_BLR_VA != BOSMINER_HC_PLUS230_CONSUMER_VT40_VA + 4 {
        return Err("BLR must sit immediately after LDR [X9,#0x40]");
    }
    let src = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_SRC18_LDR_VA)
        .ok_or("bosminer shorter than LDR [X19,#0x18]")?;
    if src != BOSMINER_FAT_SLOT40_SRC18_LDR_INSN {
        return Err("0x836e7c is not LDR X8,[X19,#0x18]");
    }
    let copy = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_COPY0_STR_VA)
        .ok_or("bosminer shorter than STR [X19]")?;
    if copy != BOSMINER_FAT_SLOT40_COPY0_STR_INSN {
        return Err("0x836e84 is not STR X8,[X19,#0x0]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_LDR238_VA)
        .ok_or("bosminer shorter than LDR #0x238")?;
    if vt != BOSMINER_HC_PLUS230_CONSUMER_LDR238_INSN {
        return Err("0x836e8c is not LDR X9,[X8,#0x238]");
    }
    let data = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_LDR230_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if data != BOSMINER_HC_PLUS230_CONSUMER_LDR230_INSN {
        return Err("0x836e90 is not LDR X0,[X8,#0x230]");
    }
    let mth = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_VT40_VA)
        .ok_or("bosminer shorter than LDR #0x40")?;
    if mth != BOSMINER_HC_PLUS230_CONSUMER_VT40_INSN {
        return Err("0x836e94 is not LDR X8,[X9,#0x40]");
    }
    let br = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_BLR_VA)
        .ok_or("bosminer shorter than BLR X8")?;
    if br != BOSMINER_HC_PLUS230_CONSUMER_BLR_INSN {
        return Err("0x836e98 is not BLR X8");
    }
    let stp = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_STP_VA)
        .ok_or("bosminer shorter than STP pair")?;
    if stp != BOSMINER_FAT_STP_28_INSN {
        return Err("0x836e9c is not STP X0,X1,[X19,#0x28]");
    }
    let join = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_JOIN_B_VA)
        .ok_or("bosminer shorter than join B")?;
    if join != BOSMINER_FAT_SLOT40_JOIN_B_INSN {
        return Err("0x836ea0 is not B 0x836fe4");
    }
    let poll = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_JOIN_TARGET)
        .ok_or("bosminer shorter than join poll")?;
    if poll != BOSMINER_DYN_FUT_POLL18_INSN {
        return Err("0x836fe4 is not LDR X9,[X1,#0x18]");
    }
    Ok(())
}

/// +0x40 is not +0x50 sret, not the X1-taking +0x30, not a named Command.
pub fn refuse_slot40_as_sret50_or_x1_or_named_command() -> Result<(), &'static str> {
    Err(
        "Fat-slot +0x40 is the unique +0x238/+0x230/+0x40/BLR call and the first fat call after MOV X19,X0 / BR X10. It copies *[X19,#0x18] onto [X19,#0], takes 0 extra X1, STP at frame+0x28, joins dyn-poll[1]. +0x50 has 0 exact fat-pattern hits (sret ADD SP+#0x160). +0x48/+0x78 are unique siblings (immediate poll / Family-B +0x58) not this slot. send_work/set_baud/write_register absent",
    )
}

/// Fat-slot +0x48 does not take an extra X1 argument.
pub fn s19k_bosminer_slot48_extra_x1() -> bool {
    BOSMINER_FAT_SLOT48_X1_WRITES != 0
}

/// +0x48 BLR is the unique zero-arg immediate-poll fat Future.
pub fn admit_bosminer_slot48_is_zero_arg_immediate_fat_future(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FAT_SLOT48_PATTERN_HITS != 1 {
        return Err("fat+0x48 pattern must stay unique");
    }
    if BOSMINER_FAT_SLOT48_X1_WRITES != 0 {
        return Err("slot +0x48 must not write X1 before BLR");
    }
    if s19k_bosminer_slot48_extra_x1() {
        return Err("slot48 extra X1 helper");
    }
    if BOSMINER_FAT_SLOT48_POLL_VA != BOSMINER_DYN_FUT_POLL_VAS[5] {
        return Err("immediate poll must stay DYN_FUT_POLL_VAS[5]");
    }
    if BOSMINER_FAT_SLOT48_BLR_VA != BOSMINER_VT_SLOT_48_LDR_VA + 4 {
        return Err("BLR must sit immediately after LDR [X9,#0x48]");
    }
    if BOSMINER_FAT_SLOT48_STP_VA != BOSMINER_FAT_SLOT48_BLR_VA + 4 {
        return Err("STP must sit immediately after BLR");
    }
    if BOSMINER_FAT_SLOT48_POLL_VA != BOSMINER_FAT_SLOT48_STP_VA + 4 {
        return Err("dyn-poll must sit immediately after STP");
    }
    let slf = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_SELF_LDR_VA)
        .ok_or("bosminer shorter than LDR [X19]")?;
    if slf != BOSMINER_FAT_SLOT48_SELF_LDR_INSN {
        return Err("0x83860c is not LDR X8,[X19]");
    }
    let c28 = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_COPY28_STR_VA)
        .ok_or("bosminer shorter than STR +0x28")?;
    if c28 != BOSMINER_FAT_SLOT48_COPY28_STR_INSN {
        return Err("0x83861c is not STR X8,[X19,#0x28]");
    }
    let c30 = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_COPY30_STR_VA)
        .ok_or("bosminer shorter than STR +0x30")?;
    if c30 != BOSMINER_FAT_SLOT48_COPY30_STR_INSN {
        return Err("0x838620 is not STR X8,[X19,#0x30]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_VT_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x238")?;
    if vt != BOSMINER_FAT_SLOT48_VT_LDR_INSN {
        return Err("0x838624 is not LDR X9,[X8,#0x238]");
    }
    let data = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_DATA_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if data != BOSMINER_FAT_SLOT48_DATA_LDR_INSN {
        return Err("0x838628 is not LDR X0,[X8,#0x230]");
    }
    let mth = engine88_le_u32(blob, BOSMINER_VT_SLOT_48_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x48")?;
    if mth != BOSMINER_VT_SLOT_48_LDR_INSN {
        return Err("0x83862c is not LDR X8,[X9,#0x48]");
    }
    let br =
        engine88_le_u32(blob, BOSMINER_FAT_SLOT48_BLR_VA).ok_or("bosminer shorter than BLR")?;
    if br != BOSMINER_FAT_SLOT48_BLR_INSN {
        return Err("0x838630 is not BLR X8");
    }
    let stp = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_STP_VA)
        .ok_or("bosminer shorter than STP +0x40")?;
    if stp != BOSMINER_FAT_STP_40_INSN {
        return Err("0x838634 is not STP X0,X1,[X19,#0x40]");
    }
    let poll = engine88_le_u32(blob, BOSMINER_FAT_SLOT48_POLL_VA)
        .ok_or("bosminer shorter than immediate poll")?;
    if poll != BOSMINER_DYN_FUT_POLL18_INSN {
        return Err("0x838638 is not LDR X9,[X1,#0x18]");
    }
    Ok(())
}

/// +0x48 is not the +0x40 copy-18 slot and not a named Command.
pub fn refuse_slot48_as_copy18_or_named_command() -> Result<(), &'static str> {
    Err(
        "Fat-slot +0x48 is the unique +0x238/+0x230/+0x48/BLR call. 0 X1 writes. It copies Future+0 onto +0x28 and +0x30, STP at frame+0x40, immediate dyn-poll[5]. It does not copy Future+0x18 (that is +0x40). hashchain.rs:336 is the +0x78 pad. send_work/set_baud/write_register absent",
    )
}

/// +0x78 prelude LDP writes X1 from frame+0x38.
pub fn s19k_bosminer_slot78_extra_x1() -> bool {
    BOSMINER_FAT_SLOT78_X1_FROM_LDP
}

/// +0x78 BLR is the unique Family-B fat Future with LDP prelude.
pub fn admit_bosminer_slot78_is_ldp_family_b_fat_future(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FAT_SLOT78_PATTERN_HITS != 1 {
        return Err("fat+0x78 pattern must stay unique");
    }
    if !BOSMINER_FAT_SLOT78_X1_FROM_LDP {
        return Err("slot +0x78 must load X1 from the LDP pair");
    }
    if !s19k_bosminer_slot78_extra_x1() {
        return Err("slot78 extra X1 helper");
    }
    if BOSMINER_FAT_SLOT78_JOIN_TARGET != BOSMINER_FAT_PAIR_RELOAD58_VA {
        return Err("join target must stay reload58 0x83757c");
    }
    if BOSMINER_FAT_SLOT78_BLR_VA != BOSMINER_VT_SLOT_78_LDR_VA + 4 {
        return Err("BLR must sit immediately after LDR [X9,#0x78]");
    }
    if BOSMINER_FAT_SLOT78_STP_VA != BOSMINER_FAT_SLOT78_BLR_VA + 4 {
        return Err("STP must sit immediately after BLR");
    }
    let ldp = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_LDP_VA)
        .ok_or("bosminer shorter than LDP +0x30")?;
    if ldp != BOSMINER_FAT_SLOT78_LDP_INSN {
        return Err("0x837dcc is not LDP X8,X1,[X19,#0x30]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_VT_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x238")?;
    if vt != BOSMINER_FAT_SLOT78_VT_LDR_INSN {
        return Err("0x837dd0 is not LDR X9,[X8,#0x238]");
    }
    let data = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_DATA_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x230")?;
    if data != BOSMINER_FAT_SLOT78_DATA_LDR_INSN {
        return Err("0x837dd4 is not LDR X0,[X8,#0x230]");
    }
    let mth = engine88_le_u32(blob, BOSMINER_VT_SLOT_78_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x78")?;
    if mth != BOSMINER_VT_SLOT_78_LDR_INSN {
        return Err("0x837dd8 is not LDR X8,[X9,#0x78]");
    }
    let br =
        engine88_le_u32(blob, BOSMINER_FAT_SLOT78_BLR_VA).ok_or("bosminer shorter than BLR")?;
    if br != BOSMINER_FAT_SLOT78_BLR_INSN {
        return Err("0x837ddc is not BLR X8");
    }
    let stp = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_STP_VA)
        .ok_or("bosminer shorter than STP +0x58")?;
    if stp != BOSMINER_FAT_STP_58_INSN {
        return Err("0x837de0 is not STP X0,X1,[X19,#0x58]");
    }
    let join = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_JOIN_B_VA)
        .ok_or("bosminer shorter than join B")?;
    if join != BOSMINER_FAT_SLOT78_JOIN_B_INSN {
        return Err("0x837de8 is not B 0x83757c");
    }
    let reload = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_JOIN_TARGET)
        .ok_or("bosminer shorter than reload58")?;
    if reload != BOSMINER_FAT_PAIR_RELOAD58_INSN {
        return Err("0x83757c is not LDR X0,[X19,#0x58]");
    }
    let poll = engine88_le_u32(blob, BOSMINER_FAT_SLOT78_JOIN_TARGET + 4)
        .ok_or("bosminer shorter than +0x78 poll")?;
    if poll != BOSMINER_DYN_FUT_POLL18_INSN {
        return Err("0x837580 is not LDR X9,[X1,#0x18]");
    }
    Ok(())
}

/// +0x78 is not +0x30 (X1 from +0x10) and :336 is not the method name.
pub fn refuse_slot78_as_slot30_or_named_hashchain_336() -> Result<(), &'static str> {
    Err(
        "Fat-slot +0x78 is the unique +0x238/+0x230/+0x78/BLR call. X1 comes from LDP [X19,#0x30] (frame+0x38), not LDR [X19,#0x10]. Family B: STP +0x58, join reload58. hashchain.rs:336:84 at 0x837e04 is the post-join panic pad, not the method. send_work/set_baud/write_register absent",
    )
}

/// Future+0x18 STR-hits helper (jump-table body).
pub fn s19k_bosminer_future18_jt_str_hits() -> usize {
    BOSMINER_FUTURE18_JT_STR_HITS
}

/// Future+0x18 is the construct-time fat-host pointer consumed by +0x40.
pub fn admit_bosminer_future18_is_construct_time_fat_host(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FUTURE18_JT_STR_HITS != 0 {
        return Err("jump-table must keep 0 STR [X19,#0x18]");
    }
    if s19k_bosminer_future18_jt_str_hits() != 0 {
        return Err("future18 STR helper");
    }
    let src = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_SRC18_LDR_VA)
        .ok_or("bosminer shorter than Future+0x18 LDR")?;
    if src != BOSMINER_FAT_SLOT40_SRC18_LDR_INSN {
        return Err("0x836e7c is not LDR X8,[X19,#0x18]");
    }
    let copy = engine88_le_u32(blob, BOSMINER_FAT_SLOT40_COPY0_STR_VA)
        .ok_or("bosminer shorter than copy onto +0")?;
    if copy != BOSMINER_FAT_SLOT40_COPY0_STR_INSN {
        return Err("0x836e84 is not STR X8,[X19,#0x0]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_HC_PLUS230_CONSUMER_LDR238_VA)
        .ok_or("bosminer shorter than fat vt")?;
    if vt != BOSMINER_HC_PLUS230_CONSUMER_LDR238_INSN {
        return Err("copied +0x18 is not used as [X8,#0x238] host");
    }
    let init = engine88_le_u32(blob, BOSMINER_HC_INIT_PLUS18_LDR_VA)
        .ok_or("bosminer shorter than HashChain-init +0x18")?;
    if init != BOSMINER_HC_INIT_PLUS18_LDR_INSN {
        return Err("0x8369b4 is not LDR [X19,#0x18]");
    }
    let ret = engine88_le_u32(blob, BOSMINER_HC_PLUS230_RET_VA)
        .ok_or("bosminer shorter than HashChain-init RET")?;
    if ret != BOSMINER_HC_PLUS230_RET_INSN {
        return Err("0x836ca8 is not RET (init +0x18 is a different function)");
    }
    Ok(())
}

/// Future+0x18 is not cmd700 Future+0x10 and not a named HashChain field.
pub fn refuse_future18_as_cmd700_or_named_hashchain_field() -> Result<(), &'static str> {
    Err(
        "Poll-self Future+0x18 is the construct-time fat-host pointer: unique jump-table LDR [X19,#0x18] @ 0x836e7c is copied onto Future+0 then used as [X8,#0x238]/[X8,#0x230]. 0 STR [X19,#0x18] in 0x836000-0x83a000. command.rs:700 stores *(+0x230)+0x10 at Future+0x40, not +0x18. 0x8369b4 LDR [X19,#0x18] is FUN_00836934 HashChain init and RETs at 0x836ca8 — not the poll Future and not a proven HashChain field name",
    )
}

/// Clone helper BL census.
pub fn s19k_bosminer_future_clone_bl_hits() -> usize {
    BOSMINER_FUTURE_CLONE_BL_HITS
}

/// Future+0x10/+0x18 are copied by the 0x188 clone from SP+#8.
pub fn admit_bosminer_future_clone_copies_sp8_and_returns_vtable(
    blob: &[u8],
) -> Result<(), &'static str> {
    if BOSMINER_FUTURE_VT_SIZE != 0x188 {
        return Err("Future size must stay 0x188");
    }
    if BOSMINER_FUTURE_VT_ALIGN != 8 {
        return Err("Future align must stay 8");
    }
    if BOSMINER_FUTURE_VT_POLL != 0x0083_6E2C {
        return Err("Future poll must stay jump-table entry 0x836e2c");
    }
    if BOSMINER_FUTURE_VT_DROP != 0x0083_1814 {
        return Err("Future drop must stay 0x831814");
    }
    if BOSMINER_FUTURE_VT_FILE_OFF != BOSMINER_FUTURE_VT_VA - 0x410_000 {
        return Err("vtable file offset must be VA-0x410000");
    }
    if BOSMINER_FUTURE_CLONE_BL_HITS != 0 {
        return Err("first-LOAD BL census to clone must stay 0");
    }
    if s19k_bosminer_future_clone_bl_hits() != 0 {
        return Err("clone BL helper");
    }
    if BOSMINER_FUTURE_VT_ADD_IMM != 0xAE8 {
        return Err("vtable ADD imm must stay 0xae8");
    }
    let ent = engine88_le_u32(blob, BOSMINER_FUTURE_CLONE_VA)
        .ok_or("bosminer shorter than clone SUB SP")?;
    if ent != BOSMINER_FUTURE_CLONE_ENTRY_INSN {
        return Err("0x836da4 is not SUB SP,#0x1b0");
    }
    let mz = engine88_le_u32(blob, BOSMINER_FUTURE_CLONE_MOVZ188_VA)
        .ok_or("bosminer shorter than MOVZ #0x188")?;
    if mz != BOSMINER_FUTURE_CLONE_MOVZ188_INSN {
        return Err("0x836dc0 is not MOVZ W0,#0x188");
    }
    let src = engine88_le_u32(blob, BOSMINER_FUTURE_CLONE_SRC_ADD_VA)
        .ok_or("bosminer shorter than ADD SP+#8")?;
    if src != BOSMINER_FUTURE_CLONE_SRC_ADD_INSN {
        return Err("0x836dd8 is not ADD X1,SP,#8");
    }
    let sz = engine88_le_u32(blob, BOSMINER_FUTURE_CLONE_SIZE_MOVZ_VA)
        .ok_or("bosminer shorter than MOVZ W2,#0x188")?;
    if sz != BOSMINER_FUTURE_CLONE_SIZE_MOVZ_INSN {
        return Err("0x836ddc is not MOVZ W2,#0x188");
    }
    let mc = engine88_le_u32(blob, BOSMINER_FUTURE_CLONE_MEMCPY_BL_VA)
        .ok_or("bosminer shorter than memcpy BL")?;
    if mc != BOSMINER_FUTURE_CLONE_MEMCPY_BL_INSN {
        return Err("0x836de4 is not BL memcpy 0xbc8fe0");
    }
    let add = engine88_le_u32(blob, BOSMINER_FUTURE_CLONE_VT_ADD_VA)
        .ok_or("bosminer shorter than ADD #0xae8")?;
    if add != BOSMINER_FUTURE_CLONE_VT_ADD_INSN {
        return Err("0x836df8 is not ADD X1,#0xae8");
    }
    Ok(())
}

/// Clone is not 0x91000c / 0x834fa8; stack filler of SP+#8 is still unnamed.
pub fn refuse_future_clone_as_91000c_or_named_stack_filler() -> Result<(), &'static str> {
    Err(
        "Construct-time writer of Future+0x10/+0x18 is the 0x188 clone at 0x836da4: memcpy from SP+#8 then RET (box, vtable 0x19bbae8). Unique first-LOAD vtable materialize is ADD #0xae8. 0 BLs to the clone in the first LOAD. 0x91000c writes +0x10/+0x18 on a 0xa8-sized object (ADD #0x518), not this vtable. 0x834fa8 STR +0x18 is command.rs:472 Vec-path, no 0x188. Jump table still has 0 STR/STP [X19,#0x10] and 0 STR [X19,#0x18]. The stack-template filler of SP+#8 is not a named rust fn",
    )
}

/// Clone does not write Future+0x10 (no store at SP+#0x18).
pub fn s19k_bosminer_clone_writes_future10() -> bool {
    false
}

/// SP+#8 template X0 store is Future+0x18.
pub fn s19k_bosminer_clone_x0_is_future18() -> bool {
    BOSMINER_FUTURE_TMPL_X0_SP_OFF == BOSMINER_FUTURE_TMPL_BASE + 0x18
}

/// Clone fills its own SP+#8 template: X0→+0x18, 0→+0x21, W1→+0x22.
pub fn admit_bosminer_clone_fills_sp8_x0_as_future18(blob: &[u8]) -> Result<(), &'static str> {
    if !s19k_bosminer_clone_x0_is_future18() {
        return Err("SP+#0x20 must be template+0x18");
    }
    if s19k_bosminer_clone_writes_future10() {
        return Err("clone must not be claimed to write Future+0x10");
    }
    if BOSMINER_FUTURE_PLUS21_OFF != 0x21 {
        return Err("Future+0x21 offset");
    }
    if BOSMINER_OWNER260_SIZE != 0x260 || BOSMINER_OWNER260_ALIGN != 0x10 {
        return Err("owner type must stay 0x260/0x10");
    }
    if BOSMINER_OWNER260_VT_FILE_OFF != BOSMINER_OWNER260_VT_SIZE_VA - 0x410_000 {
        return Err("owner vtable file offset");
    }
    if BOSMINER_SIB188_VT_ADD_IMM != 0x1A8 {
        return Err("sibling vtable ADD must stay #0x1a8");
    }
    if BOSMINER_FUTURE_CLONE_BL_HITS != 0 {
        return Err("clone BL census must stay 0");
    }
    let x0 = engine88_le_u32(blob, BOSMINER_FUTURE_TMPL_X0_STR_VA)
        .ok_or("bosminer shorter than STR X0 [SP,#0x20]")?;
    if x0 != BOSMINER_FUTURE_TMPL_X0_STR_INSN {
        return Err("0x836dbc is not STR X0,[SP,#0x20]");
    }
    let st21 = engine88_le_u32(blob, BOSMINER_FUTURE_TMPL_ST21_VA)
        .ok_or("bosminer shorter than STRB +0x29")?;
    if st21 != BOSMINER_FUTURE_TMPL_ST21_INSN {
        return Err("0x836db0 is not STRB WZR,[SP,#0x29]");
    }
    let st22 = engine88_le_u32(blob, BOSMINER_FUTURE_TMPL_ST22_VA)
        .ok_or("bosminer shorter than STRB +0x2a")?;
    if st22 != BOSMINER_FUTURE_TMPL_ST22_INSN {
        return Err("0x836dc4 is not STRB W1,[SP,#0x2a]");
    }
    let src = engine88_le_u32(blob, BOSMINER_FUTURE_CLONE_SRC_ADD_VA)
        .ok_or("bosminer shorter than ADD SP+#8")?;
    if src != BOSMINER_FUTURE_CLONE_SRC_ADD_INSN {
        return Err("0x836dd8 is not ADD X1,SP,#8");
    }
    Ok(())
}

/// No separate stack-filler fn; sibling 0x85a014 is a different Future.
pub fn refuse_sp8_filler_as_separate_fn_or_sib188() -> Result<(), &'static str> {
    Err(
        "SP+#8 0x188 template is filled by clone 0x836da4 itself: STR X0,[SP,#0x20]=Future+0x18 fat host, STRB 0 at Future+0x21, STRB W1 at Future+0x22. No store at SP+#0x18 (Future+0x10 unbound in clone). 0 first-LOAD BLs — clone is vtable method 0x19c17b0 on a 0x260/align-16 owner. Sibling 0x85a014 STR X0,[SP,#8] and ADD #0x1a8 is a different 0x188 type. 0x91000c/0x834fa8 already refused as this Future",
    )
}

/// +0x50 takes an extra X1 from frame+0x38.
pub fn s19k_bosminer_slot50_extra_x1() -> bool {
    BOSMINER_FAT_SLOT50_X1_WRITES == 1 && BOSMINER_FAT_SLOT50_X1_OFF == 0x38
}

/// +0x50 post-BLR compare is word0 vs 0, not Poll tag 9.
pub fn s19k_bosminer_slot50_is_poll_tag9() -> bool {
    false
}

/// Fat-slot +0x50 is the unique sret method: host from frame+0x30, X1 from +0x38.
pub fn admit_bosminer_slot50_is_sret_host30_x1_38(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_FAT_SLOT50_PATTERN_HITS != 0 {
        return Err("+0x50 exact fat pattern hits must stay 0");
    }
    if BOSMINER_FAT_SLOT50_HOST_OFF != 0x30 {
        return Err("+0x50 host must stay frame+0x30");
    }
    if !s19k_bosminer_slot50_extra_x1() {
        return Err("+0x50 must take X1 from frame+0x38");
    }
    if s19k_bosminer_slot50_is_poll_tag9() {
        return Err("+0x50 must not be claimed as Poll tag-9");
    }
    if BOSMINER_FAT_SLOT50_SRET_SIZE != 0x28 {
        return Err("+0x50 sret size must stay 0x28");
    }
    if BOSMINER_FAT_SLOT50_SRET_OFF != 0x160 {
        return Err("+0x50 sret must stay SP+#0x160");
    }
    let mv = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_MOV28_VA)
        .ok_or("bosminer shorter than MOV X28,X19")?;
    if mv != BOSMINER_FAT_SLOT50_MOV28_INSN {
        return Err("0x8376e8 is not MOV X28,X19");
    }
    let pre = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_LDR_PRE38_VA)
        .ok_or("bosminer shorter than LDR pre +0x38")?;
    if pre != BOSMINER_FAT_SLOT50_LDR_PRE38_INSN {
        return Err("0x8376ec is not LDR pre X1,[X28,#0x38]");
    }
    let ldur = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_LDUR_M8_VA)
        .ok_or("bosminer shorter than LDUR -8")?;
    if ldur != BOSMINER_FAT_SLOT50_LDUR_M8_INSN {
        return Err("0x8376f0 is not LDUR X8,[X28,#-8]");
    }
    let vt = engine88_le_u32(blob, BOSMINER_VT_SLOT_50_LDR_VA)
        .ok_or("bosminer shorter than LDR #0x50")?;
    if vt != BOSMINER_VT_SLOT_50_LDR_INSN {
        return Err("0x8376fc is not LDR [X9,#0x50]");
    }
    let sret = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_SRET_ADD_VA)
        .ok_or("bosminer shorter than ADD SP+#0x160")?;
    if sret != BOSMINER_FAT_SLOT50_SRET_ADD_INSN {
        return Err("0x837700 is not ADD X8,SP,#0x160");
    }
    let blr = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_BLR_VA)
        .ok_or("bosminer shorter than +0x50 BLR")?;
    if blr != BOSMINER_FAT_SLOT50_BLR_INSN {
        return Err("0x837704 is not BLR X9");
    }
    let ldp = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_LDP_VA)
        .ok_or("bosminer shorter than LDP sret")?;
    if ldp != BOSMINER_FAT_SLOT50_LDP_INSN {
        return Err("0x837708 is not LDP X10,X20,[SP,#0x160]");
    }
    let cmp0 = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_CMP0_VA)
        .ok_or("bosminer shorter than CMP word0")?;
    if cmp0 != BOSMINER_FAT_SLOT50_CMP0_INSN {
        return Err("0x837718 is not CMP X10,X9");
    }
    let prev = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_PREV_CMP9_VA)
        .ok_or("bosminer shorter than previous CMP #9")?;
    if prev != BOSMINER_FAT_SLOT50_PREV_CMP9_INSN {
        return Err("0x837688 is not CMP X24,#9 (previous slot)");
    }
    let conv = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_CONV_BL_VA)
        .ok_or("bosminer shorter than BL 0x40c2c4")?;
    if conv != BOSMINER_FAT_SLOT50_CONV_BL_INSN {
        return Err("0x837740 is not BL 0x40c2c4");
    }
    Ok(())
}

/// +0x50 is not Poll tag-9 and not a zero-arg pair-return fat Future.
pub fn refuse_slot50_as_poll9_or_zero_arg_fat() -> Result<(), &'static str> {
    Err(
        "Fat-slot +0x50 is the unique sret method: host is *[X19,#0x30] (LDR pre X1,[X28,#0x38] then LDUR X8,[X28,#-8]), extra X1 is *[X19,#0x38], ADD X8,SP,#0x160 then BLR. After return LDP/Q0/+0x180 then CMP word0 vs 0 and BL 0x40c2c4. Exact +0x238/+0x230/+0x50/BLR hits stay 0 because the sret ADD sits between LDR #0x50 and BLR. CMP #9 at 0x837688 is the previous slot's Poll Pending, not this method. Not a zero-arg Family-A/B pair-return Future",
    )
}

/// 0x260 owner is not HashChain (HashChain already has a +0x260 field).
pub fn s19k_bosminer_owner260_is_hashchain() -> bool {
    false
}

/// 0x260 owner drop loads the +0x230/+0x238 fat pair; boxer materializes the vtable.
pub fn admit_bosminer_owner260_drop_has_fat230() -> Result<(), &'static str> {
    if s19k_bosminer_owner260_is_hashchain() {
        return Err("0x260 owner must not be claimed as HashChain");
    }
    if BOSMINER_OWNER260_SIZE != 0x260 || BOSMINER_OWNER260_ALIGN != 0x10 {
        return Err("owner type must stay 0x260/0x10");
    }
    if BOSMINER_OWNER260_DROP_FN_VA != 0x0087_3D10 {
        return Err("owner drop must stay 0x873d10");
    }
    if BOSMINER_OWNER260_VT_DROP_FILE_OFF != BOSMINER_OWNER260_VT_DROP_VA - 0x410_000 {
        return Err("owner drop vtable file offset");
    }
    if BOSMINER_OWNER260_VT_DROP_VA + 8 != BOSMINER_OWNER260_VT_SIZE_VA {
        return Err("drop qword must sit immediately before size 0x260");
    }
    if BOSMINER_OWNER260_BOXER_ADD_IMM != 0x798 {
        return Err("boxer ADD must stay #0x798 -> 0x19c1798");
    }
    if BOSMINER_OWNER260_BOXER_MOVZ260_INSN != 0x5280_4C00 {
        return Err("boxer MOVZ W0,#0x260");
    }
    if BOSMINER_OWNER260_DROP_PLUS230_LDR_INSN != 0xF941_1A75 {
        return Err("drop LDR [X19,#0x230]");
    }
    if BOSMINER_OWNER260_DROP_PLUS238_LDR_INSN != 0xF941_1E74 {
        return Err("drop LDR [X19,#0x238]");
    }
    if BOSMINER_HW200_LINE != 200 || BOSMINER_HW200_COL != 14 {
        return Err("hardware.rs:200:14 loc");
    }
    Ok(())
}

/// 0x260 owner is not HashChain and not a named Hashboard type.
pub fn refuse_owner260_as_hashchain_or_named_hashboard() -> Result<(), &'static str> {
    Err(
        "0x260 owner drop is FUN_00873d10 (vtable 0x19c1798): LDR +0x240 then fat pair +0x238/+0x230. Unique boxer at 0x87e394 MOVZ #0x260/#0x10, ADD #0x798, STP (box, vt) at [X20,#0x10]. Not HashChain — FUN_00836934 STR #0x260 is the ticket-mask-Future fn-ptr field, so HashChain is larger than 0x260. Adjacent strings Hashboard / : not present and hardware.rs:200:14 are a panic/log loc (BL 0x4536b0), not a rust type name",
    )
}

/// FUN_0040c2c4 exclusive first-LOAD BL census.
pub fn s19k_bosminer_40c2c4_bl_hits() -> usize {
    BOSMINER_SLOT50_CONV_BL_HITS
}

/// FUN_0040c2c4 has 4 BLs; three jump-table arms pass SP+#0x160.
pub fn admit_bosminer_40c2c4_has_4_bls_three_jt160(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_SLOT50_CONV_BL_HITS != 4 {
        return Err("0x40c2c4 BL census must stay 4");
    }
    if s19k_bosminer_40c2c4_bl_hits() != 4 {
        return Err("0x40c2c4 BL helper");
    }
    if BOSMINER_SLOT50_CONV_JT160_HITS != 3 {
        return Err("three jump-table arms must pass SP+#0x160");
    }
    if BOSMINER_SLOT50_CONV_BL_VAS[0] != BOSMINER_FAT_SLOT50_CONV_BL_VA {
        return Err("first BL must stay the +0x50 success arm");
    }
    if BOSMINER_BACKTRACE_HELPER_BL_HITS != 171 {
        return Err("0x128ea88 BL census must stay 171");
    }
    if BOSMINER_SLOT50_CONV_OTHER_ADD_OFF != 0x30 {
        return Err("fourth caller must pass SP+#0x30");
    }
    let a2 = engine88_le_u32(blob, BOSMINER_SLOT50_CONV_ARM2_ADD_VA)
        .ok_or("bosminer shorter than arm2 ADD X0,#0x160")?;
    if a2 != BOSMINER_SLOT50_CONV_ADD0_INSN {
        return Err("0x837764 is not ADD X0,SP,#0x160");
    }
    let b2 = engine88_le_u32(blob, BOSMINER_SLOT50_CONV_ARM2_BL_VA)
        .ok_or("bosminer shorter than arm2 BL")?;
    if b2 != BOSMINER_SLOT50_CONV_ARM2_BL_INSN {
        return Err("0x837768 is not BL 0x40c2c4");
    }
    let a3 = engine88_le_u32(blob, BOSMINER_SLOT50_CONV_ARM3_ADD_VA)
        .ok_or("bosminer shorter than arm3 ADD X0,#0x160")?;
    if a3 != BOSMINER_SLOT50_CONV_ADD0_INSN {
        return Err("0x8378b0 is not ADD X0,SP,#0x160");
    }
    let b3 = engine88_le_u32(blob, BOSMINER_SLOT50_CONV_ARM3_BL_VA)
        .ok_or("bosminer shorter than arm3 BL")?;
    if b3 != BOSMINER_SLOT50_CONV_ARM3_BL_INSN {
        return Err("0x8378b4 is not BL 0x40c2c4");
    }
    let first = engine88_le_u32(blob, BOSMINER_FAT_SLOT50_CONV_BL_VA)
        .ok_or("bosminer shorter than +0x50 conv BL")?;
    if first != BOSMINER_FAT_SLOT50_CONV_BL_INSN {
        return Err("0x837740 is not BL 0x40c2c4");
    }
    Ok(())
}

/// 0x40c2c4 is not named from the rustc backtrace helper.
pub fn refuse_40c2c4_as_named_from_backtrace() -> Result<(), &'static str> {
    Err(
        "FUN_0040c2c4 has exactly 4 first-LOAD BLs: 0x837740/768/8b4 pass ADD X0,SP,#0x160 (the +0x50 0x28-byte sret) and 0x83a770 passes ADD X0,SP,#0x30. Its inner BL 0x128ea88 is the rustc backtrace helper (RUST_LIB_BACKTRACE / RUST_BACKTRACE, 171 BLs) — not a rust type name for the 0x28 sret. Converter rust ident still unbound",
    )
}

/// Jump table never STR [X19,#0x10].
pub fn s19k_bosminer_future10_jt_str_x19_hits() -> usize {
    BOSMINER_FUTURE10_JT_STR_X19_HITS
}

/// Future+0x10 is not the poll Context (X21).
pub fn s19k_bosminer_future10_is_context() -> bool {
    false
}

/// First explicit Future+0x10 writer is poll-time copy of Future+0x48.
pub fn admit_bosminer_future10_writer_is_poll_copy48(blob: &[u8]) -> Result<(), &'static str> {
    if s19k_bosminer_future10_is_context() {
        return Err("Future+0x10 must not be claimed as Context");
    }
    if s19k_bosminer_clone_writes_future10() {
        return Err("clone must still not write Future+0x10");
    }
    if s19k_bosminer_future10_jt_str_x19_hits() != 0 {
        return Err("JT STR [X19,#0x10] census must stay 0");
    }
    if BOSMINER_FUTURE10_JT_STR_X21_HITS != 0 {
        return Err("JT STR X21,#0x10 census must stay 0");
    }
    if BOSMINER_FUTURE10_SRC48_OFF != 0x48 {
        return Err("source must stay Future+0x48");
    }
    if BOSMINER_FUTURE10_JOIN_TARGET != 0x0083_72E8 {
        return Err("join target must stay 0x8372e8");
    }
    let src = engine88_le_u32(blob, BOSMINER_FUTURE10_SRC48_LDR_VA)
        .ok_or("bosminer shorter than LDR [X19,#0x48]")?;
    if src != BOSMINER_FUTURE10_SRC48_LDR_INSN {
        return Err("0x8372e0 is not LDR X8,[X19,#0x48]");
    }
    let mv = engine88_le_u32(blob, BOSMINER_FUTURE10_ALIAS_MOV_VA)
        .ok_or("bosminer shorter than MOV X12,X19")?;
    if mv != BOSMINER_FUTURE10_ALIAS_MOV_INSN {
        return Err("0x8372f0 is not MOV X12,X19");
    }
    let st = engine88_le_u32(blob, BOSMINER_FUTURE10_STR_VA)
        .ok_or("bosminer shorter than STR [X12,#0x10]")?;
    if st != BOSMINER_FUTURE10_STR_INSN {
        return Err("0x837300 is not STR X8,[X12,#0x10]");
    }
    let add = engine88_le_u32(blob, BOSMINER_FUTURE10_NEST48_ADD_VA)
        .ok_or("bosminer shorter than ADD X0,#0x48")?;
    if add != BOSMINER_FUTURE10_NEST48_ADD_INSN {
        return Err("0x837238 is not ADD X0,X19,#0x48");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_FUTURE10_NEST48_X1_VA)
        .ok_or("bosminer shorter than MOV X1,X21")?;
    if x1 != BOSMINER_FUTURE10_NEST48_X1_INSN {
        return Err("0x83723c is not MOV X1,X21");
    }
    let bl = engine88_le_u32(blob, BOSMINER_FUTURE10_NEST48_BL_VA)
        .ok_or("bosminer shorter than BL 0x834f34")?;
    if bl != BOSMINER_FUTURE10_NEST48_BL_INSN {
        return Err("0x837240 is not BL 0x834f34");
    }
    let jb = engine88_le_u32(blob, BOSMINER_FUTURE10_JOIN_B_VA)
        .ok_or("bosminer shorter than B 0x8372e8")?;
    if jb != BOSMINER_FUTURE10_JOIN_B_INSN {
        return Err("0x837178 is not B 0x8372e8");
    }
    Ok(())
}

/// Future+0x10 is not poll Context and not a clone-template store.
pub fn refuse_future10_as_context_or_clone_template() -> Result<(), &'static str> {
    Err(
        "0x188 Future+0x10 has no construct-time writer: clone 0x836da4 memcpy-copies unwritten SP+#0x18 and has 0 store there. Jump table has 0 STR [X19,#0x10] and 0 STR X21 to #0x10 — Context stays in X21 and is passed as X1 to FUN_00834f34 (nested poll at Future+0x48). The first explicit writer is poll-time 0x837300 STR X8,[X12,#0x10] after MOV X12,X19, X8=LDR [X19,#0x48]. Not HashChain+0x10 and not cmd700 Future+0x10 (that store is Future+0x40)",
    )
}

/// Exclusive first-LOAD BL census to Mutex::lock poll.
pub fn s19k_bosminer_mutex_lock_poll_bl_hits() -> usize {
    BOSMINER_MUTEX_LOCK_POLL_BL_HITS
}

/// Future+0x48 is an inlined tokio-1.45.1 Mutex::lock future.
pub fn admit_bosminer_future48_is_tokio_mutex_lock(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_MUTEX_LOCK_POLL_BL_HITS != 9 {
        return Err("0x834f34 BL census must stay 9");
    }
    if s19k_bosminer_mutex_lock_poll_bl_hits() != 9 {
        return Err("mutex lock BL helper");
    }
    if BOSMINER_MUTEX_LOCK_TAG70_OFF != 0x70 {
        return Err("lock-future tag must stay +0x70");
    }
    if BOSMINER_MUTEX_LOCK_LINE != 434 || BOSMINER_MUTEX_LOCK_COL != 51 {
        return Err("mutex.rs:434:51 is lock()");
    }
    if BOSMINER_MUTEX_ACQUIRE_LINE != 651 || BOSMINER_MUTEX_UNREACHABLE_LINE != 657 {
        return Err("mutex.rs:651/:657 are acquire/unreachable");
    }
    if !BOSMINER_MUTEX_RS_SUFFIX.ends_with("mutex.rs") {
        return Err("mutex.rs suffix");
    }
    if BOSMINER_MUTEX_RS_PATH_LEN != 157 {
        return Err("mutex.rs path length");
    }
    if BOSMINER_MUTEX_LOCK_LOC_FILE_OFF != BOSMINER_MUTEX_LOCK_LOC_VA - 0x410_000 {
        return Err("mutex lock loc file offset");
    }
    if BOSMINER_FUTURE48_SRC_OFF != 0x28 {
        return Err("+0x48 first qword from +0x240+0x28");
    }
    let ent = engine88_le_u32(blob, BOSMINER_MUTEX_LOCK_POLL_VA)
        .ok_or("bosminer shorter than 0x834f34 SUB SP")?;
    if ent != BOSMINER_MUTEX_LOCK_POLL_ENTRY_INSN {
        return Err("0x834f34 is not SUB SP,#0x60");
    }
    let tag = engine88_le_u32(blob, BOSMINER_MUTEX_LOCK_TAG70_LDRB_VA)
        .ok_or("bosminer shorter than LDRB +0x70")?;
    if tag != BOSMINER_MUTEX_LOCK_TAG70_LDRB_INSN {
        return Err("0x834f48 is not LDRB [X0,#0x70]");
    }
    let st = engine88_le_u32(blob, BOSMINER_MUTEX_LOCK_TAG70_STRB_VA)
        .ok_or("bosminer shorter than STRB +0x70")?;
    if st != BOSMINER_MUTEX_LOCK_TAG70_STRB_INSN {
        return Err("0x83502c is not STRB [X19,#0x70]");
    }
    let pad = engine88_le_u32(blob, BOSMINER_MUTEX_LOCK_PAD_ADRP_VA)
        .ok_or("bosminer shorter than mutex.rs:434 ADRP")?;
    if pad != BOSMINER_MUTEX_LOCK_PAD_ADRP_INSN {
        return Err("0x83507c is not ADRP mutex.rs:434");
    }
    let add = engine88_le_u32(blob, BOSMINER_MUTEX_LOCK_PAD_ADD_VA)
        .ok_or("bosminer shorter than ADD #0x2f0")?;
    if add != BOSMINER_MUTEX_LOCK_PAD_ADD_INSN {
        return Err("0x835080 is not ADD #0x2f0");
    }
    let pbl = engine88_le_u32(blob, BOSMINER_MUTEX_LOCK_PAD_BL_VA)
        .ok_or("bosminer shorter than BL 0x453c40")?;
    if pbl != BOSMINER_MUTEX_LOCK_PAD_BL_INSN {
        return Err("0x835084 is not BL async-resume-after-completion");
    }
    let nest = engine88_le_u32(blob, BOSMINER_FUTURE10_NEST48_BL_VA)
        .ok_or("bosminer shorter than JT BL 0x834f34")?;
    if nest != BOSMINER_FUTURE10_NEST48_BL_INSN {
        return Err("0x837240 is not BL 0x834f34");
    }
    let f48 = engine88_le_u32(blob, BOSMINER_FUTURE48_STR_VA)
        .ok_or("bosminer shorter than STR [X19,#0x48]")?;
    if f48 != BOSMINER_FUTURE48_STR_INSN {
        return Err("0x8370fc is not STR X8,[X19,#0x48]");
    }
    let src = engine88_le_u32(blob, BOSMINER_FUTURE48_SRC240_LDR_VA)
        .ok_or("bosminer shorter than LDR +0x240")?;
    if src != BOSMINER_FUTURE48_SRC240_LDR_INSN {
        return Err("0x8370d4 is not LDR [X8,#0x240]");
    }
    let a10 = engine88_le_u32(blob, BOSMINER_FUTURE48_ADD10_VA)
        .ok_or("bosminer shorter than ADD #0x10")?;
    if a10 != BOSMINER_FUTURE48_ADD10_INSN {
        return Err("0x8370e4 is not ADD #0x10");
    }
    let a18 = engine88_le_u32(blob, BOSMINER_FUTURE48_ADD18_VA)
        .ok_or("bosminer shorter than ADD #0x18")?;
    if a18 != BOSMINER_FUTURE48_ADD18_INSN {
        return Err("0x8370f0 is not ADD #0x18");
    }
    Ok(())
}

/// Future+0x48 is not fat-slot +0x48, not the 0x48 c0d4ac cell, not lock_owned.
pub fn refuse_future48_as_fat_slot_or_c0d4ac_or_lock_owned() -> Result<(), &'static str> {
    Err(
        "Future+0x48 is an inlined tokio-1.45.1 Mutex::lock future polled by FUN_00834f34 (tag +0x70, 9 BLs). Cold pads are mutex.rs:434:51 lock / :435:27 acquire_fut / :651:29 acquire / :657:13 unreachable — not lock_owned (that is mutex.rs:614). First qword is *(fat+0x240)+0x28, not a HashChain field name. Fat-slot +0x48 is a vtable offset on a different object. The 0x48 c0d4ac cell is a Copy now-scale object, not this lock future",
    )
}

/// Fat-host +0x240 is not the Mutex and is not HashChain+0x240.
pub fn s19k_bosminer_host240_is_mutex() -> bool {
    false
}

/// Fat-host +0x240 is a different field from HashChain+0x240 (1e8 u32).
pub fn s19k_bosminer_host240_is_hashchain() -> bool {
    false
}

/// Jump-table `LDR [Xn,#0x240]` census in `0x836000-0x83a000`.
pub fn s19k_bosminer_host240_jt_ldr_hits() -> usize {
    BOSMINER_HOST240_JT_LDR_HITS
}

/// First-LOAD `MOVZ #0x70` then `STR #0x240` hits (the one hit stores XZR).
pub fn s19k_bosminer_host240_ctor70_str_hits() -> usize {
    BOSMINER_HOST240_CTOR70_STR_HITS
}

/// Fat-host +0x240 is a pointer to a 0x70 heap object; Mutex is at +0x28.
pub fn admit_bosminer_host240_is_70_ptr_mutex_at_28(blob: &[u8]) -> Result<(), &'static str> {
    if s19k_bosminer_host240_is_mutex() {
        return Err("host+0x240 must not be claimed as the Mutex");
    }
    if s19k_bosminer_host240_is_hashchain() {
        return Err("host+0x240 must not be claimed as HashChain+0x240");
    }
    if BOSMINER_HOST240_OFF != 0x240 {
        return Err("host field must stay +0x240");
    }
    if BOSMINER_HOST240_BOX_SIZE != 0x70 {
        return Err("pointee size must stay 0x70");
    }
    if BOSMINER_HOST240_MUTEX_OFF != 0x28 {
        return Err("Mutex must stay pointee+0x28");
    }
    if BOSMINER_FUTURE48_SRC_OFF != BOSMINER_HOST240_MUTEX_OFF {
        return Err("Future+0x48 first qword must stay host_box+0x28");
    }
    if BOSMINER_HOST240_JT_LDR_HITS != 12 {
        return Err("JT LDR #0x240 census must stay 12");
    }
    if s19k_bosminer_host240_jt_ldr_hits() != 12 {
        return Err("host240 JT LDR helper");
    }
    if BOSMINER_HOST240_CTOR70_STR_HITS != 1 {
        return Err("MOVZ#0x70-then-STR#0x240 census must stay 1");
    }
    if s19k_bosminer_host240_ctor70_str_hits() != 1 {
        return Err("host240 ctor70 helper");
    }
    if BOSMINER_B41D80_FN_VA != 0x00B4_1D80 {
        return Err("0x70 drop must stay FUN_00b41d80");
    }
    if BOSMINER_HC_PLUS240_1E8 != 0x05F5_E100 {
        return Err("HashChain+0x240 1e8 contrast drifted");
    }
    if BOSMINER_HC_PLUS240_STR_INSN == BOSMINER_FUTURE48_SRC240_LDR_INSN {
        return Err("HashChain STR W must not equal host LDR X");
    }
    let host = engine88_le_u32(blob, BOSMINER_HOST240_LDR_HOST_VA)
        .ok_or("bosminer shorter than LDR [X19,#0]")?;
    if host != BOSMINER_HOST240_LDR_HOST_INSN {
        return Err("0x8370c0 is not LDR X8,[X19,#0]");
    }
    let p148 = engine88_le_u32(blob, BOSMINER_HOST240_LDR148_VA)
        .ok_or("bosminer shorter than LDR +0x148")?;
    if p148 != BOSMINER_HOST240_LDR148_INSN {
        return Err("0x8370c8 is not LDR [X8,#0x148]");
    }
    let st8 = engine88_le_u32(blob, BOSMINER_HOST240_STR8_VA)
        .ok_or("bosminer shorter than STR Future+8")?;
    if st8 != BOSMINER_HOST240_STR8_INSN {
        return Err("0x8370cc is not STR X9,[X19,#0x8]");
    }
    let src = engine88_le_u32(blob, BOSMINER_FUTURE48_SRC240_LDR_VA)
        .ok_or("bosminer shorter than LDR +0x240")?;
    if src != BOSMINER_FUTURE48_SRC240_LDR_INSN {
        return Err("0x8370d4 is not LDR [X8,#0x240]");
    }
    let a10 = engine88_le_u32(blob, BOSMINER_FUTURE48_ADD10_VA)
        .ok_or("bosminer shorter than ADD #0x10")?;
    if a10 != BOSMINER_FUTURE48_ADD10_INSN {
        return Err("0x8370e4 is not ADD #0x10");
    }
    let a18 = engine88_le_u32(blob, BOSMINER_FUTURE48_ADD18_VA)
        .ok_or("bosminer shorter than ADD #0x18")?;
    if a18 != BOSMINER_FUTURE48_ADD18_INSN {
        return Err("0x8370f0 is not ADD #0x18");
    }
    let f48 = engine88_le_u32(blob, BOSMINER_FUTURE48_STR_VA)
        .ok_or("bosminer shorter than STR [X19,#0x48]")?;
    if f48 != BOSMINER_FUTURE48_STR_INSN {
        return Err("0x8370fc is not STR X8,[X19,#0x48]");
    }
    let hc = engine88_le_u32(blob, BOSMINER_HC_PLUS240_STR_VA)
        .ok_or("bosminer shorter than HashChain STR W #0x240")?;
    if hc != BOSMINER_HC_PLUS240_STR_INSN {
        return Err("0x836c0c is not STR W8,[X10,#0x240]");
    }
    Ok(())
}

/// +0x240 is not HashChain's 1e8 u32 and is not the Mutex object.
pub fn refuse_host240_as_hashchain_1e8_or_as_mutex() -> Result<(), &'static str> {
    Err(
        "Fat-host +0x240 is a pointer to a 0x70 heap object: LDR [X19] then LDR [X8,#0x240], ADD #0x10+#0x18 stores pointee+0x28 as Mutex::lock self at Future+0x48. Owner drop FUN_00873d10 LDAXR on the loaded ptr then ADD X0,X19,#0x240; BL FUN_00b41d80 (0x70/8 dealloc). HashChain+0x240 is a different larger object: STR W 0x05F5E100 at 0x836c0c. The only MOVZ#0x70-then-STR#0x240 is 0xcec094 XZR (null). Not the Mutex itself; do not name Arc vs Box or Mutex<T>",
    )
}

/// All 12 JT LDR #0x240 sites project +0x10.
pub fn s19k_bosminer_host240_add10_hits() -> usize {
    BOSMINER_HOST240_ADD10_HITS
}

/// Only the lock-construct site also ADD #0x18 on the same register.
pub fn s19k_bosminer_host240_add18_hits() -> usize {
    BOSMINER_HOST240_ADD18_HITS
}

/// +0x248 is not a named Arc.
pub fn s19k_bosminer_host248_is_arc() -> bool {
    false
}

/// +0x10 is the common projection; +0x28 is lock-construct-only; +0x248 sibling.
pub fn admit_bosminer_host240_plus10_is_common_proj(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HOST240_ADD10_HITS != 12 {
        return Err("JT +0x10 projection census must stay 12");
    }
    if s19k_bosminer_host240_add10_hits() != 12 {
        return Err("host240 add10 helper");
    }
    if BOSMINER_HOST240_ADD18_HITS != 1 {
        return Err("same-rd ADD #0x18 census must stay 1");
    }
    if s19k_bosminer_host240_add18_hits() != 1 {
        return Err("host240 add18 helper");
    }
    if s19k_bosminer_host248_is_arc() {
        return Err("+0x248 must not be claimed as named Arc");
    }
    if BOSMINER_HOST248_OFF != 0x248 {
        return Err("sibling field must stay +0x248");
    }
    if BOSMINER_HOST248_DROP_TGT_VA != 0x0092_462C {
        return Err("+0x248 drop tail must stay 0x92462c");
    }
    if BOSMINER_HOST248_DROP_BL_TGT != 0x0092_47B0 {
        return Err("0x92462c BL must stay 0x9247b0");
    }
    if BOSMINER_HOST240_ALT48_ADD10_INSN != BOSMINER_FUTURE48_ADD10_INSN {
        return Err("alt Future+0x48 ADD #0x10 must match lock-construct ADD #0x10");
    }
    if BOSMINER_HOST240_ALT48_STR_INSN != BOSMINER_FUTURE48_STR_INSN {
        return Err("alt Future+0x48 STR must match lock-construct STR");
    }
    let alt_ldr = engine88_le_u32(blob, BOSMINER_HOST240_ALT48_LDR_VA)
        .ok_or("bosminer shorter than alt LDR #0x240")?;
    if alt_ldr != BOSMINER_HOST240_ALT48_LDR_INSN {
        return Err("0x837160 is not LDR [X8,#0x240]");
    }
    let alt_add = engine88_le_u32(blob, BOSMINER_HOST240_ALT48_ADD10_VA)
        .ok_or("bosminer shorter than alt ADD #0x10")?;
    if alt_add != BOSMINER_HOST240_ALT48_ADD10_INSN {
        return Err("0x83716c is not ADD #0x10");
    }
    let alt_st = engine88_le_u32(blob, BOSMINER_HOST240_ALT48_STR_VA)
        .ok_or("bosminer shorter than alt STR #0x48")?;
    if alt_st != BOSMINER_HOST240_ALT48_STR_INSN {
        return Err("0x837174 is not STR [X19,#0x48]");
    }
    let join =
        engine88_le_u32(blob, BOSMINER_FUTURE10_JOIN_B_VA).ok_or("bosminer shorter than join B")?;
    if join != BOSMINER_FUTURE10_JOIN_B_INSN {
        return Err("0x837178 is not B 0x8372e8");
    }
    let a68 = engine88_le_u32(blob, BOSMINER_HOST240_JT68_ADD10_VA)
        .ok_or("bosminer shorter than jt68 ADD #0x10")?;
    if a68 != BOSMINER_HOST240_JT68_ADD10_INSN {
        return Err("0x838600 is not ADD X0,X8,#0x10");
    }
    let s68 = engine88_le_u32(blob, BOSMINER_HOST240_JT68_STR_VA)
        .ok_or("bosminer shorter than jt68 STR #0x68")?;
    if s68 != BOSMINER_HOST240_JT68_STR_INSN {
        return Err("0x838604 is not STR [X19,#0x68]");
    }
    Ok(())
}

/// Mutex does not start at +0x28; +0x248 is not a named Arc.
pub fn refuse_mutex_start_as_plus28_or_named_arc() -> Result<(), &'static str> {
    Err(
        "All 12 JT LDR #0x240 sites project +0x10 (10 same-rd ADD, 2 dest-rd ADD). Only 0x8370d4 also ADD #0x18. Alternate Future+0x48 writer 0x837160 stores +0x10 then B 0x8372e8. +0x28 is lock-construct-only (+0x10+0x18), not the exclusive Mutex start. Sibling +0x248 last-ref jumps to 0x92462c which ADD #0x10 + BL 0x9247b0 then LDAXR at +0x08 — ArcInner-shaped on *248, not a proven name for the +0x240 object",
    )
}

/// Exclusive first-LOAD BL census to FUN_009247b0.
pub fn s19k_bosminer_9247b0_bl_hits() -> usize {
    BOSMINER_9247B0_BL_HITS
}

/// FUN_009247b0 is not Mutex::drop / Semaphore::drop / named Vec::drop.
pub fn s19k_bosminer_9247b0_is_mutex_drop() -> bool {
    false
}

/// FUN_009247b0 is a counted fat-pointer element drop walker.
pub fn admit_bosminer_9247b0_is_counted_fat_drop() -> Result<(), &'static str> {
    if s19k_bosminer_9247b0_is_mutex_drop() {
        return Err("0x9247b0 must not be claimed as Mutex::drop");
    }
    if BOSMINER_9247B0_FN_VA != BOSMINER_HOST248_DROP_BL_TGT {
        return Err("0x9247b0 must stay the 0x92462c BL target");
    }
    if BOSMINER_9247B0_BL_HITS != 4 {
        return Err("0x9247b0 BL census must stay 4");
    }
    if s19k_bosminer_9247b0_bl_hits() != 4 {
        return Err("9247b0 BL helper");
    }
    if BOSMINER_9247B0_ADD10_CALLERS != 3 {
        return Err("3 callers must pass ADD #0x10");
    }
    if BOSMINER_9247B0_LEN_OFF != 0x10 || BOSMINER_9247B0_PTR_OFF != 0x08 {
        return Err("count at +0x10 / buffer at +0x8");
    }
    if BOSMINER_9247B0_STRIDE != 0x10 {
        return Err("element stride must stay 0x10");
    }
    if BOSMINER_9247B0_LEN_LDR_INSN != 0xF940_0815 {
        return Err("0x9247bc is not LDR X21,[X0,#0x10]");
    }
    if BOSMINER_9247B0_PTR_LDR_INSN != 0xF940_0408 {
        return Err("0x9247c4 is not LDR X8,[X0,#0x8]");
    }
    if BOSMINER_9247B0_ADD18_INSN != 0x9100_6116 {
        return Err("0x9247c8 is not ADD X22,X8,#0x18");
    }
    if BOSMINER_9247B0_SUBS_INSN != 0xF100_06B5 {
        return Err("0x9247d0 is not SUBS X21,#1");
    }
    if BOSMINER_9247B0_STRIDE_ADD_INSN != 0x9100_42D6 {
        return Err("0x9247d4 is not ADD X22,#0x10");
    }
    if BOSMINER_9247B0_LDP_INSN != 0xA97E_CED4 {
        return Err("0x9247dc is not LDP X20,X19,[X22,#-0x18]");
    }
    if BOSMINER_9247B0_BLR_INSN != 0xD63F_0100 {
        return Err("0x9247ec is not BLR X8");
    }
    if BOSMINER_9247B0_DEALLOC_BL_INSN != 0x97F3_409F {
        return Err("0x924800 is not BL 0x5f4a7c");
    }
    if BOSMINER_9247B0_RET_INSN != 0xD65F_03C0 {
        return Err("0x924814 is not RET");
    }
    if BOSMINER_9247B0_CALLER_ADD10_INSN != 0x9100_4000 {
        return Err("caller ADD X0,#0x10 drifted");
    }
    if BOSMINER_9247B0_BL_VAS[2] != BOSMINER_HOST248_DROP_BL_VA {
        return Err("third BL must stay the +0x248 drop site");
    }
    if BOSMINER_HOST248_DROP_ADD10_VA != BOSMINER_9247B0_CALLER_ADD10_VAS[1] {
        return Err("0x924638 must stay the +0x248 ADD #0x10");
    }
    Ok(())
}

/// 0x9247b0 is not Mutex::drop, Semaphore::drop, or named Vec::drop.
pub fn refuse_9247b0_as_mutex_or_named_vec() -> Result<(), &'static str> {
    Err(
        "FUN_009247b0 walks a counted fat-pointer collection: len at +0x10, buffer at +0x8, stride 0x10, LDP pair + BLR drop + 0x5f4a7c dealloc. 4 BLs, 3 pass ADD #0x10 (including +0x248 drop 0x92463c). 0 locs in the body — not mutex.rs lock/drop, not batch_semaphore.rs, not a named Vec::drop (standard Vec ptr is +0, this buffer is +0x8). Not Mutex::lock (that is 0x834f34)",
    )
}

/// Exclusive first-LOAD BL census to FUN_0092462c.
pub fn s19k_bosminer_92462c_bl_hits() -> usize {
    BOSMINER_92462C_BL_HITS
}

/// *248 inner size is 0x30, not the 0x70 *240 pointee.
pub fn s19k_bosminer_host248_inner_size() -> u16 {
    BOSMINER_HOST248_INNER_SIZE
}

/// 0x9247b0 elements are not the Mutex lock() borrows.
pub fn s19k_bosminer_9247b0_elem_is_mutex() -> bool {
    false
}

/// *248 last-weak inner is 0x30; lock() &self stays on the 0x70 *240 object.
pub fn admit_bosminer_host248_inner_is_30_not_70(blob: &[u8]) -> Result<(), &'static str> {
    if s19k_bosminer_9247b0_elem_is_mutex() {
        return Err("0x9247b0 elements must not be claimed as Mutex");
    }
    if BOSMINER_HOST248_INNER_SIZE != 0x30 {
        return Err("*248 inner size must stay 0x30");
    }
    if s19k_bosminer_host248_inner_size() != 0x30 {
        return Err("host248 inner size helper");
    }
    if BOSMINER_HOST240_BOX_SIZE == BOSMINER_HOST248_INNER_SIZE {
        return Err("*240 0x70 and *248 0x30 must stay distinct");
    }
    if BOSMINER_92462C_BL_HITS != 81 {
        return Err("0x92462c BL census must stay 81");
    }
    if s19k_bosminer_92462c_bl_hits() != 81 {
        return Err("92462c BL helper");
    }
    if BOSMINER_92462C_JT_BL_HITS != 1 {
        return Err("JT BL to 0x92462c must stay 1");
    }
    if BOSMINER_92462C_JT_ADD_OFF != 0x270 {
        return Err("JT local must stay SP+#0x270");
    }
    if BOSMINER_HOST248_INNER_SIZE_INSN != 0x5280_0601 {
        return Err("0x924680 is not MOVZ W1,#0x30");
    }
    if BOSMINER_HOST248_INNER_ALIGN_INSN != 0x5280_0102 {
        return Err("0x924688 is not MOVZ W2,#8");
    }
    if BOSMINER_92462C_EXTRA18_LDR_INSN != 0xF940_0E60 {
        return Err("0x924648 is not LDR [X19,#0x18]");
    }
    if BOSMINER_FUTURE48_SRC_OFF != 0x28 {
        return Err("lock() &self must stay *240+0x28");
    }
    let add = engine88_le_u32(blob, BOSMINER_92462C_JT_ADD_VA)
        .ok_or("bosminer shorter than JT ADD SP+#0x270")?;
    if add != BOSMINER_92462C_JT_ADD_INSN {
        return Err("0x8365d4 is not ADD X0,SP,#0x270");
    }
    let bl = engine88_le_u32(blob, BOSMINER_92462C_JT_BL_VA)
        .ok_or("bosminer shorter than JT BL 0x92462c")?;
    if bl != BOSMINER_92462C_JT_BL_INSN {
        return Err("0x8365d8 is not BL 0x92462c");
    }
    Ok(())
}

/// 0x9247b0 elements are not Mutex; *248 0x30 is not the 0x70 lock object.
pub fn refuse_9247b0_elem_as_mutex_or_248_as_240() -> Result<(), &'static str> {
    Err(
        "FUN_0092462c last-weak deallocs 0x30/8 (0x924680 MOVZ #0x30), with 81 first-LOAD BLs. The one jump-table BL passes SP+#0x270, not HashChain+0x248. After 0x9247b0 it LDR [X19,#0x18] to dealloc an extra pointer. lock() &self is *(fat-host+0x240)+0x28 on the 0x70 object (b41d80). 0x9247b0 elements are fat-pointer collection entries inside the 0x30 T, not tokio Mutex",
    )
}

/// lock() poll uses the stored pointer as &Mutex with no extra offset.
pub fn s19k_bosminer_mutex_self_is_stored_ptr() -> bool {
    BOSMINER_MUTEX_SELF_IS_STORED_PTR
}

/// *248 T rust ident is not OnceCell/Lazy/Waitlist.
pub fn s19k_bosminer_host248_t_is_named() -> bool {
    false
}

/// Mutex field starts at *240 data+0x18; *248 T is 0x20 with buf/len/extra.
pub fn admit_bosminer_mutex_starts_at_data18_and_248_t_is_20(
    blob: &[u8],
) -> Result<(), &'static str> {
    if !s19k_bosminer_mutex_self_is_stored_ptr() {
        return Err("lock() &self must stay the stored pointer");
    }
    if s19k_bosminer_host248_t_is_named() {
        return Err("*248 T must not be claimed as a rust ident");
    }
    if BOSMINER_HOST240_DATA_PREFIX != 0x18 {
        return Err("T prefix before Mutex must stay 0x18");
    }
    if BOSMINER_HOST240_MUTEX_FIELD_OFF != 0x18 {
        return Err("Mutex field must stay data+0x18");
    }
    if BOSMINER_FUTURE48_SRC_OFF != 0x28 {
        return Err("stored lock() ptr must stay *240+0x28");
    }
    if BOSMINER_FUTURE48_SRC_OFF != 0x10 + BOSMINER_HOST240_MUTEX_FIELD_OFF {
        return Err("*240+0x28 must equal common +0x10 plus Mutex field +0x18");
    }
    if BOSMINER_HOST248_T_SIZE != 0x20 {
        return Err("*248 T must stay 0x20 (0x30-0x10)");
    }
    if BOSMINER_HOST248_INNER_SIZE - 0x10 != BOSMINER_HOST248_T_SIZE {
        return Err("T size must stay inner-0x10");
    }
    if BOSMINER_HOST248_T_BUF_OFF != BOSMINER_9247B0_PTR_OFF {
        return Err("T buf must stay 0x9247b0 ptr off");
    }
    if BOSMINER_HOST248_T_LEN_OFF != BOSMINER_9247B0_LEN_OFF {
        return Err("T len must stay 0x9247b0 len off");
    }
    if BOSMINER_HOST248_T_EXTRA_OFF != 0x18 {
        return Err("T extra ptr must stay +0x18");
    }
    let ldr = engine88_le_u32(blob, BOSMINER_LOCK_POLL_SELF_LDR_VA)
        .ok_or("bosminer shorter than lock poll LDR [X19,#0]")?;
    if ldr != BOSMINER_LOCK_POLL_SELF_LDR_INSN {
        return Err("0x834f5c is not LDR X8,[X19,#0]");
    }
    let st = engine88_le_u32(blob, BOSMINER_LOCK_POLL_SELF_STR18_VA)
        .ok_or("bosminer shorter than lock poll STR +0x18")?;
    if st != BOSMINER_LOCK_POLL_SELF_STR18_INSN {
        return Err("0x834fa8 is not STR X8,[X19,#0x18]");
    }
    let add = engine88_le_u32(blob, BOSMINER_LOCK_POLL_ACQ_ADD_VA)
        .ok_or("bosminer shorter than lock poll ADD #0x28")?;
    if add != BOSMINER_LOCK_POLL_ACQ_ADD_INSN {
        return Err("0x834fd0 is not ADD X0,X19,#0x28");
    }
    let bl = engine88_le_u32(blob, BOSMINER_LOCK_POLL_ACQ_BL_VA)
        .ok_or("bosminer shorter than BL 0x11f2de4")?;
    if bl != BOSMINER_LOCK_POLL_ACQ_BL_INSN {
        return Err("0x834fd4 is not BL 0x11f2de4");
    }
    Ok(())
}

/// Mutex does not start at data+0; *248 T is not a named OnceCell/Lazy/Waitlist.
pub fn refuse_mutex_at_data0_or_named_248_t() -> Result<(), &'static str> {
    Err(
        "lock() poll LDR [X19,#0] uses the stored *240+0x28 pointer as &self with 0 extra ADD. ADD X0,X19,#0x28 at 0x834fd0 is the lock-future acquire slot (BL 0x11f2de4), not Mutex+0x28. So Mutex starts at data+0x18, not at the +0x10 common projection. *248 T is 0x20 with buf+0x08/len+0x10/extra+0x18; 0 locs name OnceCell/Lazy/Waitlist; 0x9247b0 element rust ident stays unbound",
    )
}

/// JT field-LDR census of *240 data+0/+8/+0x10 after ADD #0x10.
pub fn s19k_bosminer_prefix_jt_field_ldr_hits() -> usize {
    BOSMINER_PREFIX_JT_FIELD_LDR_HITS
}

/// Exclusive first-LOAD BL census to FUN_00586cd8.
pub fn s19k_bosminer_586cd8_bl_hits() -> usize {
    BOSMINER_586CD8_BL_HITS
}

/// 0x9247b0 elements are Box-shaped, not Arc last-ref.
pub fn s19k_bosminer_9247b0_elem_is_box_shaped() -> bool {
    BOSMINER_9247B0_ELEM_IS_BOX_SHAPED
}

/// Prefix is opaque in JT; elements are Box-shaped; 0x586cd8 is not the JT walker.
pub fn admit_bosminer_prefix_opaque_and_elem_box_shaped() -> Result<(), &'static str> {
    if BOSMINER_PREFIX_JT_FIELD_LDR_HITS != 0 {
        return Err("JT prefix field-LDR census must stay 0");
    }
    if s19k_bosminer_prefix_jt_field_ldr_hits() != 0 {
        return Err("prefix JT LDR helper");
    }
    if !s19k_bosminer_9247b0_elem_is_box_shaped() {
        return Err("0x9247b0 elements must stay Box-shaped");
    }
    if BOSMINER_586CD8_BL_HITS != 66 {
        return Err("0x586cd8 BL census must stay 66");
    }
    if s19k_bosminer_586cd8_bl_hits() != 66 {
        return Err("586cd8 BL helper");
    }
    if BOSMINER_586CD8_JT_BL_HITS != 0 {
        return Err("0x586cd8 must have 0 JT BLs");
    }
    if BOSMINER_586CD8_STRIDE != 0x18 {
        return Err("0x586cd8 stride must stay 0x18");
    }
    if BOSMINER_586CD8_STRIDE_MOVZ_INSN != 0x5280_0309 {
        return Err("0x586d74 is not MOVZ W9,#0x18");
    }
    if BOSMINER_586CD8_BOUND_LDR_INSN != 0xF940_0E69 {
        return Err("0x586d68 is not LDR [X19,#0x18]");
    }
    if BOSMINER_586CD8_PTR_LDR_INSN != 0xF940_0A6A {
        return Err("0x586d78 is not LDR [X19,#0x10]");
    }
    if BOSMINER_586CD8_MADD_INSN != 0x9B09_2908 {
        return Err("0x586d7c is not MADD idx*0x18");
    }
    if BOSMINER_586CD8_PLUS28_LDR_INSN != 0xF940_1676 {
        return Err("0x586da8 is not LDR [X19,#0x28]");
    }
    if BOSMINER_HOST240_DATA_PREFIX != 0x18 {
        return Err("prefix size must stay 0x18");
    }
    if BOSMINER_9247B0_STRIDE != 0x10 {
        return Err("element stride must stay 0x10 (not 0x18)");
    }
    if BOSMINER_9247B0_STRIDE == BOSMINER_586CD8_STRIDE {
        return Err("0x9247b0 stride must differ from 0x586cd8");
    }
    Ok(())
}

/// Prefix is not a named String/Vec; 0x586cd8 is not the JT *240 walker; element Trait unbound.
pub fn refuse_prefix_as_named_vec_or_586cd8_as_jt_walker() -> Result<(), &'static str> {
    Err(
        "JT has 0 LDR of *240 data+0/+8/+0x10 after ADD #0x10 — prefix is skipped as a unit by lock() ADD #0x18. FUN_00586cd8 (66 BLs) indexes a stride-0x18 array at +0x10/+0x18 and loads +0x28, but has 0 jump-table BLs so it is not the JT *240 prefix walker. 0x9247b0 elements are Box-shaped fat pointers (drop then 0x5f4a7c), stride 0x10 not 0x18; do not name String/Vec or the dyn Trait",
    )
}

/// Non-SP non-XZR STR #0x240 census.
pub fn s19k_bosminer_host240_nonsp_nonnull_str_hits() -> usize {
    BOSMINER_HOST240_NONSP_NONNULL_STR_HITS
}

/// Unique STR X25,[X20,#0x240] on the HashChain clone.
pub fn s19k_bosminer_host240_clone_str240_unique() -> usize {
    BOSMINER_HOST240_CLONE_STR240_UNIQUE
}

/// HashChain clone installs *240 from incoming X1 (Arc-shaped LDAXR+1).
pub fn admit_bosminer_host240_clone_str_x25(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HOST240_CLONE_BL_HITS != 0 {
        return Err("clone entry must stay 0 first-LOAD BLs");
    }
    if BOSMINER_HOST240_CLONE_STR240_UNIQUE != 1 {
        return Err("STR X25,[X20,#0x240] must stay unique");
    }
    if s19k_bosminer_host240_clone_str240_unique() != 1 {
        return Err("clone STR unique helper");
    }
    if BOSMINER_HOST240_NONSP_NONNULL_STR_HITS != 54 {
        return Err("non-SP non-XZR STR #0x240 must stay 54");
    }
    if s19k_bosminer_host240_nonsp_nonnull_str_hits() != 54 {
        return Err("nonsp nonnull helper");
    }
    if BOSMINER_HOST240_CLONE_MEMCPY_LEN != 0x230 {
        return Err("clone memcpy len must stay 0x230");
    }
    let entry = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_FN_VA)
        .ok_or("bosminer shorter than clone SUB SP")?;
    if entry != BOSMINER_HOST240_CLONE_FN_INSN {
        return Err("0x835234 is not SUB SP,#0x240");
    }
    let x1 = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_X1_STR_VA)
        .ok_or("bosminer shorter than STR X1 [SP,#8]")?;
    if x1 != BOSMINER_HOST240_CLONE_X1_STR_INSN {
        return Err("0x83524c is not STR X1,[SP,#8]");
    }
    let x25 = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_X25_LDR_VA)
        .ok_or("bosminer shorter than LDR X25 [SP,#8]")?;
    if x25 != BOSMINER_HOST240_CLONE_X25_LDR_INSN {
        return Err("0x835314 is not LDR X25,[SP,#8]");
    }
    let movz = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_MEMCPY_MOVZ_VA)
        .ok_or("bosminer shorter than MOVZ #0x230")?;
    if movz != BOSMINER_HOST240_CLONE_MEMCPY_MOVZ_INSN {
        return Err("0x835320 is not MOVZ W2,#0x230");
    }
    let st240 = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_STR240_VA)
        .ok_or("bosminer shorter than STR X25 #0x240")?;
    if st240 != BOSMINER_HOST240_CLONE_STR240_INSN {
        return Err("0x835334 is not STR X25,[X20,#0x240]");
    }
    let st230 = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_STR230_VA)
        .ok_or("bosminer shorter than STR X24 #0x230")?;
    if st230 != BOSMINER_HOST240_CLONE_STR230_INSN {
        return Err("0x83532c is not STR X24,[X20,#0x230]");
    }
    let ldxr = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_LDAXR_VA)
        .ok_or("bosminer shorter than LDAXR")?;
    if ldxr != BOSMINER_HOST240_CLONE_LDAXR_INSN {
        return Err("0x8352e8 is not LDAXR");
    }
    if BOSMINER_HOST240_CTOR70_STR_HITS != 1 {
        return Err("MOVZ#0x70-then-STR#0x240 must stay the null store");
    }
    Ok(())
}

/// 0xcec094 is not a non-null ctor; 0x51a8c8 is not the 0x260 fat-host ctor.
pub fn refuse_cec094_or_51a8c8_as_host240_ctor() -> Result<(), &'static str> {
    Err(
        "0xcec094 is the only MOVZ #0x70 then STR #0x240 and stores XZR. 0x51a8c8 STR X0,[X19,#0x240] is FUN_00586cd8 index return on a larger object (fields past 0x260). The 0x260 fat-host non-null *240 installer is HashChain clone STR X25,[X20,#0x240] @ 0x835334 (incoming X1 / Arc-shaped LDAXR+1)",
    )
}

/// Unique first-LOAD BL census to the real clone entry 0x835220.
pub fn s19k_bosminer_clone_real_entry_bl_hits() -> usize {
    BOSMINER_HOST240_CLONE_REAL_BL_HITS
}

/// FUN_0060b0fc first-LOAD BL census (stride-0x18 index, not 0x70 ctor).
pub fn s19k_bosminer_60b0fc_bl_hits() -> usize {
    BOSMINER_60B0FC_BL_HITS
}

/// FUN_00681768 first-LOAD BL census (stride-0x18 sibling).
pub fn s19k_bosminer_681768_bl_hits() -> usize {
    BOSMINER_681768_BL_HITS
}

/// 0x749c58 *240 payload is a 0x228 box, not the 0x70 Mutex.
pub fn s19k_bosminer_749c58_is_70() -> bool {
    BOSMINER_749C58_ALLOC_SIZE == 0x70
}

/// Real clone entry is 0x835220; unique caller 0x87e1cc; HashChain+0x240 is STR W.
pub fn admit_bosminer_clone_real_entry_is_835220(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HOST240_CLONE_REAL_BL_HITS != 1 {
        return Err("real clone entry must stay 1 first-LOAD BL");
    }
    if s19k_bosminer_clone_real_entry_bl_hits() != 1 {
        return Err("real-entry BL helper");
    }
    if BOSMINER_HOST240_CLONE_BL_HITS != 0 {
        return Err("SUB SP site must stay 0 first-LOAD BLs");
    }
    if BOSMINER_HOST240_CLONE_VT_QWORD_HITS != 0 {
        return Err("clone vtable qword hits must stay 0");
    }
    if BOSMINER_60B0FC_BL_HITS != 27 {
        return Err("0x60b0fc BL census must stay 27");
    }
    if s19k_bosminer_60b0fc_bl_hits() != 27 {
        return Err("60b0fc helper");
    }
    if BOSMINER_681768_BL_HITS != 99 {
        return Err("0x681768 BL census must stay 99");
    }
    if s19k_bosminer_681768_bl_hits() != 99 {
        return Err("681768 helper");
    }
    if BOSMINER_749C58_ALLOC_SIZE != 0x228 {
        return Err("0x749c58 alloc size must stay 0x228");
    }
    if s19k_bosminer_749c58_is_70() {
        return Err("0x749c58 must not be named 0x70");
    }
    if BOSMINER_60B0FC_STRIDE_MOVZ_INSN != BOSMINER_586CD8_STRIDE_MOVZ_INSN {
        return Err("0x60b0fc stride MOVZ must match 0x586cd8");
    }
    if BOSMINER_681768_STRIDE_MOVZ_INSN != BOSMINER_586CD8_STRIDE_MOVZ_INSN {
        return Err("0x681768 stride MOVZ must match 0x586cd8");
    }
    let entry = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_REAL_ENTRY_VA)
        .ok_or("bosminer shorter than clone real entry")?;
    if entry != BOSMINER_HOST240_CLONE_REAL_ENTRY_INSN {
        return Err("0x835220 is not STR X29,[SP,#-0x50]!");
    }
    let stp1 = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_REAL_STP1_VA)
        .ok_or("bosminer shorter than clone STP X30")?;
    if stp1 != BOSMINER_HOST240_CLONE_REAL_STP1_INSN {
        return Err("0x835224 is not STP X30,X25");
    }
    let sub = engine88_le_u32(blob, BOSMINER_HOST240_CLONE_FN_VA)
        .ok_or("bosminer shorter than clone SUB SP")?;
    if sub != BOSMINER_HOST240_CLONE_FN_INSN {
        return Err("0x835234 is not SUB SP,#0x240");
    }
    if BOSMINER_HOST240_CLONE_REAL_ENTRY_VA + 0x14 != BOSMINER_HOST240_CLONE_FN_VA {
        return Err("SUB SP must stay 5 insns after real entry");
    }
    let hc = engine88_le_u32(blob, BOSMINER_HC_PLUS240_STR_VA)
        .ok_or("bosminer shorter than HashChain STR W #0x240")?;
    if hc != BOSMINER_HC_PLUS240_STR_INSN {
        return Err("0x836c0c is not STR W8,[X10,#0x240]");
    }
    let mz = engine88_le_u32(blob, BOSMINER_749C58_MOVZ_VA)
        .ok_or("bosminer shorter than 0x749c58 MOVZ #0x228")?;
    if mz != BOSMINER_749C58_MOVZ_INSN {
        return Err("0x749bf8 is not MOVZ W0,#0x228");
    }
    let x22 = engine88_le_u32(blob, BOSMINER_749C58_X22_MOV_VA)
        .ok_or("bosminer shorter than MOV X22,X0")?;
    if x22 != BOSMINER_749C58_X22_MOV_INSN {
        return Err("0x749c18 is not MOV X22,X0");
    }
    let st = engine88_le_u32(blob, BOSMINER_749C58_STR240_VA)
        .ok_or("bosminer shorter than STR X22 #0x240")?;
    if st != BOSMINER_749C58_STR240_INSN {
        return Err("0x749c58 is not STR X22,[X19,#0x240]");
    }
    let idx = engine88_le_u32(blob, BOSMINER_60B0FC_STRIDE_MOVZ_VA)
        .ok_or("bosminer shorter than 0x60b0fc MOVZ #0x18")?;
    if idx != BOSMINER_60B0FC_STRIDE_MOVZ_INSN {
        return Err("0x60b198 is not MOVZ W9,#0x18");
    }
    let st5 = engine88_le_u32(blob, BOSMINER_5FE12C_STR240_VA)
        .ok_or("bosminer shorter than 0x5fe12c STR")?;
    if st5 != BOSMINER_5FE12C_STR240_INSN {
        return Err("0x5fe12c is not STR X0,[X19,#0x240]");
    }
    Ok(())
}

/// 0x835234 is not the fn entry; index/0x228 sites are not the 0x70 Mutex ctor.
pub fn refuse_835234_as_fn_entry_or_70_first_alloc() -> Result<(), &'static str> {
    Err(
        "0x835234 is SUB SP,#0x240 after the 0x835220 prologue, not a function entry (0 BL/B/B.cond/vtable). Unique caller is BL 0x87e1cc in FUN_0087e02c with X1=X24. HashChain+0x240 is STR W 1e8 @ 0x836c0c, so this is not HashChain Default. 0x5fe12c/0x7b4d48 store FUN_0060b0fc/FUN_00681768 stride-0x18 index returns (27/99 BLs). 0x749c58 stores a 0x228 box. None of these is the 0x70 Mutex first-alloc",
    )
}

/// FUN_0087e02c STR [SP,#0x78] census.
pub fn s19k_bosminer_87e02c_str78_hits() -> usize {
    BOSMINER_SP78_STR78_HITS
}

/// FUN_0087deb4 first-LOAD BL census.
pub fn s19k_bosminer_87deb4_bl_hits() -> usize {
    BOSMINER_87DEB4_BL_HITS
}

/// 0x87deb4 is not proven to mint clone X24.
pub fn s19k_bosminer_87deb4_is_x24_mint() -> bool {
    BOSMINER_87DEB4_IS_X24_MINT
}

/// SP+#0x78 is sret+0x10 of BLR X23; X23 is HashMap-value fn ptr.
pub fn admit_bosminer_sp78_is_sret10_of_blr23() -> Result<(), &'static str> {
    if BOSMINER_SP78_STR78_HITS != 0 {
        return Err("FUN_0087e02c must have 0 STR [SP,#0x78]");
    }
    if s19k_bosminer_87e02c_str78_hits() != 0 {
        return Err("str78 helper");
    }
    if BOSMINER_SP78_SRET_BASE_OFF != 0x68 {
        return Err("sret base must stay SP+#0x68");
    }
    if BOSMINER_SP78_SRET_PLUS_OFF != 0x10 {
        return Err("SP+#0x78 must stay sret+0x10");
    }
    if u32::from(BOSMINER_SP78_SRET_BASE_OFF) + u32::from(BOSMINER_SP78_SRET_PLUS_OFF)
        != u32::from(BOSMINER_SP78_LDR_OFF)
    {
        return Err("0x68+0x10 must be 0x78");
    }
    if BOSMINER_SP78_SRET_ADD_INSN != 0x9101_A3E8 {
        return Err("0x87e144 must stay ADD X8,SP,#0x68");
    }
    if BOSMINER_SP78_BLR23_INSN != 0xD63F_02E0 {
        return Err("0x87e15c must stay BLR X23");
    }
    if BOSMINER_SP78_LDR78_INSN != 0xF940_3FE8 {
        return Err("0x87e168 must stay LDR X8,[SP,#0x78]");
    }
    if BOSMINER_SP78_X23_LDR_INSN != 0xF940_0037 {
        return Err("0x87e094 must stay LDR X23,[X1]");
    }
    if BOSMINER_SP78_GET_FN_VA != 0x0087_87A8 {
        return Err("HashMap get must stay 0x8787a8");
    }
    if BOSMINER_87DEB4_BL_HITS != 0 {
        return Err("0x87deb4 must stay 0 first-LOAD BLs");
    }
    if s19k_bosminer_87deb4_bl_hits() != 0 {
        return Err("87deb4 BL helper");
    }
    if BOSMINER_87DEB4_VT_QWORD_HITS != 1 {
        return Err("0x87deb4 must stay 1 data qword");
    }
    if BOSMINER_87DEB4_MOVZ70_INSN != 0x5280_0E00 {
        return Err("0x87decc must stay MOVZ W0,#0x70");
    }
    if BOSMINER_87DEB4_ALIGN_INSN != 0x5280_0101 {
        return Err("0x87dec0 must stay MOVZ W1,#8");
    }
    if BOSMINER_87DEB4_IS_X24_MINT || s19k_bosminer_87deb4_is_x24_mint() {
        return Err("do not name 0x87deb4 as the X24 mint");
    }
    if BOSMINER_HOST240_CLONE_CALLER_X1_MOV_INSN != 0xAA18_03E1 {
        return Err("clone X1 must stay X24");
    }
    Ok(())
}

/// SP+#0x78 is not a field STR; 0x87deb4 is not a named X24/Arc/Mutex mint.
pub fn refuse_sp78_as_field_or_87deb4_as_named_x24() -> Result<(), &'static str> {
    Err(
        "FUN_0087e02c has 0 STR [SP,#0x78]; the value is sret+0x10 after ADD X8,SP,#0x68; BLR X23. X23 is LDR [X1] of the HashMap-get payload, not a 0x70 pointer. FUN_0087deb4 is a 0x70/8 returning boxer (0 BLs, 1 qword at 0x19c8838) but does not STR #0x240 and is not proven to mint clone X24. 0xcec094 stays null; FUN_00bf33a4 is the factory worker 0x70 (6 BLs). Do not name Result/Arc/Mutex",
    )
}

/// Exclusive first-LOAD BL census to HashMap get `FUN_008787a8`.
pub fn s19k_bosminer_hashmap_get_bl_hits() -> usize {
    BOSMINER_HASHMAP_GET_BL_HITS
}

/// HashMap `V` spawn-fn offset.
pub fn s19k_bosminer_hashmap_v_spawn_off() -> u16 {
    BOSMINER_HASHMAP_V_SPAWN_OFF
}

/// HashMap `V` factory-method offset.
pub fn s19k_bosminer_hashmap_v_factory_off() -> u16 {
    BOSMINER_HASHMAP_V_FACTORY_OFF
}

/// Spawn sret 0x18 is not HashMap `V`.
pub fn s19k_bosminer_sret18_is_hashmap_v() -> bool {
    BOSMINER_SRET18_IS_HASHMAP_V
}

/// `V+0` is not factory4.
pub fn s19k_bosminer_v0_is_factory4() -> bool {
    BOSMINER_HASHMAP_V0_IS_FACTORY4
}

/// `V+8` is not vt0.
pub fn s19k_bosminer_v8_is_vt0() -> bool {
    BOSMINER_HASHMAP_V8_IS_VT0
}

/// Spawn `W0` test at `0x87e08c` is TBNZ (`0x37`), not TBZ.
pub fn s19k_bosminer_spawn_w0_test_is_tbnz() -> bool {
    BOSMINER_SPAWN_W0_TEST_IS_TBNZ
}

/// Chip-id keys painted into HashMap `V` (slot order).
pub fn s19k_bosminer_hashmap_v_key_count() -> usize {
    BOSMINER_HASHMAP_V_KEYS.len()
}

/// rustc type-path / OccupiedEntry name of HashMap `V` is unpublished.
pub fn s19k_bosminer_hashmap_v_type_named() -> bool {
    BOSMINER_HASHMAP_V_TYPE_NAMED
}

/// HashMap `V` is 0x18 with spawn fn at +0 and factory method at +8.
pub fn admit_bosminer_hashmap_v_is_18_spawn0_factory8(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_INSERT_VALUE_SIZE != 0x18 {
        return Err("HashMap V size must stay 0x18");
    }
    if BOSMINER_HASHMAP_V_SPAWN_OFF != 0 {
        return Err("spawn fn must stay V+0");
    }
    if s19k_bosminer_hashmap_v_spawn_off() != 0 {
        return Err("spawn-off helper");
    }
    if BOSMINER_HASHMAP_V_FACTORY_OFF != 8 {
        return Err("factory method must stay V+8");
    }
    if s19k_bosminer_hashmap_v_factory_off() != 8 {
        return Err("factory-off helper");
    }
    if BOSMINER_HASHMAP_V_EXTRA_OFF != 0x10 {
        return Err("insert extra must stay V+0x10");
    }
    if u32::from(BOSMINER_HASHMAP_V_SPAWN_OFF)
        + u32::from(BOSMINER_HASHMAP_V_FACTORY_OFF)
        + u32::from(BOSMINER_HASHMAP_V_EXTRA_OFF)
        != u32::from(BOSMINER_HASHMAP_INSERT_VALUE_SIZE)
    {
        return Err("0+8+0x10 must cover the 0x18 insert");
    }
    if BOSMINER_HASHMAP_GET_BL_HITS != 3 {
        return Err("get BL census must stay 3");
    }
    if s19k_bosminer_hashmap_get_bl_hits() != 3 {
        return Err("get-BL helper");
    }
    if BOSMINER_FACTORY_GET_BL_VA != 0x0083_525C {
        return Err("clone get BL must stay 0x83525c");
    }
    if BOSMINER_HASHMAP_GET_BL_B_VA != 0x0083_71F8 {
        return Err("third get BL must stay 0x8371f8");
    }
    if BOSMINER_PROD_GET_BL_VA != 0x0087_E088 {
        return Err("spawn get BL must stay 0x87e088");
    }
    if BOSMINER_SPAWN_X23_LDR_INSN != 0xF940_0037 {
        return Err("spawn must LDR X23,[X1]");
    }
    if BOSMINER_FACTORY_LDR8_INSN != 0xF940_0437 {
        return Err("clone must LDR X23,[X1,#8]");
    }
    if BOSMINER_HASHMAP_HIT_W0_BIT0 != 0 {
        return Err("HIT must stay W0 bit0==0");
    }
    if BOSMINER_HASHMAP_GET_MISS_TAG_INSN != 0x5280_0033 {
        return Err("get miss tag must stay MOVZ W19,#1");
    }
    if !BOSMINER_SPAWN_W0_TEST_IS_TBNZ || !s19k_bosminer_spawn_w0_test_is_tbnz() {
        return Err("0x87e08c must stay TBNZ 0x37");
    }
    if BOSMINER_SPAWN_TBZ_INSN != 0x3700_0F60 {
        return Err("spawn W0 test word must stay 0x37000f60");
    }
    if (BOSMINER_SPAWN_TBZ_INSN >> 24) != 0x37 {
        return Err("spawn W0 test opcode must be TBNZ");
    }
    if BOSMINER_SPAWN_TBZ_TGT != 0x0087_E278 {
        return Err("spawn TBNZ miss tgt must stay 0x87e278");
    }
    if BOSMINER_CLONE_GET_TBZ_INSN != 0x3600_03A0 {
        return Err("clone TBZ must stay 0x360003a0");
    }
    if (BOSMINER_CLONE_GET_TBZ_INSN >> 24) != 0x36 {
        return Err("clone W0 test opcode must be TBZ");
    }
    if BOSMINER_CLONE_GET_TBZ_TGT != BOSMINER_FACTORY_LDR8_VA {
        return Err("clone TBZ HIT must land on LDR [X1,#8]");
    }
    if BOSMINER_THIRD_GET_TBZ_TGT != 0x0083_7638 {
        return Err("third TBZ HIT must stay 0x837638");
    }
    if BOSMINER_SRET18_Q0_CBZ_INSN != 0xB400_1073 {
        return Err("sret qword0 must stay CBZ X19");
    }
    if BOSMINER_SRET18_Q0_CBZ_TGT != 0x0087_E370 {
        return Err("sret CBZ tgt must stay 0x87e370");
    }
    if BOSMINER_SRET18_Q2_LDAXR_INSN != 0xC85F_7D09 {
        return Err("sret qword2 must stay LDAXR X9,[X8]");
    }
    if BOSMINER_SRET18_IS_HASHMAP_V || s19k_bosminer_sret18_is_hashmap_v() {
        return Err("do not name sret 0x18 as HashMap V");
    }
    if BOSMINER_HASHMAP_V0_IS_FACTORY4 || s19k_bosminer_v0_is_factory4() {
        return Err("do not name V+0 as factory4");
    }
    if BOSMINER_HASHMAP_V8_IS_VT0 || s19k_bosminer_v8_is_vt0() {
        return Err("do not name V+8 as vt0");
    }
    if BOSMINER_FACTORY4_X8_STR_HITS != 0 {
        return Err("factory4 first-80 X8 STR census must stay 0");
    }
    if BOSMINER_ENTRY8_QWORD0_FN_VA == BOSMINER_SPAWN_BLR_VA {
        return Err("factory4 is not the spawn BLR site");
    }
    if BOSMINER_VT0_RET_INSN != 0xD65F_03C0 {
        return Err("vt0 RET word");
    }
    let tbnz =
        engine88_le_u32(blob, BOSMINER_SPAWN_TBZ_VA).ok_or("bosminer shorter than spawn TBNZ")?;
    if tbnz != BOSMINER_SPAWN_TBZ_INSN {
        return Err("0x87e08c is not TBNZ W0,#0");
    }
    let ctbz = engine88_le_u32(blob, BOSMINER_CLONE_GET_TBZ_VA)
        .ok_or("bosminer shorter than clone TBZ")?;
    if ctbz != BOSMINER_CLONE_GET_TBZ_INSN {
        return Err("0x835260 is not TBZ W0,#0");
    }
    let ldr8 = engine88_le_u32(blob, BOSMINER_FACTORY_LDR8_VA)
        .ok_or("bosminer shorter than LDR [X1,#8]")?;
    if ldr8 != BOSMINER_FACTORY_LDR8_INSN {
        return Err("0x8352d4 is not LDR X23,[X1,#8]");
    }
    let g3 = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_BL_B_VA)
        .ok_or("bosminer shorter than third get BL")?;
    if g3 != BOSMINER_HASHMAP_GET_BL_B_INSN {
        return Err("0x8371f8 is not BL 0x8787a8");
    }
    let t3 = engine88_le_u32(blob, BOSMINER_THIRD_GET_TBZ_VA)
        .ok_or("bosminer shorter than third TBZ")?;
    if t3 != BOSMINER_THIRD_GET_TBZ_INSN {
        return Err("0x8371fc is not TBZ W0");
    }
    let cbz =
        engine88_le_u32(blob, BOSMINER_SRET18_Q0_CBZ_VA).ok_or("bosminer shorter than sret CBZ")?;
    if cbz != BOSMINER_SRET18_Q0_CBZ_INSN {
        return Err("0x87e164 is not CBZ X19");
    }
    let ldx = engine88_le_u32(blob, BOSMINER_SRET18_Q2_LDAXR_VA)
        .ok_or("bosminer shorter than sret LDAXR")?;
    if ldx != BOSMINER_SRET18_Q2_LDAXR_INSN {
        return Err("0x87e174 is not LDAXR X9,[X8]");
    }
    let miss = engine88_le_u32(blob, BOSMINER_HASHMAP_GET_MISS_TAG_VA)
        .ok_or("bosminer shorter than get miss tag")?;
    if miss != BOSMINER_HASHMAP_GET_MISS_TAG_INSN {
        return Err("0x8788e4 is not MOVZ W19,#1");
    }
    Ok(())
}

/// sret 0x18 is not HashMap V / rust Result; V+0/+8 are not factory4/vt0.
pub fn refuse_sret18_as_hashmap_v_or_named_result() -> Result<(), &'static str> {
    Err(
        "HashMap V is 0x18 with spawn BLR at +0 and clone BLR at +8; get HIT is W0 bit0==0 (miss tag MOVZ #1). Spawn sret at SP+#0x68 is a different 0x18: qword0 CBZ X19, qword2 LDAXR on [SP,#0x78]. factory4 0x877d40 has 0 X8 sret stores and takes X5/X6; vt0 0x8dbdf4 RET X0 after boxing 0x250, not the clone (X0,X1) pair. Do not name Result",
    )
}

/// : HashMap `V` is the 7-key chip-id factory tuple, not a rustc type name.
pub fn admit_bosminer_hashmap_v_is_chipid_factory_tuple(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHMAP_V_SIZE != 0x18 {
        return Err("HashMap V size must stay 0x18");
    }
    if BOSMINER_HASHMAP_V_CTOR_VA != 0x0086_2458 {
        return Err("V constructor must stay FUN_00862458");
    }
    if BOSMINER_HASHMAP_V_CTOR_FRAME != 0x130 {
        return Err("FUN_00862458 frame must stay 0x130");
    }
    if BOSMINER_HASHMAP_V_WRAPPER_VA != BOSMINER_ENTRY8_INSERT_FN_VA {
        return Err("7-insert wrapper must stay FUN_008d4a10");
    }
    if BOSMINER_HASHMAP_V_WRAPPER_BL_HITS != 1 {
        return Err("wrapper BL census must stay 1");
    }
    if BOSMINER_HASHMAP_V_INSERT_UNROLL != 7 {
        return Err("wrapper unroll must stay 7");
    }
    if s19k_bosminer_hashmap_v_key_count() != 7 {
        return Err("key-count helper");
    }
    if BOSMINER_HASHMAP_V_SLOT_STRIDE != 0x20 {
        return Err("slot stride must stay 0x20");
    }
    if BOSMINER_HASHMAP_V_KEY_OFF != 0 || BOSMINER_HASHMAP_V_VALUE_OFF != 8 {
        return Err("K at slot+0, V at slot+8");
    }
    if BOSMINER_HASHMAP_V_KEYS != [0x1362, 0x1366, 0x1368, 0x1370, 0x1398, 0x1396, 0x1397] {
        return Err("slot-order chip ids drifted");
    }
    if !BOSMINER_HASHMAP_V_KEYS.contains(&BOSMINER_BM1366_CHIP_ID) {
        return Err("0x1366 must stay in the 7-key table");
    }
    if BOSMINER_AM3_CHIP_DISPATCH_IDS.len() != BOSMINER_HASHMAP_V_SIBLING_UNROLL {
        return Err("sibling 4-unroll must match AM3 4-id table");
    }
    if BOSMINER_HASHMAP_V_INSERT_BL_HITS != 13 {
        return Err("insert BL census must stay 13 (2+7+4)");
    }
    if BOSMINER_HASHMAP_V_TYPE_PATH_HITS != 0 || BOSMINER_HASHMAP_V_TYPE_NAMED {
        return Err("do not invent a HashMap V type path");
    }
    if s19k_bosminer_hashmap_v_type_named() {
        return Err("type-named helper");
    }
    if BOSMINER_HASHMAP_OCCUPIED_ENTRY_STR_HITS != 0
        || BOSMINER_HASHMAP_VACANT_ENTRY_STR_HITS != 0
        || BOSMINER_HASHMAP_V_IS_OCCUPIED_ENTRY
    {
        return Err("OccupiedEntry/VacantEntry strings must stay 0");
    }
    if BOSMINER_HASHBROWN_0145_MOD86_XREF_HITS != 1 {
        return Err("hashbrown-0.14.5:86 xref census must stay 1");
    }
    if BOSMINER_HASHBROWN_0145_MOD86_XREF_VA == BOSMINER_HASHMAP_V_CTOR_VA
        || BOSMINER_HASHBROWN_0145_MOD86_XREF_VA == BOSMINER_ENTRY8_INSERT_BL_VA
    {
        return Err("hashbrown:86 is not the V constructor");
    }
    if BOSMINER_HASHMAP_V0_IS_FACTORY4 {
        return Err("do not name V as type factory4; paint ≠ rust ident");
    }
    if BOSMINER_HASHMAP_V_1366_MOVZ_INSN != BOSMINER_AM3_CHIP_DISPATCH_1366_MOVZ_INSN {
        return Err("1366 MOVZ must stay 0x52826cca");
    }
    let pro = engine88_le_u32(blob, BOSMINER_HASHMAP_V_CTOR_VA)
        .ok_or("bosminer shorter than V ctor prologue")?;
    if pro != BOSMINER_HASHMAP_V_CTOR_PROLOGUE_INSN {
        return Err("0x862458 is not SUB SP,#0x130");
    }
    let mz = engine88_le_u32(blob, BOSMINER_HASHMAP_V_1366_MOVZ_VA)
        .ok_or("bosminer shorter than 1366 MOVZ")?;
    if mz != BOSMINER_HASHMAP_V_1366_MOVZ_INSN {
        return Err("0x862498 is not MOVZ W10,#0x1366");
    }
    let sh = engine88_le_u32(blob, BOSMINER_HASHMAP_V_1366_STRH_VA)
        .ok_or("bosminer shorter than 1366 STRH")?;
    if sh != BOSMINER_HASHMAP_V_1366_STRH_INSN {
        return Err("0x8624b4 is not STRH W10,[SP,#0x50]");
    }
    let sh0 = engine88_le_u32(blob, BOSMINER_HASHMAP_V_1362_STRH_VA)
        .ok_or("bosminer shorter than 1362 STRH")?;
    if sh0 != BOSMINER_HASHMAP_V_1362_STRH_INSN {
        return Err("0x86248c is not STRH W9,[SP,#0x30]");
    }
    let ibl = engine88_le_u32(blob, BOSMINER_ENTRY8_INSERT_BL_VA)
        .ok_or("bosminer shorter than unique wrapper BL")?;
    if ibl != BOSMINER_ENTRY8_INSERT_BL_INSN {
        return Err("0x862570 is not BL FUN_008d4a10");
    }
    let first = engine88_le_u32(blob, BOSMINER_HASHMAP_INSERT_CALL_BL_VA)
        .ok_or("bosminer shorter than first wrapper insert")?;
    if first != BOSMINER_HASHMAP_INSERT_CALL_BL_INSN {
        return Err("0x8d4a5c is not BL FUN_008da510");
    }
    let last = engine88_le_u32(blob, BOSMINER_HASHMAP_V_WRAPPER_LAST_INSERT_BL_VA)
        .ok_or("bosminer shorter than last wrapper insert")?;
    if last != BOSMINER_HASHMAP_V_WRAPPER_LAST_INSERT_BL_INSN {
        return Err("0x8d4b04 is not the 7th BL FUN_008da510");
    }
    let adrp = engine88_le_u32(blob, BOSMINER_ENTRY8_QWORD0_ADRP_VA)
        .ok_or("bosminer shorter than factory4 ADRP")?;
    if adrp != BOSMINER_ENTRY8_QWORD0_ADRP_INSN {
        return Err("0x8624a0 is not ADRP of factory4");
    }
    let add = engine88_le_u32(blob, BOSMINER_ENTRY8_QWORD0_ADD_VA)
        .ok_or("bosminer shorter than factory4 ADD")?;
    if add != BOSMINER_ENTRY8_QWORD0_ADD_INSN {
        return Err("0x8624a4 is not ADD #0xd40");
    }
    let s1366 = engine88_le_u32(blob, BOSMINER_ENTRY8_1366_STP_VA)
        .ok_or("bosminer shorter than 1366 V STP")?;
    if s1366 != BOSMINER_ENTRY8_1366_STP_INSN {
        return Err("0x8624d4 is not STP X9,X10,[SP,#0x58]");
    }
    Ok(())
}

/// HashMap `V` is not OccupiedEntry / VacantEntry / a rustc type path / hashbrown:86.
pub fn refuse_hashmap_v_as_occupied_entry_or_named_type() -> Result<(), &'static str> {
    Err(
        "HashMap V rust ident is the FUN_00862458 7-key chip-id factory tuple (stride 0x20, V at slot+8). 0 HashMap<> / OccupiedEntry / VacantEntry type-path strings. hashbrown-0.14.5 raw/mod.rs:86 xref is 0x403294, not this map. factory4 paint at 1366 V+0 is not the type name. Do not name OccupiedEntry",
    )
}

/// Exclusive first-LOAD BL census to FUN_011f2de4.
pub fn s19k_bosminer_acquire_poll_bl_hits() -> usize {
    BOSMINER_ACQUIRE_POLL_BL_HITS
}

/// Coop TLS offset used by Acquire::poll (`+0x40`, not parking_lot `+0x280`).
pub fn s19k_bosminer_acquire_poll_tls_off() -> u16 {
    BOSMINER_ACQUIRE_POLL_TLS_OFF
}

/// FUN_011f2de4 is not parking_lot RawMutex::lock.
pub fn s19k_bosminer_acquire_poll_is_raw_mutex() -> bool {
    false
}

/// FUN_011f2de4 is tokio batch_semaphore Acquire::poll with poll_acquire inlined.
pub fn admit_bosminer_11f2de4_is_acquire_poll() -> Result<(), &'static str> {
    if BOSMINER_ACQUIRE_POLL_FN_VA != BOSMINER_LOCK_POLL_ACQ_FN_VA {
        return Err("Acquire::poll VA must stay the lock-future BL target");
    }
    if BOSMINER_ACQUIRE_POLL_ENTRY_INSN != 0xD102_C3FF {
        return Err("0x11f2de4 is not SUB SP,#0xb0");
    }
    if BOSMINER_ACQUIRE_POLL_BL_HITS != 34 {
        return Err("0x11f2de4 BL census must stay 34");
    }
    if s19k_bosminer_acquire_poll_bl_hits() != 34 {
        return Err("acquire-poll BL helper");
    }
    if BOSMINER_ACQUIRE_POLL_JT_BL_HITS != 0 {
        return Err("0x11f2de4 must have 0 JT BLs");
    }
    if BOSMINER_ACQUIRE_POLL_TLS_OFF != 0x40 {
        return Err("Acquire::poll TLS must stay +0x40");
    }
    if s19k_bosminer_acquire_poll_tls_off() != 0x40 {
        return Err("acquire-poll TLS helper");
    }
    if BOSMINER_ACQUIRE_POLL_X1_MOV_INSN != 0xAA01_03F5 {
        return Err("0x11f2e0c is not MOV X21,X1");
    }
    if BOSMINER_ACQUIRE_POLL_MRS_INSN != 0xD53B_D058 {
        return Err("0x11f2e20 is not MRS TPIDR_EL0");
    }
    if BOSMINER_ACQUIRE_POLL_TLS_MOVZ_INSN != 0xD2A0_0000 {
        return Err("0x11f2e10 is not MOVZ X0,#0,LSL#16");
    }
    if BOSMINER_ACQUIRE_POLL_TLS_MOVK_INSN != 0xF280_0800 {
        return Err("0x11f2e14 is not MOVK X0,#0x40");
    }
    if BOSMINER_ACQUIRE_POLL_COOP_ADD_INSN != 0x9118_4021 {
        return Err("0x11f3024 is not ADD coop loc");
    }
    if BOSMINER_ACQUIRE_POLL_RET_INSN != 0xD65F_03C0 {
        return Err("0x11f332c is not RET");
    }
    if BOSMINER_ACQUIRE_POLL_PAD425_ADD_INSN != 0x9116_6042 {
        return Err("0x11f333c is not ADD loc 425");
    }
    if BOSMINER_ACQUIRE_POLL_PAD493_ADD_INSN != 0x9116_C084 {
        return Err("0x11f335c is not ADD loc 493");
    }
    if BOSMINER_ACQUIRE_POLL_LOC425_LINE != 425 || BOSMINER_ACQUIRE_POLL_LOC425_COL != 18 {
        return Err("inlined poll_acquire loc must stay 425:18");
    }
    if BOSMINER_ACQUIRE_POLL_LOC493_LINE != 493 || BOSMINER_ACQUIRE_POLL_LOC493_COL != 9 {
        return Err("inlined poll_acquire loc must stay 493:9");
    }
    if BOSMINER_ACQUIRE_POLL_COOP_LINE != 345 || BOSMINER_ACQUIRE_POLL_COOP_COL != 13 {
        return Err("coop register_waker loc must stay 345:13");
    }
    if !BOSMINER_BATCH_SEMAPHORE_RS.ends_with("batch_semaphore.rs") {
        return Err("batch_semaphore path");
    }
    if !BOSMINER_COOP_MOD_RS.ends_with("coop/mod.rs") {
        return Err("coop/mod path");
    }
    if s19k_bosminer_acquire_poll_is_raw_mutex() {
        return Err("must not claim RawMutex");
    }
    Ok(())
}

/// Not RawMutex::lock / parking_lot Mutex::lock / standalone poll_acquire.
pub fn refuse_11f2de4_as_raw_mutex_or_standalone_poll_acquire() -> Result<(), &'static str> {
    Err(
        "FUN_011f2de4 is 2-arg Future::poll (MOV X21,X1 Context; lock-future ADD #0x28 as X0). Body materializes coop/mod.rs:345:13 register_waker (TLS +0x40), so it is not standalone Semaphore::poll_acquire (no coop) and not parking_lot RawMutex::lock (no raw_mutex.rs; parking_lot TLS is +0x280). Panic pads after RET are batch_semaphore.rs:425:18 and :493:9 from inlined poll_acquire",
    )
}

/// `0x626aac` second inbound stores `X8+0x20`, not `*X23`.
pub fn admit_bosminer_hashmap_626aac_second_arm_is_x8_plus20(
    blob: &[u8],
) -> Result<(), &'static str> {
    let add = engine88_le_u32(blob, BOSMINER_HASHMAP_626FB0_ADD20_VA)
        .ok_or("bosminer shorter than ADD X0,X8,#0x20")?;
    if add != BOSMINER_HASHMAP_626FB0_ADD20_INSN {
        return Err("0x626fb0 is not ADD X0,X8,#0x20");
    }
    let b = engine88_le_u32(blob, BOSMINER_HASHMAP_626FC0_B_VA)
        .ok_or("bosminer shorter than second B 0x626aac")?;
    if b != BOSMINER_HASHMAP_626FC0_B_INSN {
        return Err("0x626fc0 is not B 0x626aac");
    }
    let st = engine88_le_u32(blob, BOSMINER_HASHMAP_626AAC_VA)
        .ok_or("bosminer shorter than STR X0 #0x88")?;
    if st != BOSMINER_HASHMAP_626AAC_STR_INSN {
        return Err("0x626aac is not STR X0,[X19,#0x88]");
    }
    Ok(())
}

/// Job-id byte in the 8-byte work-response word (`u64 >> 0x28`).
pub fn s19k_braiins_uart_job_byte_from_payload8(payload_le: u64) -> u8 {
    (payload_le >> u64::from(BOSMINER_WORK_RESP_JOB_SHIFT)) as u8
}

/// Version u16 in payload bytes [6:7], byte-swapped like `FUN_0091c0a0`.
pub fn s19k_braiins_uart_version_from_payload8(payload_le: u64) -> u16 {
    ((payload_le >> 48) as u16).swap_bytes()
}

/// `FUN_0091c0a0` version AND-mask width is MidstateCount log, not 16 BIP320 bits.
/// Fill midstates=1 ⇒ log 0 ⇒ mask 0.
pub fn s19k_braiins_uart_version_mask_from_log(midstate_log: u32) -> Result<u16, &'static str> {
    let _ = s19k_braiins_midstate_count_from_log(midstate_log)?;
    if midstate_log == 0 {
        return Ok(0);
    }
    if midstate_log >= 16 {
        return Err("version mask width >= 16");
    }
    Ok((1u16 << midstate_log) - 1)
}

/// Bosminer UART WorkResponse version field: `bswap16(payload[6:8]) & ((1<<log)-1)`.
/// Does **not** replace ESP/BIP320 `version_be << 13` share reconstruct.
pub fn s19k_braiins_uart_version_bits(
    version_be: u16,
    midstate_log: u32,
) -> Result<u16, &'static str> {
    Ok(version_be & s19k_braiins_uart_version_mask_from_log(midstate_log)?)
}

/// `FUN_00bf2478(engine+0x60)`: tag `+0x20`==1 → `FUN_0125fc94(*(self+0x18))`, else `*(self+0x10)`.
pub fn admit_bosminer_bf2478_is_midstate_log_helper() -> Result<(), &'static str> {
    if BOSMINER_VERWIDTH_LDRB20_INSN != 0x3940_8008 {
        return Err("LDRB [X0,#0x20] tag");
    }
    if BOSMINER_VERWIDTH_LDR18_INSN != 0xF940_0C00 {
        return Err("LDR X0,[X0,#0x18] count");
    }
    if BOSMINER_VERWIDTH_B_LOG_INSN != 0x1419_B603 {
        return Err("B FUN_0125fc94 tail-call");
    }
    if BOSMINER_VERWIDTH_LDR10_INSN != 0xF940_0800 {
        return Err("LDR X0,[X0,#0x10] already-log");
    }
    if BOSMINER_MIDSTATE_COUNT_FN_VA != 0x0125_FC94 {
        return Err("count→log is FUN_0125fc94");
    }
    Ok(())
}

/// UART parse `param_1[4]` width is that MidstateCount log (path requires engine+0x80==1).
pub fn admit_bosminer_uart_version_width_is_midstate_log() -> Result<(), &'static str> {
    if BOSMINER_VERWIDTH_FN_VA != 0x00BF_2478 {
        return Err("FUN_00bf2478");
    }
    if BOSMINER_ENGINE_MIDSTATE_COUNT_OFF != 0x78 {
        return Err("count lives at engine+0x78 (= helper +0x18)");
    }
    if s19k_braiins_uart_version_mask_from_log(0)? != 0 {
        return Err("fill log 0 ⇒ mask 0");
    }
    if s19k_braiins_uart_version_mask_from_log(3)? != 7 {
        return Err("log 3 ⇒ mask 0b111");
    }
    if s19k_braiins_uart_version_bits(0xABCD, 0)? != 0 {
        return Err("fill path zeros the WorkResponse version field");
    }
    Ok(())
}

/// Bosminer UART version field is not a 16-bit BIP320 mask.
pub fn refuse_bip320_16_as_bosminer_uart_version_width() -> Result<(), &'static str> {
    if s19k_braiins_uart_version_mask_from_log(0).ok() != Some(0) {
        return Ok(());
    }
    Err("FUN_0091c0a0 masks version to ((1<<FUN_00bf2478(engine+0x60))-1), not 16 BIP320 bits")
}

/// `FUN_00bf2478` is not a BIP320 `0x1FFFE000` computer.
pub fn refuse_bf2478_as_bip320_mask() -> Result<(), &'static str> {
    if BOSMINER_VERWIDTH_B_LOG_INSN != 0x1419_B603 {
        return Ok(());
    }
    Err("FUN_00bf2478 is MidstateCount::log (1→0 / 2→1 / 4→2 / 8→3); not 0x1FFFE000")
}

/// Five identical UART wrappers (`0x101c`) `BL FUN_0091c0a0` then Ok-gate then `FUN_00bf6c2c`.
pub fn admit_bosminer_five_uart_parse_callers() -> Result<(), &'static str> {
    if BOSMINER_UART_WRAP_HITS != 5 {
        return Err("5 UART wrappers");
    }
    if BOSMINER_UART_WRAP_SIZE != 0x101C {
        return Err("each wrapper is 0x101c");
    }
    if BOSMINER_UART_PARSE_BL_A_INSN != 0x9400_A5AC {
        return Err("FUN_008f262c BL FUN_0091c0a0");
    }
    if BOSMINER_UART_OK_LDR_INSN != 0xB941_A3E8 {
        return Err("LDR W Result tag [SP,#0x1a0]");
    }
    if BOSMINER_UART_OK_TBZ_INSN != 0x3600_1088 {
        return Err("TBZ W,#0 Ok gate");
    }
    if BOSMINER_UART_CONS_MOVZ11D0_INSN != 0x5282_3A08 {
        return Err("MOVZ #0x11d0");
    }
    if BOSMINER_UART_CONS_ADD_X0_INSN != 0x8B08_0260 {
        return Err("ADD X0,X19,X8 worker+0x11d0");
    }
    if BOSMINER_UART_CONS_BL_A_INSN != 0x940C_1001 {
        return Err("BL FUN_00bf6c2c");
    }
    Ok(())
}

/// `FUN_00bf6c2c` is registry/submit (`MOVZ #0x78` slot stride), not a version expander.
pub fn admit_bosminer_bf6c2c_is_registry_submit() -> Result<(), &'static str> {
    if BOSMINER_RESP_CONSUMER_FN_VA != 0x00BF_6C2C {
        return Err("FUN_00bf6c2c");
    }
    if BOSMINER_RESP_CONSUMER_MOV_X26_INSN != 0xAA01_03FA {
        return Err("MOV X26,X1 WorkResponse");
    }
    if BOSMINER_RESP_CONSUMER_MOVZ78_INSN != 0x5280_0F08 {
        return Err("MOVZ #0x78 registry stride");
    }
    if BOSMINER_REGISTRY_SLOT_STRIDE != 0x78 {
        return Err("slot stride already 0x78");
    }
    Ok(())
}

/// `FUN_00bf6c2c` does not `LSL #13` / build `0x1FFFE000`.
pub fn refuse_bf6c2c_as_bip320_reexpand() -> Result<(), &'static str> {
    if BOSMINER_BF6C_LSL13_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_BIP320_MOVP_HITS != 0 {
        return Ok(());
    }
    Err("FUN_00bf6c2c has 0 LSL#13 and first-LOAD has 0 MOVZ#E000+MOVK#1FFF; no BIP320 re-expand")
}

/// The five UART wrappers do not re-expand version after parse.
pub fn refuse_uart_wrappers_as_bip320_reexpand() -> Result<(), &'static str> {
    if BOSMINER_UART_WRAP_LSL13_HITS != 0 {
        return Ok(());
    }
    Err("5 UART wrappers 0 LSL#13; Ok path only copies WorkResponse into FUN_00bf6c2c")
}

/// First-LOAD `STRB #0x228` (Xn!=SP) is exactly 24.
pub fn admit_bosminer_strb228_census_is_24() -> Result<(), &'static str> {
    if BOSMINER_STRB228_NONSP_HITS != 24 {
        return Err("24 STRB #0x228 Xn!=SP");
    }
    if BOSMINER_STRB228_WZR_HITS != 16 {
        return Err("16 are STRB WZR");
    }
    if BOSMINER_STRB228_WZR_INSN != 0x3908_A27F {
        return Err("STRB WZR,[X19,#0x228]");
    }
    Ok(())
}

/// Three Default-like inits store immediate `0x7c` at +0x228.
pub fn admit_bosminer_strb228_7c_is_three() -> Result<(), &'static str> {
    if BOSMINER_STRB228_7C_HITS != 3 {
        return Err("3 MOVZ#0x7c + STRB #0x228");
    }
    if BOSMINER_STRB228_7C_MOVZ_INSN != 0x5280_0F88 {
        return Err("MOVZ W8,#0x7c");
    }
    if BOSMINER_STRB228_7C_STRB_INSN != 0x3908_A268 {
        return Err("STRB W8,[X19,#0x228]");
    }
    Ok(())
}

/// `FUN_00bf26d0` is the engine-absolute MidstateCount→log sibling of `FUN_00bf2478`.
pub fn admit_bosminer_bf26d0_is_engine_abs_log() -> Result<(), &'static str> {
    if BOSMINER_LOG_ABS_LDRB80_INSN != 0x3942_0008 {
        return Err("LDRB [X0,#0x80]");
    }
    if BOSMINER_LOG_ABS_LDR78_INSN != 0xF940_3C00 {
        return Err("LDR [X0,#0x78] count");
    }
    if BOSMINER_LOG_ABS_B_INSN != 0x1419_B56D {
        return Err("B FUN_0125fc94");
    }
    if BOSMINER_LOG_ABS_LDR70_INSN != 0xF940_3800 {
        return Err("LDR [X0,#0x70] already-log");
    }
    if BOSMINER_MIDSTATE_COUNT_FN_VA != 0x0125_FC94 {
        return Err("same count→log");
    }
    Ok(())
}

/// WZR / `0x7c` / iterator-flag STRB are not the HashChain +0x228 u32 tag.
pub fn refuse_strb228_7c_as_hashchain_tag() -> Result<(), &'static str> {
    if BOSMINER_STRB228_7C_MOVZ_INSN != 0x5280_0F88 {
        return Ok(());
    }
    Err("STRB #0x7c is a Default field (FUN_005f4a8c/79b4d4/9c6fc4); HashChain tag is u32 via prep")
}

/// `FUN_00c906e8` +0x228/+0x229/+0x22a are iterator bit-flags, not HashChain.
pub fn refuse_c906e8_as_hashchain_228() -> Result<(), &'static str> {
    if BOSMINER_STRB228_C906_INSN != 0x3908_A288 {
        return Ok(());
    }
    Err("FUN_00c906e8 polls +0x228/+0x229/+0x22a bit flags on a +0x1c0 iterator; not HashChain")
}

/// `Worker::new` / AM3 factory do not mint engine+0x88; they copy/clone it.
pub fn refuse_worker_new_as_engine_88_mint() -> Result<(), &'static str> {
    if BOSMINER_WORKER_NEW_STR88_HITS != 0 {
        return Ok(());
    }
    if BOSMINER_FACTORY_STR88_HITS != 0 {
        return Ok(());
    }
    Err("FUN_00903534 0 STR#0x88 (memcpy 0x1c8 of param_3); FUN_00876ca8 0 STR#0x88 (clone [0x11])")
}

/// First-LOAD has exactly seven `BL FUN_00bf26d0` sites.
pub fn admit_bosminer_bf26d0_has_seven_bl_callers() -> Result<(), &'static str> {
    if BOSMINER_LOG_ABS_BL_CALLERS != 7 {
        return Err("FUN_00bf26d0 has 7 BL callers");
    }
    if BOSMINER_LOG_ABS_WORKER_BL_HITS != 5 {
        return Err("5 are Worker monomorphs");
    }
    if BOSMINER_LOG_ABS_FPGA_BL_INSN != 0x940D_0F15 {
        return Err("FUN_008aea30 BL FUN_00bf26d0");
    }
    if BOSMINER_LOG_ABS_ONESHR_BL_INSN != 0x9403_30CD {
        return Err("1>>log tail BL FUN_00bf26d0");
    }
    if BOSMINER_LOG_REL_BL_CALLERS != 1 {
        return Err("FUN_00bf2478 has 1 BL (UART parse)");
    }
    if BOSMINER_LOG_REL_PARSE_BL_INSN != 0x940B_58DD {
        return Err("FUN_0091c0a0 BL FUN_00bf2478 entry");
    }
    Ok(())
}

/// Five Worker ctors pass engine then feed abs-log into Registry wrap X3.
pub fn admit_bosminer_workers_pass_abs_log_to_registry() -> Result<(), &'static str> {
    if BOSMINER_LOG_ABS_WORKER_MOV_X0_INSN != 0xAA18_03E0 {
        return Err("4 workers MOV X0,X24 (engine)");
    }
    if BOSMINER_LOG_ABS_WORKER_NEW_MOV_X0_INSN != 0xAA19_03E0 {
        return Err("FUN_00903534 MOV X0,X25 (engine)");
    }
    if BOSMINER_LOG_ABS_WORKER_A_BL_INSN != 0x940B_C734 {
        return Err("FUN_00900810 BL FUN_00bf26d0");
    }
    if BOSMINER_LOG_ABS_WORKER_NEW_BL_INSN != 0x940B_BC27 {
        return Err("FUN_00903534 BL FUN_00bf26d0");
    }
    if BOSMINER_LOG_ABS_WORKER_MOV_X3_INSN != 0xAA00_03E3 {
        return Err("MOV X3,X0 (log → Registry wrap)");
    }
    if BOSMINER_LOG_ABS_WORKER_NEW_REG_BL_INSN != 0x940B_D047 {
        return Err("FUN_00903534 BL FUN_00bf7798");
    }
    if BOSMINER_REGISTRY_WRAP_FN_VA != 0x00BF_7798 {
        return Err("Registry wrap is FUN_00bf7798");
    }
    for (i, &site) in BOSMINER_LOG_ABS_WORKER_BL_VAS.iter().enumerate() {
        let ctor = BOSMINER_AM3_WORKER_CTOR_VAS[i];
        if site < ctor || site > ctor + 0x400 {
            return Err("abs-log BL is outside its Worker ctor");
        }
    }
    Ok(())
}

/// FPGA factory `FUN_008aea30` also calls the engine-absolute log.
pub fn admit_bosminer_fpga_factory_calls_abs_log() -> Result<(), &'static str> {
    if BOSMINER_FPGA_REGISTRY_FACTORY_VA != 0x008A_EA30 {
        return Err("FPGA factory VA");
    }
    if BOSMINER_LOG_ABS_FPGA_MOV_X0_INSN != 0xAA01_03E0 {
        return Err("FPGA MOV X0,X1 then abs log");
    }
    if BOSMINER_FPGA_LOG_VALIDATE_BL_INSN != 0x9402_01EB {
        return Err("FPGA then BL FUN_0092f240");
    }
    if BOSMINER_FPGA_LOG_VALIDATE_FN_VA != 0x0092_F240 {
        return Err("FUN_0092f240 is the log validator");
    }
    Ok(())
}

/// `MOVZ #1; LSRV X0,X8,X0` after abs-log is `1>>log`, not UART registry size.
pub fn admit_bosminer_b2639c_is_one_shr_log() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_MOVZ_INSN != 0x5280_0028 {
        return Err("MOVZ W8,#1");
    }
    if BOSMINER_ONESHR_LSRV_INSN != 0x9AC0_2100 {
        return Err("LSRV X0,X8,X0");
    }
    if BOSMINER_ONESHR_RET_INSN != 0xD65F_03C0 {
        return Err("RET after 1>>log");
    }
    if BOSMINER_ONESHR_FN_VA != 0x00B2_6398 {
        return Err("FUN_00b26398 is the 1>>log leaf");
    }
    if BOSMINER_ONESHR_PROLOGUE_INSN != 0xF81F_0FFE {
        return Err("STR X30,[SP,#-0x10]!");
    }
    if BOSMINER_ONESHR_EPILOGUE_INSN != 0xF841_07FE {
        return Err("LDR X30,[SP],#0x10");
    }
    if BOSMINER_ONESHR_BL_CALLERS != 9 {
        return Err("9 BL callers of FUN_00b26398");
    }
    if BOSMINER_ONESHR_CALLER_A_INSN != 0x941A_A841 {
        return Err("first caller BL FUN_00b26398");
    }
    if s19k_braiins_one_shr_log(0)? != 1 {
        return Err("fill log0 → 1");
    }
    if s19k_braiins_one_shr_log(3)? != 0 {
        return Err("MS8 log3 → 0");
    }
    Ok(())
}

/// `1>>log` is not the UART `0x100>>log` registry size.
pub fn refuse_one_shr_log_as_uart_registry_size() -> Result<(), &'static str> {
    let one = s19k_braiins_one_shr_log(0)?;
    let size = u64::from(s19k_braiins_uart_registry_size_from_log(0)?);
    if one == size {
        return Ok(());
    }
    Err("1>>log is the FUN_00b2639c tail; UART registry_size stays 0x100>>log")
}

/// Fill / midstates=1 is the only log that makes `1>>log` nonzero.
pub fn s19k_braiins_oneshr_is_fill_log(log: u32) -> Result<bool, &'static str> {
    Ok(s19k_braiins_one_shr_log(log)? != 0)
}

/// 6/9 oneshr callers store X0; 3/9 discard it after sibling `FUN_00b263f4`.
pub fn admit_bosminer_oneshr_six_store_three_discard() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_STACK_STORE_HITS != 6 {
        return Err("6 STR X0 of 1>>log");
    }
    if BOSMINER_ONESHR_DISCARD_HITS != 3 {
        return Err("3 discarders");
    }
    if BOSMINER_ONESHR_STR_3280_INSN != 0xF919_43E0 {
        return Err("STR X0,[SP,#0x3280]");
    }
    if BOSMINER_ONESHR_STR_2A70_INSN != 0xF915_3BE0 {
        return Err("STR X0,[SP,#0x2a70]");
    }
    if BOSMINER_ONESHR_STR_3280_OFF != 0x3280 || BOSMINER_ONESHR_STR_2A70_OFF != 0x2A70 {
        return Err("stack slots");
    }
    if BOSMINER_ONESHR_DISCARD_SIMD_INSN != 0x3DC7_4BE0 {
        return Err("discard +4 is SIMD, not STR X0");
    }
    if BOSMINER_ONESHR_SIB_ADD400_INSN != 0x9110_0001 {
        return Err("sibling ADD X1,X0,#0x400");
    }
    if BOSMINER_ONESHR_SIB_BL_HITS != 3 {
        return Err("3 BL FUN_00b263f4");
    }
    Ok(())
}

/// dest+2 1→0 around the 3 discarders is not the 1>>log value.
pub fn refuse_oneshr_flag2_toggle_as_one_shr_result() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_FLAG2_SET_INSN != 0x3900_0AC8 {
        return Ok(());
    }
    if BOSMINER_ONESHR_FLAG2_CLR_INSN != 0x3900_0ADF {
        return Ok(());
    }
    Err("discarders STRB #1 then STRB WZR at dest+2; that toggle is not 1>>log")
}

/// Recovered bosminer layouts (OFFLINE_PROVEN offsets only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBosminerJobLayout {
    pub size: usize,
    pub prevhash: usize,
    pub merkle: usize,
    pub nbits: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBosminerEngineLayout {
    pub midstate_log: usize,
    pub midstate_count: usize,
    pub nonce_fn: usize,
    pub job_id_fn: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBosminerFillLayout {
    pub prefix: usize,
    pub job_id: usize,
    pub midstates: usize,
    pub nonce: usize,
    pub nbits: usize,
    pub ntime: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBosminerHashChainLayout {
    pub rx_copy: usize,
    pub div: usize,
    pub worker_div: usize,
}

pub const S19K_BOSMINER_JOB: S19kBosminerJobLayout = S19kBosminerJobLayout {
    size: BOSMINER_JOB_SIZE,
    prevhash: BOSMINER_JOB_PREVHASH_OFF,
    merkle: BOSMINER_JOB_MERKLE_OFF,
    nbits: BOSMINER_JOB_NBITS_OFF,
};

pub const S19K_BOSMINER_ENGINE: S19kBosminerEngineLayout = S19kBosminerEngineLayout {
    midstate_log: BOSMINER_ENGINE_MIDSTATE_LOG_OFF,
    midstate_count: BOSMINER_ENGINE_MIDSTATE_COUNT_OFF,
    nonce_fn: BOSMINER_ENGINE_NONCE_FN_OFF,
    job_id_fn: BOSMINER_ENGINE_JOB_ID_FN_OFF,
};

pub const S19K_BOSMINER_FILL: S19kBosminerFillLayout = S19kBosminerFillLayout {
    prefix: BOSMINER_FILL_PREFIX_OFF,
    job_id: BOSMINER_FILL_JOB_ID_OFF,
    midstates: BOSMINER_FILL_MIDSTATES_OFF,
    nonce: BOSMINER_FILL_NONCE_OFF,
    nbits: BOSMINER_FILL_NBITS_OFF,
    ntime: BOSMINER_FILL_NTIME_OFF,
};

pub const S19K_BOSMINER_HASHCHAIN: S19kBosminerHashChainLayout = S19kBosminerHashChainLayout {
    rx_copy: BOSMINER_HASHCHAIN_RX_COPY_OFF,
    div: BOSMINER_HASHCHAIN_DIV_OFF,
    worker_div: BOSMINER_UART_WORK_RESP_DIV_OFF,
};

pub fn admit_s19k_bosminer_layouts() -> Result<(), &'static str> {
    if S19K_BOSMINER_JOB.size != 0x80 || S19K_BOSMINER_JOB.nbits != 0x78 {
        return Err("Job 0x80 nbits+0x78");
    }
    if S19K_BOSMINER_ENGINE.midstate_log != 0x70 || S19K_BOSMINER_ENGINE.job_id_fn != 0x90 {
        return Err("engine +0x70 log / +0x90 job_id fn");
    }
    if BOSMINER_ENGINE_WORK_TYPE_OFF != 0x80 || BOSMINER_WORK_TYPE_VERSION_ROLLING != 1 {
        return Err("engine +0x80 work-type VR=1");
    }
    if S19K_BOSMINER_FILL.midstates != 0x55 || BOSMINER_FILL_MIDSTATES != 1 {
        return Err("fill +0x55=1");
    }
    if S19K_BOSMINER_HASHCHAIN.rx_copy + S19K_BOSMINER_HASHCHAIN.worker_div
        != S19K_BOSMINER_HASHCHAIN.div
    {
        return Err("HashChain+0x11F0 = +0x30 + Worker+0x11c0");
    }
    if BOSMINER_WORKER_SIZE != 0x1C8 {
        return Err("Worker 0x1C8");
    }
    Ok(())
}

/// #0x3280 oneshr STR is overwritten by STR X8 with 0 mid LDR/STR.
pub fn refuse_3280_oneshr_str_as_live_consumer() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_3280_MID_LDST != 0 {
        return Ok(());
    }
    if BOSMINER_ONESHR_3280_OVERWRITE_INSN != 0xF919_43E8 {
        return Ok(());
    }
    Err("STR X0 #0x3280 has 0 mid ldst then STR X8; later LDR reads the pointer overwrite")
}

/// #0x2a70 LDR after a RET is Arc LDXR in another fn, not oneshr 0/1.
pub fn refuse_2a70_ldxr_as_oneshr_consumer() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_2A70_RET_BETWEEN != 1 {
        return Ok(());
    }
    if BOSMINER_ONESHR_2A70_LDXR_INSN != 0xC85F_7D09 {
        return Ok(());
    }
    Err("LDR #0x2a70 after RET is LDXR drop of another frame; not 1>>log")
}

/// No caller inspects X0 as a 0/1 flag in the 0x80-byte window after the BL.
pub fn admit_bosminer_oneshr_no_x0_cond_branch() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_CALLER_VAS.len() != BOSMINER_ONESHR_BL_CALLERS {
        return Err("oneshr caller VA table must list all 9 BLs");
    }
    if BOSMINER_ONESHR_CALLER_VAS[0] != BOSMINER_ONESHR_CALLER_A_VA {
        return Err("caller[0] is FUN clone A");
    }
    if BOSMINER_ONESHR_X0_COND_HITS != 0 {
        return Err("unexpected CBZ/CBNZ/TBZ X0 after oneshr BL");
    }
    Ok(())
}

/// The three LDR [SP,#0x3280] sit after STR X8 overwrite and load a pointer pair.
pub fn refuse_3280_ldr_as_oneshr_consumer() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_3280_LDR_HITS != 3 {
        return Ok(());
    }
    if BOSMINER_ONESHR_3280_LDR_VA <= BOSMINER_ONESHR_3280_OVERWRITE_VA {
        return Ok(());
    }
    if BOSMINER_ONESHR_3280_LDR_INSN != 0xF959_43E0 {
        return Ok(());
    }
    if BOSMINER_ONESHR_3280_LDR_NEXT_INSN != 0xF959_63E1 {
        return Ok(());
    }
    Err("LDR #0x3280 is after X8 overwrite; next insn LDR X1 (pointer pair), not 1>>log")
}

/// Early LDR [SP,#0x2a70] X6 is before the oneshr STR; not the 0/1 result.
pub fn refuse_2a70_early_ldr_as_oneshr_consumer() -> Result<(), &'static str> {
    if BOSMINER_ONESHR_2A70_LDR_HITS != 6 {
        return Ok(());
    }
    if BOSMINER_ONESHR_2A70_EARLY_LDR_VA >= BOSMINER_ONESHR_STR_2A70_VA {
        return Ok(());
    }
    if BOSMINER_ONESHR_2A70_EARLY_LDR_INSN != 0xF955_3BE6 {
        return Ok(());
    }
    Err("LDR #0x2a70 X6 is before oneshr STR; stack slot reused, not 1>>log")
}

/// Legacy function name: validates the parser's REV-before-BLR sequence, not
/// a nonce transform. BM1366's BLR return is an attribution tuple.
pub fn admit_bosminer_work_resp_rev_then_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_WORK_RESP_LDR88_INSN != 0xF940_4428 {
        return Err("LDR X8,[X1,#0x88] before REV");
    }
    if BOSMINER_WORK_RESP_REV_INSN != 0x5AC0_0B00 {
        return Err("FUN_0091c0a0 is not REV W0,W24 before blr +0x88");
    }
    if BOSMINER_WORK_RESP_BLR_INSN != 0xD63F_0100 {
        return Err("BLR X8 after REV");
    }
    if BOSMINER_ENGINE_NONCE_FN_OFF != 0x88 {
        return Err("attribution callback is engine+0x88");
    }
    if s19k_braiins_uart_nonce_arg_from_payload8(0x0000_0000_DDCC_BBAA) != 0xAABB_CCDD {
        return Err("payload low32 REV is from_be nonce word");
    }
    if s19k_braiins_fill_nonce_word(0xAABB_CCDD) != 0xAABB_CCDD {
        return Err("fill nonce word is identity on the REV argument");
    }
    Ok(())
}

/// +0x88 is not a 2-insn `REV W0,W0; RET`; BM1366 resolves to the recovered
/// multi-instruction attribution callback.
pub fn refuse_rev_w0_ret_as_engine_nonce_fn() -> Result<(), &'static str> {
    if BOSMINER_REV_W0_RET_HITS == 0 {
        return Err("no REV W0,W0;RET in first LOAD; BM1366 +0x88 is FUN_009256ac attribution");
    }
    Ok(())
}

/// Encoder body is not MUL/LSLV of (work_id, count); formula stays RX-inverse.
pub fn refuse_mul_lslv_ret_as_named_job_id_encoder() -> Result<(), &'static str> {
    if BOSMINER_MUL_W0_W1_RET_HITS != 0 || BOSMINER_LSLV_W0_W0_RET_HITS != 0 {
        return Ok(());
    }
    Err("no MUL W0,W0,W1;RET or LSLV W0,W0,Wm;RET; +0x90 body still unlocated")
}

/// : no exclusive `.text` fn is stored at worker+0x90; memcpy 0x1C8 only.
pub fn refuse_unlocated_engine_job_id_fn_as_named_encoder() -> Result<(), &'static str> {
    if BOSMINER_JOB_ID_FN_ADRP_STR_HITS != 0 || BOSMINER_LSL3_RET_HITS != 0 {
        return Ok(());
    }
    Err("engine+0x90 is copied with the 0x1C8 Worker; no ADRP+STR .text fn and no LSL#3;ret encoder")
}

/// `0xE0000020` in Worker::new is a tracing FieldSet mask, not registry_size=32.
pub fn refuse_worker_ctor_e0000020_as_registry_size(word: u32) -> Result<(), &'static str> {
    if word == BOSMINER_WORKER_CTOR_TRACE_MASK {
        return Err(
            "Worker ctor 0xE0000020 is movz#0x20+movk#0xe000 tracing mask, not registry_size",
        );
    }
    Ok(())
}

/// The only `and w0,w0,#0xff; ret` is unreferenced — not the UART encoder.
pub fn refuse_unreferenced_and_ff_ret_as_uart_job_id() -> Result<(), &'static str> {
    if BOSMINER_AND_FF_RET_XREFS == 0 {
        return Err("AND#0xFF;RET @ 0x010af790 has 0 xrefs; not engine+0x90");
    }
    Ok(())
}

/// Read nbits from a 0x80-byte `stratum_v2` Job object (`FUN_00d1372c` layout).
pub fn s19k_braiins_job_nbits_from_object(job: &[u8]) -> Result<u32, &'static str> {
    if job.len() != BOSMINER_JOB_SIZE {
        return Err("stratum_v2 Job object is 0x80 bytes");
    }
    let bytes: [u8; 4] = job[BOSMINER_JOB_NBITS_OFF..BOSMINER_JOB_NBITS_OFF + 4]
        .try_into()
        .map_err(|_| "nbits slice")?;
    Ok(u32::from_le_bytes(bytes))
}

/// `0x36` is the hardcoded DAT prefix length byte, not ESP `data_len+4`.
pub fn refuse_len_field_36_as_esp_data_len_plus_4(len_field: u8) -> Result<(), &'static str> {
    if len_field == 0x36 && FPGA_ESP_JOB_PAYLOAD_LEN + 4 == FPGA_ESP_JOB_LEN_FIELD as usize {
        return Err("0x36 is DAT_012ec448[3], not ESP sizeof(BM1366_job)+4=0x56");
    }
    Ok(())
}

///  Ghidra: the 0xEEC448 bytes **are** the packer prefix.
pub fn admit_bosminer_ghidra_pack_prefix_21_36() -> Result<(), &'static str> {
    if BOSMINER_GHIDRA_PREFIX != CLOSED_11D_PREFIX {
        return Err("bosminer DAT_012ec448 is not 55 AA 21 36");
    }
    if BOSMINER_PREFIX_CONST_VA != 0x400000 + BOSMINER_55AA2136_COLLISION_OFF {
        return Err("prefix VA is not image_base + file off 0xEEC448");
    }
    Ok(())
}

/// Historical name.  refuse is superseded by [`admit_bosminer_ghidra_pack_prefix_21_36`].
pub fn refuse_bosminer_55aa2136_collision_as_job_template() -> Result<(), &'static str> {
    admit_bosminer_ghidra_pack_prefix_21_36()
        .map_err(|_| "bosminer 55AA2136 @ 0xEEC448 / VA 0x12ec448 is the packer prefix")?;
    Err("superseded: Ghidra FUN_0091ba88 loads this as dest[0:4]; not a collision")
}

/// : packed_struct next to `bm136x.rs` does not name 0x36 vs 0x56.
pub fn refuse_packed_struct_string_as_job_length_fact() -> Result<(), &'static str> {
    Err("bosminer packed_struct-0.10.1 + bm136x.rs has no on-wire length-field literal; T1 stays DESK_PENDING")
}

/// : the unique `bm136x.rs` ADRP+ADD site is not a length-field proof.
pub fn refuse_bm136x_xref_as_job_length_fact() -> Result<(), &'static str> {
    Err("bosminer VA 0x9208CC xrefs bm136x.rs:36:26 with no #0x21/#0x36/#0x56 immediates; not the packer")
}

/// /273: `0x9208F8` is `bm13xx.rs:200` broadcast assert, not `bm136x.rs:46`.
pub fn refuse_bm136x_panic_site_as_job_packer() -> Result<(), &'static str> {
    Err("bosminer VA 0x9208F8 is panic(bm13xx.rs:200, !chip_address.is_broadcast()); MOVZ #0x2E is strlen 46, not rustc line 46")
}

/// : zero `BL` callers — do not treat the stub as the packer entry.
pub fn refuse_zero_bl_callers_as_packer_entry() -> Result<(), &'static str> {
    Err("bm136x panic stub has 0 BL callers; packer is still unidentified; T1 stays open")
}

/// : packed `bosminer` + `boser.unpacked` + `bos-tools.unpacked` have no `55AA2136`.
pub const BOSMINER_SIBLING_55AA2136_HITS: usize = 0;

pub fn refuse_sibling_braiins_binaries_as_job_template() -> Result<(), &'static str> {
    Err("boser/bos-tools/packed-bosminer have 0x 55AA2136/55AA2156; T1 stays open")
}

/// : all-register MOVZ+STRB hunt (W0..W31). The only `#0x36` then
/// `STRB W8` site is a hex/`ip` parser: `MOVZ W8,#0x36` (`'6'`), then
/// `MOVZ W8,#1` **overwrites** before `STRB`. Not a length-field store.
pub const BOSMINER_MOVZ36_ASCII6_VA: u64 = 0x00ED_E73C;
/// Jump table of ASCII class bytes (`':'` `'6'` `'!'` …) then `B`. Not pack().
pub const BOSMINER_MOVZ21_36_CHARCLASS_VA: u64 = 0x00E8_17F8;
/// Same-function `MOVZ #0x21` STRB + `MOVZ #0x36` STRB within 64 B.
pub const BOSMINER_PACK_CANDIDATE_21_36_STRB: usize = 0;
/// Same-function `MOVZ #0x21` STRB + `MOVZ #0x56` STRB within 64 B.
pub const BOSMINER_PACK_CANDIDATE_21_56_STRB: usize = 0;

/// : immediate stores do not name the Braiins job length field.
pub fn refuse_movz_strb_false_positives_as_pack_body() -> Result<(), &'static str> {
    Err(
        "bosminer MOVZ#0x36 @ 0xEDE73C is ASCII '6' (W8 overwritten before STRB); 0xE817F8 is char-class; 0 pack-candidate STRB pairs; T1 stays open",
    )
}

/// : no `generic_array` / `GenericArray` strings. ASCII `U86` at
/// `0xE80871` is `LDURB` bytes (`4d 55 38 36`), not typenum `U86`.
pub const BOSMINER_GENERICARRAY_STR_HITS: usize = 0;
pub const BOSMINER_TYPENUM_U88_HITS: usize = 0;
pub const BOSMINER_U86_INSTRUCTION_COLLISION_OFF: u64 = 0x00E8_0871;

/// : GenericArray/typenum sizing does not name 0x36 vs 0x56.
pub fn refuse_genericarray_u86_as_job_length_fact() -> Result<(), &'static str> {
    Err(
        "bosminer has 0 GenericArray strings; file 0xE80871 U86 is an instruction collision; T1 stays open",
    )
}

/// Leftover desk scanners stay tracked. They do not close T1.
pub fn admit_s19k_bosminer_scan_scripts(
    generic: &str,
    job: &str,
    pack: &str,
    jig: &str,
    memcpy: &str,
) -> Result<(), &'static str> {
    if !generic.contains("U86_AT_0xe80871") {
        return Err("genericarray scanner must pin U86 instruction collision");
    }
    if !generic.contains("T1_LENGTH_FIELD not closed as fact") {
        return Err("genericarray scanner must not close T1");
    }
    if !job.contains("55AA2136") || !job.contains("55AA2156") {
        return Err("job-bytes scanner must hunt 21 36 and 21 56");
    }
    if !pack.contains("Does not close T1 as fact") {
        return Err("pack-body scanner must not close T1");
    }
    if !jig.contains("Does not close Braiins on-wire identity") {
        return Err("jig scanner is not Braiins SoT");
    }
    if !memcpy.contains("Does not close T1") {
        return Err("memcpy-size scanner must not close T1");
    }
    if !memcpy.contains("0x36") || !memcpy.contains("0x56") {
        return Err("memcpy-size scanner must hunt 0x36/0x56 MOVZ lengths");
    }
    Ok(())
}

/// : packed `s19k_bosminer` (9_113_388 B ELF64) has no `55AA2136`/`55AA2156`.
pub const S19K_PACKED_BOSMINER_BYTES: usize = 9_113_388;
pub const S19K_PACKED_BOSMINER_55AA2136_HITS: usize = 0;

pub fn refuse_s19k_packed_bosminer_as_job_template() -> Result<(), &'static str> {
    Err("s19k_bosminer packed ELF64 has 0x 55AA2136/55AA2156; T1 stays open")
}

/// : 118 ADRP xrefs to `Failed to send work` page; none have MOVZ
/// `#0x21/#0x36/#0x56/#0x54/#0x58/82/84/86/88` in the next 64 B.
pub const BOSMINER_FAILED_SEND_WORK_OFF: u64 = 0x00F2_3802;
pub const BOSMINER_FAILED_SEND_WORK_JOB_IMM_XREFS: usize = 0;

pub fn refuse_failed_send_work_xrefs_as_job_length() -> Result<(), &'static str> {
    Err("bosminer Failed-to-send-work xrefs have 0 job-size MOVZ immediates; T1 stays open")
}

/// : GetAddress / chain-inactive are packed, not 7-byte rodata.
pub const BOSMINER_55AA5205_HITS: usize = 0;
pub const BOSMINER_55AA5305_HITS: usize = 0;

pub fn refuse_missing_getaddress_literal_as_job_length() -> Result<(), &'static str> {
    Err(
        "bosminer has 0x 55AA5205/55AA5305 rodata; GetAddress is packed like the job; T1 stays open",
    )
}

/// Wrap a queued `send_work` body (`21 36 …`) as the 88-byte on-wire frame.
/// Refuses the live-miss `21 56` length field. Used by mining-on first-frame log.
pub fn reconstruct_s19k_send_work_wire(body: &[u8]) -> Result<[u8; JOB_WIRE_TOTAL], &'static str> {
    if body.len() != MINING_ON_SEND_WORK_BODY_LEN {
        return Err("send_work body must be 0x54 bytes");
    }
    if body[0] != JOB_CMD_TYPE {
        return Err("send_work body must start with type 0x21");
    }
    admit_job_length_field(body[1])?;
    let crc = crc16_itu_t(body);
    let mut wire = [0u8; JOB_WIRE_TOTAL];
    wire[0] = JOB_PREAMBLE_0;
    wire[1] = JOB_PREAMBLE_1;
    wire[2..2 + MINING_ON_SEND_WORK_BODY_LEN].copy_from_slice(body);
    wire[86] = (crc >> 8) as u8;
    wire[87] = (crc & 0xFF) as u8;
    if classify_job_wire_prefix(&wire) != JobWirePrefixKind::Closed11d {
        return Err("reconstructed wire is not Closed11d");
    }
    Ok(wire)
}

/// Header fields in **job-packet byte order** (4cc0 `job_pkt+0x10/14/34/38` raw).
/// Caller does not byte-rev; this module applies desk 11f reversals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kClosedJobHeader {
    /// Work-ring slot. On-wire `job_id = slot << 3` (MS8 dialect).
    pub slot: u8,
    pub bbversion: [u8; JOB_DATA_BBVERSION_LEN],
    pub prev_hash: [u8; JOB_DATA_PREV_HASH_LEN],
    pub merkle_root: [u8; 32],
    /// Raw 4B at job_pkt+0x34.
    pub ntime: [u8; 4],
    /// Raw 4B at job_pkt+0x38.
    pub nbits: [u8; 4],
}

/// Assemble `data2[12]` then byte-reverse (desk 11f / ABI §5.4).
///
/// Layout before rev: merkle_root[28:32] ‖ ntime ‖ nbits.
pub fn fill_job_data2(
    merkle_root_suffix4: &[u8; 4],
    ntime_job_pkt: &[u8; 4],
    nbits_job_pkt: &[u8; 4],
) -> [u8; JOB_DATA2_LEN] {
    let mut data2 = [0u8; JOB_DATA2_LEN];
    data2[0..4].copy_from_slice(merkle_root_suffix4);
    data2[4..8].copy_from_slice(ntime_job_pkt);
    data2[8..12].copy_from_slice(nbits_job_pkt);
    data2.reverse();
    data2
}

/// Split merkle into 28B prefix (into `data[64]`) + 4B suffix (into `data2`).
pub fn split_merkle_root(merkle_root: &[u8; 32]) -> ([u8; JOB_DATA_MERKLE_PREFIX_LEN], [u8; 4]) {
    let mut prefix = [0u8; JOB_DATA_MERKLE_PREFIX_LEN];
    let mut suffix = [0u8; 4];
    prefix.copy_from_slice(&merkle_root[..JOB_DATA_MERKLE_PREFIX_LEN]);
    suffix.copy_from_slice(&merkle_root[JOB_DATA_MERKLE_PREFIX_LEN..]);
    (prefix, suffix)
}

/// Pack one CLOSED 88-byte userspace frame for Braiins raw ttyS write.
///
/// Does **not** emit FPGA/ESP `21 56`. Length field is always [`JOB_LEN_FIELD`]
/// (`0x36`). One frame only (desk 11e).
pub fn pack_s19k_closed_uart_job(header: &S19kClosedJobHeader) -> [u8; JOB_WIRE_TOTAL] {
    let (merk28, merk4) = split_merkle_root(&header.merkle_root);
    let data = fill_job_data_header_chunk_byte_rev(&header.bbversion, &header.prev_hash, &merk28);
    let data2 = fill_job_data2(&merk4, &header.ntime, &header.nbits);
    pack_uart_trans_job(job_id_from_slot(header.slot), &data2, &data)
}

/// Track-2 mmap ring element from the same CLOSED header (no `/dev` open).
pub fn pack_s19k_closed_uart_trans_ring(
    header: &S19kClosedJobHeader,
    nonce2: u64,
    pool_job_id: u32,
) -> [u8; crate::s19k_uart_trans_job::UART_TRANS_RING_STRIDE] {
    crate::s19k_uart_trans_job::pack_uart_trans_ring_from_header_chunk(
        &header.bbversion,
        &header.prev_hash,
        &header.merkle_root,
        &header.ntime,
        &header.nbits,
        nonce2,
        pool_job_id,
    )
}

/// Stock 11f header helper: bookkeeping `asic_job_id` (already `slot<<3`) +
/// [`dcentrald_stratum::work::MiningWork`] integer/header fields.
///
/// `ntime`/`nbits`/`version` are copied as little-endian job-packet bytes
/// (same as the live BM1362 builder). Desk 11f then byte-revs `data`/`data2`.
pub fn s19k_braiins_mining_on_header(
    asic_job_id: u8,
    version: u32,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    ntime: u32,
    nbits: u32,
) -> S19kClosedJobHeader {
    S19kClosedJobHeader {
        slot: asic_job_id >> 3,
        bbversion: version.to_le_bytes(),
        prev_hash: prev_block_hash,
        merkle_root,
        ntime: ntime.to_le_bytes(),
        nbits: nbits.to_le_bytes(),
    }
}

/// 32-bit word reverse (W0↔W7). Matches `serial_mining::reverse_32bit_words`
/// and the Braiins fill's two 8×u32 endian-swapped blobs.
pub fn reverse_32bit_words(data: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..8 {
        out[i * 4..(i + 1) * 4].copy_from_slice(&data[(7 - i) * 4..(8 - i) * 4]);
    }
    out
}

/// Braiins Track-1 body after `21 36` (Ghidra `FUN_0091beb4` / `FUN_0091ba88`).
///
/// Same 82-byte ESP-style payload the 2026-08-12 live miss sent, but the
/// length **field** is `0x36` (DAT_012ec448), not `0x56`.
///
/// ```text
/// 21 36 <job_id> 01 <nonce=0> <nbits LE> <ntime LE> <merkle32 wr> <prev32 wr> <ver0 LE>
/// ```
/// `ver0` = [`s19k_braiins_midstate0_version`] (`FUN_00c41e5c(work, 0)`).
pub fn pack_s19k_braiins_ghidra_job_body(
    asic_job_id: u8,
    version: u32,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    ntime: u32,
    nbits: u32,
) -> [u8; MINING_ON_SEND_WORK_BODY_LEN] {
    pack_s19k_braiins_ghidra_job_body_with_vbits(
        asic_job_id,
        version,
        0,
        prev_block_hash,
        merkle_root,
        ntime,
        nbits,
    )
}

/// Same as [`pack_s19k_braiins_ghidra_job_body`] with explicit midstate-0 vbits.
pub fn pack_s19k_braiins_ghidra_job_body_with_vbits(
    asic_job_id: u8,
    version: u32,
    version_bits_base: u16,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    ntime: u32,
    nbits: u32,
) -> [u8; MINING_ON_SEND_WORK_BODY_LEN] {
    let mut body = [0u8; MINING_ON_SEND_WORK_BODY_LEN];
    body[0] = JOB_CMD_TYPE;
    body[1] = JOB_LEN_FIELD;
    body[2] = asic_job_id;
    body[3] = JOB_RSVD2;
    body[4..8].copy_from_slice(&0u32.to_le_bytes());
    body[8..12].copy_from_slice(&nbits.to_le_bytes());
    body[12..16].copy_from_slice(&ntime.to_le_bytes());
    body[16..48].copy_from_slice(&reverse_32bit_words(&merkle_root));
    body[48..80].copy_from_slice(&reverse_32bit_words(&prev_block_hash));
    let ver0 = s19k_braiins_midstate0_version(version, version_bits_base);
    body[80..84].copy_from_slice(&ver0.to_le_bytes());
    body
}

/// Inverse of [`pack_s19k_braiins_ghidra_job_body_with_vbits`].
/// Fields are in the same domain the packer accepted (WorkBuilder merkle /
/// already-reversed prev, integer ntime/nbits, packed ver0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBraiinsGhidraJobFields {
    pub job_id: u8,
    pub nbits: u32,
    pub ntime: u32,
    pub merkle_root: [u8; 32],
    pub prev_block_hash: [u8; 32],
    pub packed_ver0: u32,
}

pub fn unpack_s19k_braiins_ghidra_job_body(
    body: &[u8],
) -> Result<S19kBraiinsGhidraJobFields, &'static str> {
    if body.len() != MINING_ON_SEND_WORK_BODY_LEN {
        return Err("send_work body must be 0x54 bytes");
    }
    if body[0] != JOB_CMD_TYPE {
        return Err("send_work body must start with type 0x21");
    }
    admit_job_length_field(body[1])?;
    let mut merkle_wr = [0u8; 32];
    let mut prev_wr = [0u8; 32];
    merkle_wr.copy_from_slice(&body[16..48]);
    prev_wr.copy_from_slice(&body[48..80]);
    let mut nbits = [0u8; 4];
    let mut ntime = [0u8; 4];
    let mut ver0 = [0u8; 4];
    nbits.copy_from_slice(&body[8..12]);
    ntime.copy_from_slice(&body[12..16]);
    ver0.copy_from_slice(&body[80..84]);
    Ok(S19kBraiinsGhidraJobFields {
        job_id: body[2],
        nbits: u32::from_le_bytes(nbits),
        ntime: u32::from_le_bytes(ntime),
        merkle_root: reverse_32bit_words(&merkle_wr),
        prev_block_hash: reverse_32bit_words(&prev_wr),
        packed_ver0: u32::from_le_bytes(ver0),
    })
}

/// Unpack a Closed11d 88-byte wire (`55 AA 21 36 …` + CRC).
pub fn unpack_s19k_braiins_ghidra_job_wire(
    wire: &[u8],
) -> Result<S19kBraiinsGhidraJobFields, &'static str> {
    if wire.len() != JOB_WIRE_TOTAL {
        return Err("Closed11d wire must be 88 bytes");
    }
    if wire[0] != JOB_PREAMBLE_0 || wire[1] != JOB_PREAMBLE_1 {
        return Err("wire must start with 55 AA");
    }
    unpack_s19k_braiins_ghidra_job_body(&wire[2..2 + MINING_ON_SEND_WORK_BODY_LEN])
}

/// Parse compact `tx_wire` hex from a post-clean dump or a spaced
/// `FULL FRAME ON WIRE` log line. ASCII whitespace is ignored so either
/// form (`55AA…` or `55 AA …`) unpacks.
pub fn parse_s19k_compact_hex(hex: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let mut hi: Option<u8> = None;
    for &b in hex.as_bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        let nibble = hex_nibble(b)?;
        match hi.take() {
            None => hi = Some(nibble),
            Some(high) => out.push((high << 4) | nibble),
        }
    }
    if hi.is_some() {
        return Err("compact hex must be a non-empty even-length string");
    }
    if out.is_empty() {
        return Err("compact hex must be a non-empty even-length string");
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, &'static str> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err("compact hex contains a non-hex digit"),
    }
}

/// Full 88-byte on-wire frame (`55 AA 21 36 …` + CRC16-ITU-T).
/// `work_id` is the registry slot; the packer stores [`s19k_braiins_fill_job_id`].
/// Stock uart_trans 11f stays on [`pack_s19k_closed_uart_job`].
pub fn build_s19k_braiins_mining_on_work_wire(
    work_id: u8,
    version: u32,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    ntime: u32,
    nbits: u32,
) -> [u8; JOB_WIRE_TOTAL] {
    let _ = admit_s19k_braiins_job_fanout(1);
    reconstruct_s19k_send_work_wire(&pack_s19k_braiins_ghidra_job_body(
        s19k_braiins_fill_job_id(work_id),
        version,
        prev_block_hash,
        merkle_root,
        ntime,
        nbits,
    ))
    .expect("Ghidra 21 36 body reconstructs to Closed11d")
}

/// 84-byte `send_work` body (no preamble, no CRC). Daemon queues this.
pub fn build_s19k_braiins_mining_on_work_body(
    work_id: u8,
    version: u32,
    prev_block_hash: [u8; 32],
    merkle_root: [u8; 32],
    ntime: u32,
    nbits: u32,
) -> [u8; MINING_ON_SEND_WORK_BODY_LEN] {
    let wire = build_s19k_braiins_mining_on_work_wire(
        work_id,
        version,
        prev_block_hash,
        merkle_root,
        ntime,
        nbits,
    );
    let mut body = [0u8; MINING_ON_SEND_WORK_BODY_LEN];
    body.copy_from_slice(&wire[2..2 + MINING_ON_SEND_WORK_BODY_LEN]);
    debug_assert_eq!(JOB_BODY_LEN, MINING_ON_SEND_WORK_BODY_LEN + 2);
    body
}

/// Admit only the CLOSED length field. `0x56` is the FPGA/ESP field we sent live.
pub fn admit_job_length_field(len_field: u8) -> Result<(), &'static str> {
    if len_field == FPGA_ESP_JOB_LEN_FIELD {
        return Err(
            "refuse FPGA/ESP-Miner length field 0x56; CLOSED desk 11d length field is 0x36",
        );
    }
    if len_field != JOB_LEN_FIELD {
        return Err("CLOSED desk 11d job length field must be 0x36");
    }
    Ok(())
}

/// Inspect a captured on-wire prefix (at least 4 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobWirePrefixKind {
    Closed11d,
    FpgaEspLiveMiss,
    Unknown,
}

pub fn classify_job_wire_prefix(bytes: &[u8]) -> JobWirePrefixKind {
    if bytes.len() < 4 {
        return JobWirePrefixKind::Unknown;
    }
    let p = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if p == CLOSED_11D_PREFIX {
        JobWirePrefixKind::Closed11d
    } else if p == LIVE_20260812_FPGA_PREFIX {
        JobWirePrefixKind::FpgaEspLiveMiss
    } else {
        JobWirePrefixKind::Unknown
    }
}

/// Policy pin: passthrough dispatch must write 1 CLOSED frame, never 8 midstate UART copies.
pub fn admit_s19k_braiins_job_fanout(frames: usize) -> Result<(), &'static str> {
    admit_uart_frames_per_work(frames)
}

/// Host-visible delta between the live miss and the CLOSED frame (same slot/header).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LiveMissVsClosed {
    pub live_len_field: u8,
    pub closed_len_field: u8,
    pub live_payload_len: usize,
    pub closed_wire_total: usize,
    /// Stock uart_trans 11f still uses `slot<<3`. Fill path does not.
    pub closed_job_id_is_slot_shl_3: bool,
}

pub const LIVE_MISS_VS_CLOSED: LiveMissVsClosed = LiveMissVsClosed {
    live_len_field: FPGA_ESP_JOB_LEN_FIELD,
    closed_len_field: JOB_LEN_FIELD,
    live_payload_len: FPGA_ESP_JOB_PAYLOAD_LEN,
    closed_wire_total: JOB_WIRE_TOTAL,
    closed_job_id_is_slot_shl_3: false,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::s19k_uart_trans_job::{
        crc16_itu_t, JOB_CMD_TYPE, JOB_CRC_LEN, JOB_DATA_LEN, JOB_PREAMBLE_0, JOB_PREAMBLE_1,
        UART_FRAMES_PER_RING_ENTRY,
    };

    fn sample_header() -> S19kClosedJobHeader {
        let mut prev = [0u8; 32];
        prev[0] = 0xB0;
        prev[31] = 0xBF;
        let mut merkle = [0u8; 32];
        merkle[0] = 0xC0;
        merkle[27] = 0xCF;
        merkle[28] = 0xD0;
        merkle[29] = 0xD1;
        merkle[30] = 0xD2;
        merkle[31] = 0xD3;
        S19kClosedJobHeader {
            slot: 1,
            bbversion: [0xA1, 0xA2, 0xA3, 0xA4],
            prev_hash: prev,
            merkle_root: merkle,
            ntime: [0xE0, 0xE1, 0xE2, 0xE3],
            nbits: [0xF0, 0xF1, 0xF2, 0xF3],
        }
    }

    #[test]
    fn pack_is_55_aa_21_36_not_21_56() {
        let frame = pack_s19k_closed_uart_job(&sample_header());
        assert_eq!(frame.len(), 0x58);
        assert_eq!(&frame[0..4], &CLOSED_11D_PREFIX);
        assert_ne!(&frame[0..4], &LIVE_20260812_FPGA_PREFIX);
        assert_eq!(frame[2], JOB_CMD_TYPE);
        assert_eq!(frame[3], JOB_LEN_FIELD);
        assert_eq!(frame[4], 0x08); // slot 1 << 3
        assert_eq!(frame[5], 0x01);
        assert_eq!(&frame[6..10], &[0, 0, 0, 0]);
        assert!(admit_job_length_field(frame[3]).is_ok());
        assert!(admit_job_length_field(FPGA_ESP_JOB_LEN_FIELD).is_err());
        assert_eq!(
            classify_job_wire_prefix(&frame),
            JobWirePrefixKind::Closed11d
        );
        assert_eq!(
            classify_job_wire_prefix(&LIVE_20260812_FPGA_PREFIX),
            JobWirePrefixKind::FpgaEspLiveMiss
        );
        let body = &frame[2..];
        let crc = crc16_itu_t(&body[..JOB_CRC_LEN]);
        assert_eq!(frame[86], (crc >> 8) as u8);
        assert_eq!(frame[87], (crc & 0xff) as u8);
    }

    #[test]
    fn data2_is_merkle_suffix_ntime_nbits_then_byte_rev() {
        let h = sample_header();
        let (_, suffix) = split_merkle_root(&h.merkle_root);
        assert_eq!(suffix, [0xD0, 0xD1, 0xD2, 0xD3]);
        let data2 = fill_job_data2(&suffix, &h.ntime, &h.nbits);
        // before rev: D0 D1 D2 D3 E0 E1 E2 E3 F0 F1 F2 F3
        assert_eq!(
            data2,
            [0xF3, 0xF2, 0xF1, 0xF0, 0xE3, 0xE2, 0xE1, 0xE0, 0xD3, 0xD2, 0xD1, 0xD0]
        );
        let frame = pack_s19k_closed_uart_job(&h);
        assert_eq!(&frame[10..22], &data2);
        // data[64] last byte is first assembled byte (bbversion[0]) after full reverse
        assert_eq!(frame[85], 0xA1);
        // data[64] first byte is last assembled byte (merkle[27])
        assert_eq!(frame[22], 0xCF);
        let ring = pack_s19k_closed_uart_trans_ring(&h, 0, 0);
        assert_eq!(&ring[0..64], &frame[22..86]);
        assert_eq!(&ring[64..76], &frame[10..22]);
        assert_eq!(
            crate::s19k_uart_trans_job::uart_trans_wire_from_ring_element(h.slot, &ring),
            frame
        );
    }

    #[test]
    fn mining_on_passthrough_emits_21_36_not_21_56() {
        // Fill-path work_id 2 (registry slot). Log 0 ⇒ on-wire byte 2, not 2<<3.
        let work_id = 2u8;
        let version = 0x2000_0000u32;
        let mut prev = [0u8; 32];
        prev[0] = 0x11;
        prev[31] = 0x22;
        let mut merkle = [0u8; 32];
        merkle[0] = 0x33;
        merkle[27] = 0x44;
        merkle[28] = 0x55;
        merkle[31] = 0x66;
        let ntime = 0x5F5E_1000;
        let nbits = 0x1707_A30A;

        let wire =
            build_s19k_braiins_mining_on_work_wire(work_id, version, prev, merkle, ntime, nbits);
        let body =
            build_s19k_braiins_mining_on_work_body(work_id, version, prev, merkle, ntime, nbits);
        assert_eq!(wire.len(), 0x58);
        assert_eq!(&wire[0..4], &[0x55, 0xAA, 0x21, 0x36]);
        assert_ne!(wire[3], 0x56);
        assert_eq!(wire[4], work_id);
        assert_eq!(wire[4], s19k_braiins_fill_job_id(work_id));
        assert_ne!(wire[4], 2u8 << 3);
        assert_eq!(
            classify_job_wire_prefix(&wire),
            JobWirePrefixKind::Closed11d
        );
        assert_ne!(
            classify_job_wire_prefix(&wire),
            JobWirePrefixKind::FpgaEspLiveMiss
        );
        assert_eq!(body.len(), 0x54);
        assert_eq!(body[0], 0x21);
        assert_eq!(body[1], 0x36);
        assert_ne!(body[1], 0x56);
        assert_eq!(body[2], work_id);
        // send_work wraps body with the same CRC the packer stored.
        let crc = crc16_itu_t(&body);
        assert_eq!(wire[86], (crc >> 8) as u8);
        assert_eq!(wire[87], (crc & 0xff) as u8);
        let hex: String = wire
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!("S19K_CLOSED_WIRE {hex}");
        eprintln!(
            "S19K_SEND_WORK_BODY_PREFIX {:02X} {:02X} {:02X} {:02X}",
            body[0], body[1], body[2], body[3]
        );
    }

    #[test]
    fn s19k_ghidra_job_unpack_is_pack_inverse() {
        let work_id = 2u8;
        let version = 0x2000_0000u32;
        let mut prev = [0u8; 32];
        prev[0] = 0x11;
        prev[31] = 0x22;
        let mut merkle = [0u8; 32];
        merkle[0] = 0x33;
        merkle[27] = 0x44;
        merkle[28] = 0x55;
        merkle[31] = 0x66;
        let ntime = 0x5F5E_1000;
        let nbits = 0x1707_A30A;
        let wire =
            build_s19k_braiins_mining_on_work_wire(work_id, version, prev, merkle, ntime, nbits);
        let compact: String = wire.iter().map(|b| format!("{b:02X}")).collect();
        let parsed = parse_s19k_compact_hex(&compact).expect("compact hex");
        let fields = unpack_s19k_braiins_ghidra_job_wire(&parsed).expect("unpack");
        assert_eq!(fields.job_id, work_id);
        assert_eq!(fields.nbits, nbits);
        assert_eq!(fields.ntime, ntime);
        assert_eq!(fields.merkle_root, merkle);
        assert_eq!(fields.prev_block_hash, prev);
        assert_eq!(
            fields.packed_ver0,
            s19k_braiins_midstate0_version(version, 0)
        );
        assert!(parse_s19k_compact_hex("").is_err());
        assert!(parse_s19k_compact_hex("21").is_ok());
        assert!(parse_s19k_compact_hex("2").is_err());
        assert_eq!(
            parse_s19k_compact_hex("21 36").expect("spaced hex"),
            vec![0x21, 0x36]
        );
        assert!(unpack_s19k_braiins_ghidra_job_wire(&[0u8; 10]).is_err());
    }

    /// live412 logged one `FULL FRAME ON WIRE` — the first-fill slot-0 TX,
    /// not SHARE #1's extra2=08 slot. Unpack that exact dump and pin it to
    /// RAW_NOTIFY[0] (`…8bd0`). Post-clean frames were never logged
    /// (`total_work <= 1` gate); this is the held on-wire evidence.
    #[test]
    fn s19k_live412_captured_first_frame_is_8bd0_job0() {
        const LIVE412_FIRST_FRAME: &str = "55 AA 21 36 00 01 00 00 00 00 3D 35 02 17 \
B0 57 82 6A 76 F5 EF 1D 69 B7 B2 8E 1B A6 BC 50 CA 98 F0 6C 93 96 28 A6 8F 12 33 \
DD E7 92 4A 00 85 62 E9 03 00 00 00 00 00 00 00 00 B4 80 01 00 FB 21 BE DB 9E E1 \
B3 5D 1B 45 6F A0 34 33 F6 96 9E 84 1B 98 00 00 00 20 64 C2";
        let parsed = parse_s19k_compact_hex(LIVE412_FIRST_FRAME).expect("live412 spaced dump");
        assert_eq!(parsed.len(), JOB_WIRE_TOTAL);
        let fields = unpack_s19k_braiins_ghidra_job_wire(&parsed).expect("unpack live412 frame");
        assert_eq!(fields.job_id, 0);
        assert_eq!(fields.ntime, 0x6A82_57B0);
        assert_eq!(fields.nbits, 0x1702_353D);
        assert_eq!(fields.packed_ver0, 0x2000_0000);
        // WorkBuilder prev = per-word endian reverse of the logged stratum prev.
        assert_eq!(
            fields.prev_block_hash,
            [
                0x9E, 0x84, 0x1B, 0x98, 0x34, 0x33, 0xF6, 0x96, 0x1B, 0x45, 0x6F, 0xA0, 0x9E, 0xE1,
                0xB3, 0x5D, 0xFB, 0x21, 0xBE, 0xDB, 0xB4, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn mining_on_dispatch_source_calls_shipped_packer() {
        // Host-visible seam: the unix daemon cannot compile here, so this
        // crate test reads the production work_frame builder and requires it
        // to call *this* packer for BM1366 passthrough.
        let source = include_str!("../../dcentrald/src/serial_mining.rs");
        let work_frame = source
            .find("let work_frame = if is_bm1398")
            .expect("production work_frame builder");
        let window = &source[work_frame..work_frame + 3500];
        assert!(
            window.contains("} else if is_bm1366 {"),
            "S19k BM1366 mining-on (passthrough and experimental native) must leave FPGA 21 56"
        );
        assert!(
            !window.contains("else if is_bm1366 && passthrough"),
            "21 36 must not be gated on passthrough alone"
        );
        assert!(
            window.contains("build_s19k_braiins_mining_on_work_body"),
            "production work_frame must call the shipped CLOSED packer"
        );
        let closed_arm = window
            .split("} else if is_bm1366 {")
            .nth(1)
            .expect("closed arm")
            .split("} else {")
            .next()
            .expect("arm end");
        assert!(closed_arm.contains("build_s19k_braiins_mining_on_work_body"));
        assert!(
            !closed_arm.contains("frame.push(0x56)"),
            "closed arm must not emit live-miss 0x56"
        );
        eprintln!("S19K_DISPATCH_SHAPE CLOSED_21_36_via_build_s19k_braiins_mining_on_work_body");
    }

    #[test]
    fn refuse_ms8_uart_fanout_and_pin_live_delta() {
        assert_eq!(UART_FRAMES_PER_RING_ENTRY, 1);
        assert!(admit_s19k_braiins_job_fanout(1).is_ok());
        assert!(admit_s19k_braiins_job_fanout(8).is_err());
        assert_eq!(LIVE_MISS_VS_CLOSED.live_len_field, 0x56);
        assert_eq!(LIVE_MISS_VS_CLOSED.closed_len_field, 0x36);
        assert_eq!(LIVE_MISS_VS_CLOSED.live_payload_len, 82);
        assert_eq!(LIVE_MISS_VS_CLOSED.closed_wire_total, 0x58);
        assert!(!LIVE_MISS_VS_CLOSED.closed_job_id_is_slot_shl_3);
        assert_eq!(JOB_PREAMBLE_0, 0x55);
        assert_eq!(JOB_PREAMBLE_1, 0xAA);
        assert_eq!(JOB_DATA_LEN, 64);
        assert_eq!(BOSMINER_55AA2136_COLLISION_OFF, 0x00EE_C448);
        assert_eq!(BOSMINER_PREFIX_CONST_VA, 0x012E_C448);
        assert_eq!(BOSMINER_PACK_FN_VA, 0x0091_BEB4);
        assert_eq!(BOSMINER_FILL_FN_VA, 0x0091_BA88);
        assert_eq!(BOSMINER_GHIDRA_PREFIX, CLOSED_11D_PREFIX);
        assert!(admit_bosminer_ghidra_pack_prefix_21_36().is_ok());
        assert_eq!(BOSMINER_CRC_INIT_RAW, 0x84CF);
        assert_eq!(BOSMINER_CRC_TABLE_HEAD[1], 0x1021);
        assert_eq!(BOSMINER_CRC_INIT_FN_VA, 0x0093_8F50);
        assert_eq!(BOSMINER_CRC_TABLE_VA, 0x0132_8F60);
        assert!(admit_bosminer_ghidra_crc_is_itu_t().is_ok());
        assert!(refuse_bosminer_55aa2136_collision_as_job_template().is_err());
        let ghidra = pack_s19k_braiins_ghidra_job_body(
            0x10,
            0x2000_0000,
            {
                let mut p = [0u8; 32];
                p[0] = 0x11;
                p[31] = 0x22;
                p
            },
            {
                let mut m = [0u8; 32];
                m[0] = 0x33;
                m[31] = 0x66;
                m
            },
            0x5F5E_1000,
            0x1707_A30A,
        );
        assert_eq!(&ghidra[0..4], &[0x21, 0x36, 0x10, 0x01]);
        assert_eq!(&ghidra[4..8], &[0, 0, 0, 0]);
        assert_eq!(&ghidra[8..12], &0x1707_A30Au32.to_le_bytes());
        assert_eq!(&ghidra[12..16], &0x5F5E_1000u32.to_le_bytes());
        assert_eq!(&ghidra[80..84], &0x2000_0000u32.to_le_bytes());
        assert!(admit_bosminer_ghidra_fill_pack_map().is_ok());
        assert!(admit_bosminer_91beb4_dest_layout().is_ok());
        assert!(admit_s19k_ghidra_pack_body_matches_production().is_ok());
        assert!(refuse_91beb4_alloc_fail_packing40_as_pack_ident().is_err());
        assert_eq!(BOSMINER_PACK_FN_MOVZ56_INSN, 0x5280_0AC0);
        assert_eq!(BOSMINER_PACK_FN_MOVZ54_INSN, 0x5280_0A82);
        assert_eq!(BOSMINER_PACK_FN_STUR52_INSN, 0xB805_2009);
        assert_eq!(BOSMINER_PACK_FN_RET_INSN, 0xD65F_03C0);
        assert_eq!(BOSMINER_PACK_FN_SUCCESS_RUSTC_LOCS, 0);
        assert_eq!(BOSMINER_PACK_FN_FAIL_LOC_LINE, 40);
        assert_eq!(BOSMINER_PACK_FN_FAIL_LOC_COL, 23);
        let mut pack_blob = vec![0u8; (BOSMINER_PACK_FN_RET_VA - 0x400_000 + 4) as usize];
        let putp = |buf: &mut [u8], va: u64, insn: u32| {
            let o = (va - 0x400_000) as usize;
            buf[o..o + 4].copy_from_slice(&insn.to_le_bytes());
        };
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_VA,
            BOSMINER_PACK_FN_SUB_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_MOVZ56_VA,
            BOSMINER_PACK_FN_MOVZ56_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_ADD54_VA,
            BOSMINER_PACK_FN_ADD54_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_ADD50_VA,
            BOSMINER_PACK_FN_ADD50_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_STRQ0_VA,
            BOSMINER_PACK_FN_STRQ0_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_STUR52_VA,
            BOSMINER_PACK_FN_STUR52_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_CRC_INIT_BL_VA,
            BOSMINER_PACK_FN_CRC_INIT_BL_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_ADD2_VA,
            BOSMINER_PACK_FN_ADD2_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_MOVZ54_VA,
            BOSMINER_PACK_FN_MOVZ54_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_CRC_UPD_BL_VA,
            BOSMINER_PACK_FN_CRC_UPD_BL_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_CRC_FIN_BL_VA,
            BOSMINER_PACK_FN_CRC_FIN_BL_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_FN_RET_VA,
            BOSMINER_PACK_FN_RET_INSN,
        );
        putp(
            &mut pack_blob,
            BOSMINER_PACK_ALLOC_BL_VA,
            BOSMINER_PACK_ALLOC_BL_INSN,
        );
        assert!(admit_bosminer_91beb4_pack_body_elf(&pack_blob).is_ok());
        assert!(admit_bosminer_91beb4_unique_alloc56_elf(&pack_blob).is_ok());
        assert_eq!(BOSMINER_VERSION_ROLL_FN_VA, 0x00C4_1E5C);
        assert_eq!(
            s19k_braiins_midstate0_version(0x2000_0000, 1),
            0x2000_0000 | (1 << 13)
        );
        assert_eq!(s19k_braiins_midstate0_version(0x2000_6000, 0), 0x2000_6000);
        assert_ne!(
            refuse_bip320_strip_as_braiins_fill_ver0(0x2000_6000, 0),
            0x2000_6000
        );
        assert_eq!(
            refuse_bip320_strip_as_braiins_fill_ver0(0x2000_6000, 0),
            0x2000_0000
        );
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_rolled_version_is_midstate0_or(serial).is_ok());
        // The midstate0-OR pin tolerates rustfmt's two canonical spellings
        // (single line, or wrapped with a trailing comma) but still refuses
        // argument drift. This pins the fix for the 2026-08-17..19 "unchanged
        // dirty S19k failure": the old pin matched only the exact single-line
        // byte string, so a pure formatting wrap of the identical production
        // call in the dirty worktree broke it.
        let one_line = "fn serial_rolled_version() -> Option<u32> {
            if is_bm1366 {
                return Some(s19k_braiins_midstate0_version(entry.version, version_bits_raw));
            }
            let (rolled_version, vbits_delta) =
                dcentrald_asic::bm1362::bip320_reconstruct_rolled_version(
                    entry.version,
                    version_bits_raw,
                );
            rolled_version
        }";
        let wrapped = "fn serial_rolled_version() -> Option<u32> {
            if is_bm1366 {
                return Some(s19k_braiins_midstate0_version(
                    entry.version,
                    version_bits_raw,
                ));
            }
            let (rolled_version, vbits_delta) =
                dcentrald_asic::bm1362::bip320_reconstruct_rolled_version(
                    entry.version,
                    version_bits_raw,
                );
            rolled_version
        }";
        assert!(admit_s19k_production_rolled_version_is_midstate0_or(one_line).is_ok());
        assert!(admit_s19k_production_rolled_version_is_midstate0_or(wrapped).is_ok());
        let wrong_args = "fn serial_rolled_version() -> Option<u32> {
            if is_bm1366 {
                return Some(s19k_braiins_midstate0_version(entry.version, 0));
            }
            rolled_version
        }";
        assert!(admit_s19k_production_rolled_version_is_midstate0_or(wrong_args).is_err());
        let strip_regression = "fn serial_rolled_version() -> Option<u32> {
            if is_bm1366 {
                return Some(entry.version & !0x1FFF_E000);
            }
            rolled_version
        }";
        assert!(admit_s19k_production_rolled_version_is_midstate0_or(strip_regression).is_err());
        let rolled = pack_s19k_braiins_ghidra_job_body_with_vbits(
            0x10,
            0x2000_0000,
            1,
            [0u8; 32],
            [0u8; 32],
            0,
            0,
        );
        assert_eq!(&rolled[80..84], &(0x2000_0000u32 | (1 << 13)).to_le_bytes());
        assert!(refuse_len_field_36_as_esp_data_len_plus_4(0x36).is_err());
        assert_eq!(ESP_BM1366_JOB_PAYLOAD, 82);
        assert_eq!(BOSMINER_FILL_PREFIX_OFF, 0x50);
        assert_eq!(BOSMINER_WORK_NTIME_OFF, 0x38);
        assert_eq!(BOSMINER_WORK_VERSION_OFF, 0x34);
        assert_eq!(BOSMINER_FILL_NBITS_OFF, 0x44);
        assert_eq!(BOSMINER_FILL_NTIME_OFF, 0x48);
        assert!(admit_bosminer_work_ntime_off(0x38).is_ok());
        assert!(refuse_bosminer_work_plus_0x38_as_nbits(0x38).is_err());
        assert_eq!(BOSMINER_NTIME_ROLL_FN_VA, 0x00C4_1C48);
        assert_eq!(BOSMINER_INCORRECT_NBITS_STR_VA, 0x013A_D458);
        assert_eq!(BOSMINER_WORK_NTIME_LDR_VA, 0x0091_BCB8);
        assert_eq!(BOSMINER_JOB_NBITS_OFF, 0x78);
        assert_eq!(BOSMINER_JOB_NBITS_GETTER_VA, 0x00C7_B380);
        assert_eq!(BOSMINER_JOB_NBITS_GETTER2_VA, 0x00D1_39DC);
        assert_eq!(BOSMINER_JOB_NBITS_GETTER_INSN, 0xB940_7800);
        assert_eq!(BOSMINER_STRATUM_V2_JOB_VTABLE_VA, 0x01A1_21D8);
        assert_eq!(BOSMINER_WORK_JOB_VTABLE_OFF, 0x20);
        assert_eq!(BOSMINER_NBITS_BUG_WORK_RS_LINE, 307);
        assert!(admit_bosminer_job_nbits_is_self_plus_0x78().is_ok());
        assert!(refuse_bosminer_pack_caller_engine_plus_0x90_as_nbits().is_err());
        let mut job_obj = [0u8; BOSMINER_JOB_SIZE];
        job_obj[0x78..0x7c].copy_from_slice(&0x1707_A30Au32.to_le_bytes());
        assert_eq!(
            s19k_braiins_job_nbits_from_object(&job_obj).unwrap(),
            0x1707_A30A
        );
        assert!(s19k_braiins_job_nbits_from_object(&[0u8; 8]).is_err());
        let wire =
            build_s19k_braiins_mining_on_work_wire(0x10, 0x2000_0000, [0u8; 32], [0u8; 32], 0, 0);
        // work_id 0x10 encodes as 0x10 at fill log 0 (identity), not 0x10 meaning slot 2.
        assert_eq!(&wire[0..6], &[0x55, 0xAA, 0x21, 0x36, 0x10, 0x01]);
        let wire2 =
            build_s19k_braiins_mining_on_work_wire(2, 0x2000_0000, [0u8; 32], [0u8; 32], 0, 0);
        assert_eq!(&wire2[0..6], &[0x55, 0xAA, 0x21, 0x36, 0x02, 0x01]);
        assert_ne!(&wire[10..14], &[0xF3, 0xF2, 0xF1, 0xF0]);
        assert_eq!(BOSMINER_BM136X_PACKED_STRUCT_OFF, 0x00F2_56E0);
        assert_eq!(BOSMINER_UNEXPECTED_SIZE_OFF, 0x00F2_5468);
        assert!(BOSMINER_UNEXPECTED_SIZE_OFF < BOSMINER_BM136X_PACKED_STRUCT_OFF);
        assert!(refuse_packed_struct_string_as_job_length_fact().is_err());
        assert_eq!(BOSMINER_BM136X_XREF_VA, 0x0092_08CC);
        assert!(refuse_bm136x_xref_as_job_length_fact().is_err());
        assert_eq!(BOSMINER_BM136X_LOC_LINE, 36);
        assert_eq!(BOSMINER_BM13XX_BROADCAST_ASSERT_LEN, 46);
        assert!(refuse_bm136x_panic_site_as_job_packer().is_err());
        assert!(refuse_9208f8_movz2e_as_bm136x_line46().is_err());
        assert!(admit_bosminer_bm136x_rs_36_is_not_pack().is_ok());
        assert!(admit_bosminer_bm13xx_broadcast_assert().is_ok());
        assert!(admit_bosminer_91beb4_unique_alloc56().is_ok());
        assert!(admit_bosminer_pack56_type_unnamed_in_rustc_metadata().is_ok());
        assert!(refuse_hashmap_v_as_pack56_type().is_err());
        assert!(refuse_factory4_as_pack56_type().is_err());
        assert!(refuse_workpair_as_pack56_type().is_err());
        assert!(refuse_chipparams_as_pack56_type().is_err());
        assert!(refuse_hal_io_as_pack56_type().is_err());
        assert_eq!(BOSMINER_TYPEINFO_SIZE56_HITS, 0);
        assert_eq!(BOSMINER_HASHMAP_V_SIZE, 0x18);
        assert_eq!(BOSMINER_FACTORY4_PREFIX_BOX, 0x98);
        assert!(BOSMINER_HAL_WORKPAIR_FIELDS.contains("version_idx"));
        assert_eq!(BOSMINER_BM136X_PANIC_BL_CALLERS, 0);
        assert!(refuse_zero_bl_callers_as_packer_entry().is_err());
        assert_eq!(BOSMINER_SIBLING_55AA2136_HITS, 0);
        assert!(refuse_sibling_braiins_binaries_as_job_template().is_err());
        assert_eq!(BOSMINER_MOVZ36_ASCII6_VA, 0x00ED_E73C);
        assert_eq!(BOSMINER_MOVZ21_36_CHARCLASS_VA, 0x00E8_17F8);
        assert_eq!(BOSMINER_PACK_CANDIDATE_21_36_STRB, 0);
        assert_eq!(BOSMINER_PACK_CANDIDATE_21_56_STRB, 0);
        assert!(refuse_movz_strb_false_positives_as_pack_body().is_err());
        assert_eq!(BOSMINER_GENERICARRAY_STR_HITS, 0);
        assert_eq!(BOSMINER_TYPENUM_U88_HITS, 0);
        assert_eq!(BOSMINER_U86_INSTRUCTION_COLLISION_OFF, 0x00E8_0871);
        assert!(refuse_genericarray_u86_as_job_length_fact().is_err());
        assert!(admit_s19k_bosminer_scan_scripts(
            include_str!("../../../scripts/s19k_scan_bosminer_genericarray.py"),
            include_str!("../../../scripts/s19k_scan_bosminer_job_bytes.py"),
            include_str!("../../../scripts/s19k_scan_bosminer_pack_body.py"),
            include_str!("../../../scripts/s19k_scan_jig_job_bytes.py"),
            include_str!("../../../scripts/s19k_scan_bosminer_memcpy_sizes.py"),
        )
        .is_ok());
        assert_eq!(S19K_PACKED_BOSMINER_BYTES, 9_113_388);
        assert_eq!(S19K_PACKED_BOSMINER_55AA2136_HITS, 0);
        assert!(refuse_s19k_packed_bosminer_as_job_template().is_err());
        assert_eq!(BOSMINER_FAILED_SEND_WORK_OFF, 0x00F2_3802);
        assert_eq!(BOSMINER_FAILED_SEND_WORK_JOB_IMM_XREFS, 0);
        assert!(refuse_failed_send_work_xrefs_as_job_length().is_err());
        assert_eq!(BOSMINER_55AA5205_HITS, 0);
        assert_eq!(BOSMINER_55AA5305_HITS, 0);
        assert!(refuse_missing_getaddress_literal_as_job_length().is_err());
        let body =
            build_s19k_braiins_mining_on_work_body(0x10, 0x2000_0000, [0u8; 32], [0u8; 32], 0, 0);
        let wire = reconstruct_s19k_send_work_wire(&body).unwrap();
        assert_eq!(&wire[0..4], &CLOSED_11D_PREFIX);
        assert_eq!(wire.len(), 0x58);
        let mut miss = body;
        miss[1] = 0x56;
        assert!(reconstruct_s19k_send_work_wire(&miss).is_err());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("reconstruct_s19k_send_work_wire"),
            "first-frame log must use the shipped reconstruct, not an ad-hoc 21 56 wrap"
        );
    }

    #[test]
    fn wave44_job_nbits_is_self_plus_0x78_not_engine_vtable() {
        assert!(admit_bosminer_job_nbits_is_self_plus_0x78().is_ok());
        assert!(refuse_bosminer_pack_caller_engine_plus_0x90_as_nbits().is_err());
        assert_eq!(BOSMINER_JOB_NBITS_GETTER_INSN, 0xB940_7800);
        assert_eq!(BOSMINER_JOB_NBITS_VTABLE_HITS, 2);
        assert_eq!(BOSMINER_STRATUM_V2_JOB_VTABLE_VA + 0x90, 0x01A1_2268);
        let mut job_obj = [0u8; BOSMINER_JOB_SIZE];
        job_obj[BOSMINER_JOB_NBITS_OFF..BOSMINER_JOB_NBITS_OFF + 4]
            .copy_from_slice(&0x1A44_B9F6u32.to_le_bytes());
        assert_eq!(
            s19k_braiins_job_nbits_from_object(&job_obj).unwrap(),
            0x1A44_B9F6
        );
        let packed = pack_s19k_braiins_ghidra_job_body(
            0x08,
            0x2000_0000,
            [0u8; 32],
            [0u8; 32],
            0x5F5E_1000,
            0x1A44_B9F6,
        );
        assert_eq!(&packed[8..12], &0x1A44_B9F6u32.to_le_bytes());
    }

    #[test]
    fn wave45_uart_job_id_is_engine_fn_not_ext_work_id() {
        assert!(admit_bosminer_engine_midstate_log(0x70).is_ok());
        assert!(admit_bosminer_engine_midstate_log(0x90).is_err());
        assert_eq!(s19k_braiins_midstate_count_from_log(0).unwrap(), 1);
        assert_eq!(s19k_braiins_midstate_count_from_log(3).unwrap(), 8);
        assert!(s19k_braiins_midstate_count_from_log(4).is_err());
        assert_eq!(s19k_braiins_fpga_work_id_count(0).unwrap(), 0x1_0000);
        assert_eq!(s19k_braiins_fpga_work_id_count(3).unwrap(), 0x2000);
        assert!(refuse_ext_work_id_to_hw_as_s19k_uart_job_id().is_err());
        assert!(refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id().is_err());
        assert_eq!(BOSMINER_PACK_CALLER_WORKER_RS_LINE, 482);
        assert!(BOSMINER_WORKER_RS.ends_with("worker.rs"));
        assert!(BOSMINER_EXT_WORK_ID_RS.ends_with("ext_work_id.rs"));
        assert_eq!(BOSMINER_FILL_MIDSTATES, 1);
        assert_eq!(BOSMINER_ENGINE_JOB_ID_FN_OFF, 0x90);
        assert_eq!(BOSMINER_REGISTRY_EMPTY_LINE, 119);
        assert_eq!(BOSMINER_REGISTRY_ASSERT_LINE, 148);
    }

    #[test]
    fn wave46_work_plus_0x40_is_registry_work_id() {
        assert!(admit_bosminer_work_plus_0x40_is_registry_work_id(0x40).is_ok());
        assert!(admit_bosminer_work_plus_0x40_is_registry_work_id(0x38).is_err());
        assert!(refuse_invented_registry_size_as_uart_job_id_space(32).is_err());
        assert!(refuse_invented_registry_size_as_uart_job_id_space(128).is_err());
        assert!(refuse_invented_registry_size_as_uart_job_id_space(256).is_err());
        assert!(refuse_invented_registry_size_as_uart_job_id_space(77).is_ok());
        assert_eq!(BOSMINER_REGISTRY_SLOT_STRIDE, 0x78);
        assert_eq!(BOSMINER_WORK_BUILD_FN_VA, 0x00BF_5414);
        assert_eq!(BOSMINER_REGISTRY_INSERT_FN_VA, 0x00BE_7084);
        assert_eq!(BOSMINER_WORK_ID_STP_VA, 0x00BF_6454);
        assert_eq!(BOSMINER_WORK_ID_STP_INSN, 0xA903_DB68);
        assert!(!BOSMINER_REGISTRY_SIZE_KNOWN);
        assert_eq!(s19k_braiins_uart_job_id_inputs(7, 0).unwrap(), (7, 1));
        assert_eq!(s19k_braiins_uart_job_id_inputs(7, 3).unwrap(), (7, 8));
        assert!(s19k_braiins_uart_job_id_inputs(7, 4).is_err());
        assert!(refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id().is_err());
    }

    #[test]
    fn wave47_engine_job_id_fn_not_named_from_ctor() {
        assert_eq!(BOSMINER_WORKER_SIZE, 0x1C8);
        assert_eq!(BOSMINER_JOB_ID_FN_ADRP_STR_HITS, 0);
        assert_eq!(BOSMINER_LSL3_RET_HITS, 0);
        assert_eq!(BOSMINER_AND_FF_RET_XREFS, 0);
        assert_eq!(BOSMINER_WORKER_CTOR_TRACE_MASK, 0xE000_0020);
        assert_eq!(BOSMINER_WORKER_NEW_FN_VA, 0x0090_3534);
        assert!(refuse_unlocated_engine_job_id_fn_as_named_encoder().is_err());
        assert!(refuse_worker_ctor_e0000020_as_registry_size(0xE000_0020).is_err());
        assert!(refuse_worker_ctor_e0000020_as_registry_size(32).is_ok());
        assert!(refuse_unreferenced_and_ff_ret_as_uart_job_id().is_err());
        assert!(refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id().is_err());
        assert!(!BOSMINER_REGISTRY_SIZE_KNOWN);
    }

    #[test]
    fn wave48_uart_registry_size_is_0x100_shr_log_not_fpga() {
        assert!(admit_bosminer_uart_registry_size_is_0x100_shr_log().is_ok());
        assert_eq!(s19k_braiins_uart_registry_size_from_log(0).unwrap(), 0x100);
        assert_eq!(s19k_braiins_uart_registry_size_from_log(1).unwrap(), 0x80);
        assert_eq!(s19k_braiins_uart_registry_size_from_log(2).unwrap(), 0x40);
        assert_eq!(s19k_braiins_uart_registry_size_from_log(3).unwrap(), 0x20);
        assert!(s19k_braiins_uart_registry_size_from_log(4).is_err());
        assert!(refuse_fpga_0x10000_shr_log_as_uart_registry_size(0x1_0000).is_err());
        assert!(refuse_fpga_0x10000_shr_log_as_uart_registry_size(0x100).is_ok());
        assert!(refuse_aml_ctrl_rs_as_uart_registry_factory().is_err());
        assert_eq!(BOSMINER_AM3_FACTORY_0X100_SHR_HITS, 5);
        assert_eq!(BOSMINER_AM3_FACTORY_MOVZ_VAS.len(), 5);
        assert_eq!(BOSMINER_AM3_WORKER_CTOR_VAS[1], BOSMINER_WORKER_NEW_FN_VA);
        assert_eq!(BOSMINER_AM3_COMBO_BUG_LINE, 57);
        assert_eq!(BOSMINER_FPGA_0X10000_MOVZ_VA, 0x008A_EE2C);
        assert_eq!(
            s19k_braiins_uart_registry_size_from_log(0).unwrap(),
            BOSMINER_UART_REGISTRY_SIZE_BASE
        );
        // Fill midstates=1 ⇒ log 0 ⇒ 256. Still refuse pinning 256 alone.
        assert!(refuse_invented_registry_size_as_uart_job_id_space(256).is_err());
        assert!(!BOSMINER_REGISTRY_SIZE_KNOWN);
        assert!(refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id().is_err());
    }

    #[test]
    fn wave49_bm1366_uses_same_am3_uart_registry_factory() {
        assert!(admit_bosminer_bm1366_uses_am3_uart_registry_factory().is_ok());
        assert!(refuse_bm1366_exclusive_uart_registry_size().is_err());
        assert_eq!(BOSMINER_AM3_CHIP_DISPATCH_FN_VA, 0x008D_6CF0);
        assert_eq!(BOSMINER_AM3_CHIP_DISPATCH_1366_MOVZ_VA, 0x008D_6D14);
        assert_eq!(BOSMINER_AM3_CHIP_DISPATCH_IDS[1], 0x1366);
        assert_eq!(s19k_braiins_uart_registry_size_from_log(0).unwrap(), 0x100);
        assert!(BOSMINER_BM1366_RS.contains("bm1366.rs"));
        assert!(BOSMINER_BM136X_RS.contains("bm136x.rs"));
        assert_eq!(BOSMINER_HASHCHAIN_TICKET_LINE, 298);
        assert!(refuse_aml_ctrl_rs_as_uart_registry_factory().is_err());
        assert!(refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id().is_err());
    }

    #[test]
    fn wave50_uart_relay_nonce_gap_is_flags_bit2() {
        use crate::s19k_bm1366_wire_b::{
            admit_bosminer_uart_relay_pack_matches_public_chip0, pack_uart_relay,
            pack_uart_relay_braiins, refuse_uart_relay_without_nonce_gap_field,
            BOSMINER_UART_RELAY_PACK_FN_VA, BOSMINER_UART_RELAY_REV16_INSN, UART_RELAY_CHIP0_DIST,
            UART_RELAY_CHIP0_PUBLIC,
        };
        assert!(admit_bosminer_uart_relay_pack_matches_public_chip0().is_ok());
        assert!(refuse_uart_relay_without_nonce_gap_field().is_err());
        assert_eq!(
            pack_uart_relay(true, true, UART_RELAY_CHIP0_DIST),
            UART_RELAY_CHIP0_PUBLIC
        );
        assert_eq!(
            pack_uart_relay_braiins(true, true, false, UART_RELAY_CHIP0_DIST),
            0x007C_0003
        );
        assert_eq!(
            pack_uart_relay_braiins(true, true, true, UART_RELAY_CHIP0_DIST),
            0x007C_0007
        );
        assert_eq!(BOSMINER_UART_RELAY_PACK_FN_VA, 0x0083_CA30);
        assert_eq!(BOSMINER_UART_RELAY_REV16_INSN, 0x5AC0_094A);
        assert!(refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id().is_err());
    }

    #[test]
    fn wave51_uart_job_id_is_work_id_shl_log_from_rx_inverse() {
        assert!(admit_bosminer_uart_job_id_is_work_id_shl_log().is_ok());
        assert!(refuse_factory_clone_as_first_writer_of_job_id_fn().is_err());
        assert_eq!(s19k_braiins_uart_job_id(0, 0).unwrap(), 0);
        assert_eq!(s19k_braiins_uart_job_id(7, 0).unwrap(), 7);
        assert_eq!(s19k_braiins_uart_job_id(255, 0).unwrap(), 255);
        assert!(s19k_braiins_uart_job_id(256, 0).is_err());
        assert_eq!(s19k_braiins_uart_job_id(7, 3).unwrap(), 0x38);
        assert_eq!(s19k_braiins_uart_job_id(31, 3).unwrap(), 0xF8);
        assert!(s19k_braiins_uart_job_id(32, 3).is_err());
        assert_eq!(s19k_braiins_uart_work_id_from_rx_job_byte(7, 0).unwrap(), 7);
        assert_eq!(
            s19k_braiins_uart_work_id_from_rx_job_byte(0x38, 3).unwrap(),
            7
        );
        assert_eq!(BOSMINER_FACTORY_CLONE_FN_VA, 0x0087_5F54);
        assert_eq!(BOSMINER_WORK_RESP_PARSE_FN_VA, 0x0091_C0A0);
        assert_eq!(BOSMINER_PACK_CALLER_LSL_COUNT_INSN, 0x9ACA_2121);
        assert_eq!(BOSMINER_ENGINE_NONCE_FN_OFF, 0x88);
        assert!(refuse_slot_shl_3_as_offline_proven_braiins_uart_job_id().is_err());
        assert!(refuse_unlocated_engine_job_id_fn_as_named_encoder().is_err());
    }

    #[test]
    fn wave52_nonce_arg_is_rev_payload_and_count_to_log() {
        assert!(admit_bosminer_work_resp_rev_then_nonce_fn().is_ok());
        assert!(admit_bosminer_1366_factory_is_876ca8().is_ok());
        assert!(refuse_work_resp_low8_div_as_pool_nonce().is_err());
        assert!(refuse_rev_w0_ret_as_engine_nonce_fn().is_err());
        assert!(refuse_mul_lslv_ret_as_named_job_id_encoder().is_err());
        assert!(refuse_factory_clone_as_first_writer_of_job_id_fn().is_err());
        assert_eq!(s19k_braiins_midstate_log_from_count(1).unwrap(), 0);
        assert_eq!(s19k_braiins_midstate_log_from_count(2).unwrap(), 1);
        assert_eq!(s19k_braiins_midstate_log_from_count(4).unwrap(), 2);
        assert_eq!(s19k_braiins_midstate_log_from_count(8).unwrap(), 3);
        assert!(s19k_braiins_midstate_log_from_count(0).is_err());
        assert!(s19k_braiins_midstate_log_from_count(3).is_err());
        assert!(s19k_braiins_midstate_log_from_count(16).is_err());
        assert_eq!(
            s19k_braiins_uart_nonce_arg_from_payload8(0x1122_3344_DDCC_BBAA),
            0xAABB_CCDD
        );
        assert_eq!(
            s19k_braiins_uart_job_byte_from_payload8(0x0000_3800_0000_0000),
            0x38
        );
        assert_eq!(
            s19k_braiins_uart_version_from_payload8(0x3412_0000_0000_0000),
            0x1234
        );
        assert_eq!(BOSMINER_WORK_RESP_REV_INSN, 0x5AC0_0B00);
        assert_eq!(BOSMINER_MIDSTATE_COUNT_FN_VA, 0x0125_FC94);
        assert_eq!(BOSMINER_REV_W0_RET_HITS, 0);
        assert_eq!(BOSMINER_MUL_W0_W1_RET_HITS, 0);
        assert!(BOSMINER_MIDSTATE_COUNT_RS.ends_with("midstate_count.rs"));
        assert_eq!(
            s19k_braiins_uart_work_id_from_rx_job_byte(
                s19k_braiins_uart_job_byte_from_payload8(0x0000_3800_0000_0000),
                3
            )
            .unwrap(),
            7
        );
    }

    #[test]
    fn wave53_fill_path_encodes_work_id_not_slot_shl_3() {
        assert!(admit_bosminer_fill_path_job_id_is_work_id_shl_log().is_ok());
        assert!(refuse_am3_factory_as_first_writer_of_engine_fn_ptrs().is_err());
        assert!(refuse_bf3264_as_engine_nonce_fn().is_err());
        assert_eq!(s19k_braiins_fill_midstate_log(), 0);
        assert_eq!(s19k_braiins_fill_job_id(0), 0);
        assert_eq!(s19k_braiins_fill_job_id(2), 2);
        assert_ne!(s19k_braiins_fill_job_id(2), 2u8 << 3);
        assert_eq!(s19k_braiins_fill_job_id(255), 255);
        assert_eq!(BOSMINER_FILL_MIDSTATE_LOG, 0);
        assert_eq!(BOSMINER_WORK_RESP_DIV_FN_VA, 0x00BF_3264);
        assert_eq!(BOSMINER_WORK_RESP_DIV_LDR_INSN, 0xF940_0008);
        assert_eq!(BOSMINER_AM3_FACTORY_STR_88_90_HITS, 0);
        assert!(!LIVE_MISS_VS_CLOSED.closed_job_id_is_slot_shl_3);
        let wire = build_s19k_braiins_mining_on_work_wire(2, 0, [0u8; 32], [0u8; 32], 0, 0);
        assert_eq!(wire[4], 2);
        let body = build_s19k_braiins_mining_on_work_body(2, 0, [0u8; 32], [0u8; 32], 0, 0);
        assert_eq!(body[2], 2);
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("SerialMiningEngineBookkeeping::s19k_braiins_fill"),
            "BM1366+passthrough must use the 256-slot fill cursor, not step-8"
        );
        assert!(
            serial.contains("hunt_s19k_bm1366_fill_from_admitted_tx_path"),
            "fill RX must bind tagged body to a path that received the sent work"
        );
        assert!(admit_s19k_no_held_uart_abort_opcode().is_ok());
        let esp_bm1366 =
            include_str!("../../../../../");
        let esp_jobs = include_str!(
            "../../../../../"
        );
        assert!(admit_s19k_esp_bm1366_has_no_work_abort_opcode(esp_bm1366, esp_jobs).is_ok());
        assert!(refuse_s19k_cmd_inactive_as_midrun_work_replace().is_err());
        assert!(refuse_s19k_esp_job_step8_as_track1_fill().is_err());
        assert!(refuse_s19k_experimental_job_flip_as_chip_work_replace().is_err());
        assert!(refuse_s19k_experimental_job_flip_as_production().is_err());
        assert_eq!(s19k_track1_fill_job_id(2, 0, true), 2);
        assert_eq!(s19k_track1_fill_job_id(2, 1, false), 2);
        assert_eq!(
            s19k_track1_fill_job_id(2, 1, true),
            2 ^ S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP
        );
        assert_ne!(s19k_track1_fill_job_id(2, 1, true), 2u8 << 3);
        assert!(!s19k_experimental_post_clean_flip_enabled_from_env(None));
        assert!(!s19k_experimental_post_clean_flip_enabled_from_env(Some(
            "0"
        )));
        assert!(s19k_experimental_post_clean_flip_enabled_from_env(Some(
            "1"
        )));
        assert!(admit_s19k_production_post_clean_job_flip_is_env_gated(serial).is_ok());
        assert!(admit_s19k_production_post_clean_job_flip_is_env_gated("no flip").is_err());
    }

    #[test]
    fn wave425_post_clean_chain_inactive_is_env_gated_evidence_pinned() {
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        // Evidence pins: BM1366 protocol CMD=3 chain inactive, ESP-Miner
        // _send_chain_inactive wire 55 AA 53 05 00 00 03.
        assert!(admit_s19k_bm1366_chain_inactive_wire_evidence(
            &S19K_BM1366_CHAIN_INACTIVE_BODY,
            &S19K_BM1366_CHAIN_INACTIVE_WIRE,
        )
        .is_ok());
        assert!(admit_s19k_bm1366_chain_inactive_wire_evidence(
            &[0x53, 0x05, 0x00, 0x01],
            &S19K_BM1366_CHAIN_INACTIVE_WIRE,
        )
        .is_err());
        assert!(admit_s19k_bm1366_chain_inactive_wire_evidence(
            &S19K_BM1366_CHAIN_INACTIVE_BODY,
            &[0x55, 0xAA, 0x53, 0x05, 0x00, 0x00, 0x04],
        )
        .is_err());
        // Env gate mirrors the flip gate: default off, "1" only.
        assert!(!s19k_experimental_post_clean_chain_inactive_enabled_from_env(None));
        assert!(!s19k_experimental_post_clean_chain_inactive_enabled_from_env(Some("0")));
        assert!(s19k_experimental_post_clean_chain_inactive_enabled_from_env(Some("1")));
        assert!(admit_s19k_live431_leftover_admits_experimental_inactive().is_ok());
        assert!(admit_s19k_live436_wrap_retire_leftover_admits_first_clean_inactive().is_ok());
        assert!(admit_s19k_live436_leftover3_wrap4_early_admits_inactive().is_ok());
        assert!(admit_s19k_live437_wrap4_same_tick_admits_before_header_climb().is_ok());
        assert!(s19k_post_inactive_flush_measured_not_replace(
            Some(6),
            0,
            3,
            0
        ));
        assert!(!s19k_post_inactive_replace_proven(Some(6), 0, 3, 0));
        assert!(s19k_flush_measured_is_not_replace(true, false));
        assert!(!s19k_flush_measured_is_not_replace(true, true));
        assert!(refuse_s19k_live438_post_flush_leftover0_as_replace().is_err());
        assert!(s19k_leftover_header_is_not_tx_leftover(true, false));
        assert!(!s19k_leftover_header_is_not_tx_leftover(true, true));
        assert!(!s19k_leftover_header_admits_second_cmd3(0, 3, 0));
        assert!(refuse_s19k_live438_header_leftover_as_second_cmd3().is_err());
        assert_eq!(
            admit_s19k_production_wrap4_logs_snapshot_leftover(serial),
            Ok(())
        );
        const LIVE437: &str = include_str!(
            "../../../../../"
        );
        assert_eq!(
            admit_s19k_live437_launch_wrap4_early_is_experimental(LIVE437),
            Ok(())
        );
        const LIVE436: &str = include_str!(
            "../../../../../"
        );
        assert!(LIVE436.contains("unset DCENT_S19K_EXPERIMENTAL_WRAP4_EARLY_CLEAN"));
        assert!(!s19k_experimental_wrap4_early_clean_enabled_from_env(None));
        assert!(crate::admit_s19k_wrap4_snapshot_preserves_wrap_retire_leftover().is_ok());
        assert!(s19k_leftover_hit_admits_experimental_inactive(4, 0, 0));
        assert!(s19k_leftover_hit_admits_experimental_inactive(3, 0, 0));
        assert!(!s19k_leftover_hit_admits_experimental_inactive(0, 0, 0));
        assert!(!s19k_leftover_hit_admits_experimental_inactive(0, 6, 0));
        assert!(s19k_leftover_hit_admits_experimental_inactive(216, 1, 0));
        assert!(!s19k_leftover_hit_admits_experimental_inactive(216, 1, 1));
        assert!(admit_s19k_live439_wrap7_leftover_readmit().is_ok());
        assert!(admit_s19k_live440_wrap7_snapshots_post_admit_store().is_ok());
        assert!(admit_s19k_live440_header_only_refuses_leftover_hit_still_admits().is_ok());
        assert!(admit_s19k_live441_wrap5_snapshots_before_wrap6_death().is_ok());
        assert_eq!(
            admit_s19k_production_wrap7_readmit_logs_and_queues(serial),
            Ok(())
        );
        assert_eq!(
            admit_s19k_production_wrap5_snapshot_logs_and_queues(serial),
            Ok(())
        );
        assert!(refuse_s19k_bosminer_53050000_as_chain_inactive_template().is_err());
        assert!(refuse_s19k_jig_chain_inactive_log_as_midrun_abort().is_err());
        assert!(admit_s19k_live431_leftover_vs_meets_unproven().is_ok());
        assert!(admit_s19k_live433_leftover_vs_meets_unproven().is_ok());
        assert!(!s19k_leftover_hit_vs_meets_replace_proven(4, 0, 0, false));
        assert!(!s19k_leftover_hit_vs_meets_replace_proven(4, 0, 0, true));
        assert!(!s19k_leftover_hit_vs_meets_replace_proven(0, 0, 0, false));
        assert!(s19k_leftover_hit_vs_meets_replace_proven(1, 0, 4, true));
        // Production stays fill identity re-fill; leftover_hit=4 only
        // admits the experimental env, not production default.
        assert!(refuse_s19k_post_clean_chain_inactive_as_production().is_err());
        // The prior pin still holds: CMD_INACTIVE is not THE mid-run
        // work-replace;  only ships it as an experimental flush.
        assert!(refuse_s19k_cmd_inactive_as_midrun_work_replace().is_err());
        assert!(admit_s19k_production_post_clean_chain_inactive_is_env_gated(serial).is_ok());
        assert!(
            admit_s19k_production_post_clean_chain_inactive_is_env_gated("no inactive").is_err()
        );
    }

    #[test]
    fn s19k_live439_planner_numbers_drive_shipped_helpers() {
        let admit_wire = s19k_leftover_hit_admits_experimental_inactive(216, 1, 0);
        let refuse_header = s19k_leftover_hit_admits_experimental_inactive(0, 3, 0);
        let readmit = s19k_wrap7_leftover_readmit_due(7, Some(2), 216, 1, 0, false, false, true);
        let production =
            s19k_wrap7_leftover_readmit_due(7, Some(2), 216, 1, 0, false, false, false);
        eprintln!("leftover_admit(216,1,0)={admit_wire}");
        eprintln!("leftover_admit(0,3,0)={refuse_header}");
        eprintln!("wrap7_readmit(exp=true,wrap_rx=7,leftover_at=2,216,1,0)={readmit}");
        eprintln!("wrap7_readmit(exp=false)={production}");
        assert!(
            admit_wire,
            "live439 leftover_hit=216 leftover_header=1 must leftover-admit"
        );
        assert!(!refuse_header, "live438 leftover_header-only must refuse");
        assert!(readmit, "live439 wrap-7 leftover-readmit must fire");
        assert!(!production, "production wrap-7 leftover-readmit stays OFF");
        assert_eq!(admit_s19k_live439_wrap7_leftover_readmit(), Ok(()));
        let live440_refuse =
            s19k_wrap7_leftover_readmit_due(7, Some(1), 0, 3, 0, false, false, true);
        let live440_snap = s19k_wrap7_leftover_snapshot_due(7, Some(1), false, false, true);
        eprintln!("live440_wrap7_readmit(0,3,0)={live440_refuse}");
        eprintln!("live440_wrap7_snapshot={live440_snap}");
        assert!(
            !live440_refuse,
            "live440 leftover_header-only must refuse leftover-readmit"
        );
        assert!(
            live440_snap,
            "live440 wrap_rx=7 leftover_at=1 must snapshot POST-admit 21 36"
        );
        assert_eq!(
            admit_s19k_live440_wrap7_snapshots_post_admit_store(),
            Ok(())
        );
        let live441_wrap5 = s19k_wrap5_leftover_snapshot_due(5, Some(4), false, false, true);
        let live441_wrap5_header =
            s19k_wrap5_leftover_readmit_due(5, Some(4), 0, 4, 0, false, false, true);
        let live441_wrap5_hit =
            s19k_wrap5_leftover_readmit_due(5, Some(4), 4, 0, 0, false, false, true);
        eprintln!("live441_wrap5_snapshot={live441_wrap5}");
        eprintln!("live441_wrap5_readmit_header_only={live441_wrap5_header}");
        eprintln!("live441_wrap5_readmit_hit={live441_wrap5_hit}");
        assert!(
            live441_wrap5,
            "live441 wrap_rx=5 leftover_at=4 must snapshot"
        );
        assert!(
            !live441_wrap5_header,
            "live441 leftover_header-only must refuse wrap-5 leftover-readmit"
        );
        assert!(
            live441_wrap5_hit,
            "after wrap-5 snapshot leftover_hit leftover-readmits"
        );
        assert_eq!(
            admit_s19k_live441_wrap5_snapshots_before_wrap6_death(),
            Ok(())
        );
    }

    #[test]
    fn s19k_plan_post_clean_uart_replace_is_identity_unless_env_gates() {
        let protocol = include_str!("../tests/fixtures/bm1366_protocol_reference.md");
        assert!(admit_s19k_held_protocol_has_no_job_abort_opcode(protocol).is_ok());
        let session = s19k_plan_post_clean_uart_replace(false, true, true, 4, 0, 0);
        assert!(!session.chain_inactive);
        assert!(!session.job_flip);
        assert!(!session.refill);
        assert_eq!(session.ops().count(), 0);

        let production = s19k_plan_post_clean_uart_replace(true, false, false, 4, 0, 0);
        assert!(!production.chain_inactive);
        assert!(!production.job_flip);
        assert!(production.refill);
        assert_eq!(
            production.ops().collect::<Vec<_>>(),
            vec![S19kPostCleanUartOp::IdentityRefill]
        );

        let first_clean = s19k_plan_post_clean_uart_replace(true, true, true, 0, 0, 0);
        assert!(!first_clean.chain_inactive);
        assert!(!first_clean.job_flip);
        assert!(first_clean.refill);
        assert!(admit_s19k_job_flip_is_leftover_admitted().is_ok());
        assert!(admit_s19k_second_clean_plans_from_pre_reset_leftover().is_ok());

        let both = s19k_plan_post_clean_uart_replace(true, true, true, 4, 0, 0);
        assert!(both.chain_inactive);
        assert!(both.job_flip);
        assert_eq!(
            both.ops().collect::<Vec<_>>(),
            vec![
                S19kPostCleanUartOp::ChainInactive,
                S19kPostCleanUartOp::IdentityRefill
            ]
        );

        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("s19k_plan_post_clean_uart_replace("),
            "serial_mining must execute the leftover-safe UART replace planner"
        );
        assert!(
            serial.contains("post_clean_uart.chain_inactive"),
            "post-clean chain-inactive must come from the planner, not a raw env bool"
        );
        assert!(!s19k_experimental_wrap4_early_clean_enabled_from_env(None));
        assert!(s19k_experimental_wrap4_early_clean_enabled_from_env(Some(
            "1"
        )));
        assert!(admit_s19k_live434_wrap4_early_clean_was_due().is_ok());
        assert!(
            serial.contains("s19k_plan_wrap4_early_leftover_safe("),
            "serial_mining must call the wrap-4 early leftover-safe planner"
        );
        assert!(
            serial.contains("s19k_track1_clean_after_rx_death_silent"),
            "mid-run clean must snapshot clean-after-RX-death from per-port silence"
        );
        assert!(
            serial.contains("s19k_post_inactive_replace_proven("),
            "funnel must print leftover-vs-meets replace_proven from the live helper"
        );
    }

    #[test]
    fn s19k_experimental_post_clean_replace_is_shipped_21_36_with_flipped_id() {
        let mut merkle = [0u8; 32];
        merkle[0] = 0xAB;
        let mut prev = [0u8; 32];
        prev[0] = 0xCD;
        let work_id = 5u8;
        let asic = s19k_experimental_post_clean_job_id(work_id, 1);
        assert_eq!(asic, work_id ^ S19K_EXPERIMENTAL_POST_CLEAN_JOB_FLIP);
        assert_ne!(asic, work_id);
        let wire = build_s19k_braiins_mining_on_work_wire(
            asic,
            0x2000_0000,
            prev,
            merkle,
            0x6A82_57B0,
            0x1702_353D,
        );
        assert_eq!(&wire[0..4], &CLOSED_11D_PREFIX);
        let fields = unpack_s19k_braiins_ghidra_job_wire(&wire).expect("unpack");
        assert_eq!(fields.job_id, asic);
        assert_eq!(fields.merkle_root, merkle);
        assert_eq!(fields.prev_block_hash, prev);
        assert_ne!(fields.job_id, work_id);
    }

    #[test]
    fn s19k_jig_elf_has_no_closed11d_job_and_libc_abort_is_not_replace() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let blob = std::fs::read(&path).expect("held S19k jig ELF");
        assert!(admit_s19k_jig_has_no_closed11d_job(&blob).is_ok());
        assert_eq!(s19k_jig_closed11d_prefix_hits(&blob), 0);
        assert!(refuse_s19k_jig_libc_abort_as_work_replace(&blob).is_err());
        assert!(admit_s19k_jig_has_no_closed11d_job(&[0x55, 0xAA, 0x21, 0x36]).is_err());
    }

    #[test]
    fn wave54_work_resp_div_is_worker_plus_0x11c0() {
        assert!(admit_bosminer_uart_work_resp_div_is_worker_plus_0x11c0().is_ok());
        assert!(refuse_fpga_0x340_as_uart_work_resp_div().is_err());
        assert!(refuse_worker_ctor_str88_sp_as_engine_nonce_fn().is_err());
        assert!(refuse_unnamed_0x11c0_value_as_chip_count().is_err());
        assert!(refuse_asic_index_from_nonce_be_as_bf3264().is_err());
        assert!(refuse_bf3264_as_engine_nonce_fn().is_err());
        assert_eq!(s19k_braiins_work_resp_index(0xAB, 2).unwrap(), 0x55);
        assert_eq!(s19k_braiins_work_resp_index(0x04, 2).unwrap(), 2);
        assert!(s19k_braiins_work_resp_index(1, 0).is_err());
        assert_eq!(BOSMINER_UART_WORK_RESP_DIV_OFF, 0x11C0);
        assert_eq!(BOSMINER_FPGA_WORK_RESP_DIV_OFF, 0x340);
        assert_eq!(BOSMINER_WORK_RESP_DIV_MOVZ_INSN, 0x5282_3819);
        assert_eq!(BOSMINER_WORK_RESP_ADD_X2_INSN, 0x8B19_0262);
        assert_eq!(BOSMINER_FPGA_DIV_ADD_INSN, 0x910D_0260);
        assert_eq!(BOSMINER_WORKER_CTOR_STR88_SP_INSN, 0xF900_47F3);
        assert_eq!(BOSMINER_WORK_RESP_PARSE_CALLER_COUNT, 5);
        assert_eq!(BOSMINER_WORK_RESP_DIV_MOVZ_VAS[2], 0x008F_4AE8);
        assert_eq!(BOSMINER_WORK_RESP_PARSE_CALLER_VAS[2], 0x008F_4B88);
    }

    #[test]
    fn wave55_rx_copy_maps_div_to_wrapper_plus_0x11d0() {
        assert!(admit_bosminer_rx_object_is_wrapper_plus_0x10_copy().is_ok());
        assert!(refuse_serde_str_11c0_as_uart_div_writer().is_err());
        assert!(refuse_hashchain_str88_self_plus_90_as_engine_nonce_fn().is_err());
        assert!(refuse_unnamed_0x11c0_value_as_chip_count().is_err());
        assert_eq!(BOSMINER_RX_WRAPPER_COPY_OFF, 0x10);
        assert_eq!(BOSMINER_RX_WRAPPER_COPY_LEN, 0x1390);
        assert_eq!(BOSMINER_WRAPPER_DIV_OFF, 0x11D0);
        assert_eq!(
            BOSMINER_UART_WORK_RESP_DIV_OFF + BOSMINER_RX_WRAPPER_COPY_OFF,
            0x11D0
        );
        assert_eq!(BOSMINER_RX_WRAPPER_ADD_SRC_INSN, 0x9100_4261);
        assert_eq!(BOSMINER_RX_WRAPPER_SIZE_INSN, 0x5282_7202);
        assert_eq!(BOSMINER_HASHCHAIN_STR88_SELF_PTR_HITS, 5);
        assert_eq!(BOSMINER_HASHCHAIN_STR88_SELF_PTR_INSN, 0xF900_4674);
        assert_eq!(BOSMINER_HASHCHAIN_ADD90_INSN, 0x9102_4274);
        assert_eq!(BOSMINER_HASHCHAIN_RUN_FN_VA, 0x0089_271C);
        assert_eq!(BOSMINER_SERDE_STR_11C0_VA, 0x00B2_8344);
    }

    #[test]
    fn wave56_hashchain_div_is_self_plus_0x11f0() {
        assert!(admit_bosminer_hashchain_div_is_self_plus_0x11f0().is_ok());
        assert!(admit_bosminer_div_is_single_deref_udiv().is_ok());
        assert!(refuse_86e3d0_as_hashchain_spawn().is_err());
        assert!(refuse_749200_halt_box_as_uart_div_writer().is_err());
        assert!(refuse_unnamed_0x11c0_value_as_chip_count().is_err());
        assert!(admit_bosminer_rx_object_is_wrapper_plus_0x10_copy().is_ok());
        assert_eq!(BOSMINER_HASHCHAIN_RX_COPY_OFF, 0x30);
        assert_eq!(BOSMINER_HASHCHAIN_DIV_OFF, 0x11F0);
        assert_eq!(
            BOSMINER_HASHCHAIN_RX_COPY_OFF + BOSMINER_UART_WORK_RESP_DIV_OFF,
            0x11F0
        );
        assert_eq!(BOSMINER_HASHCHAIN_DIV_OFF - BOSMINER_WRAPPER_DIV_OFF, 0x20);
        assert_eq!(BOSMINER_HASHCHAIN_COPY_ADD_INSN, 0x9100_C261);
        assert_eq!(BOSMINER_HASHCHAIN_COPY_SIZE_INSN, 0x5282_7202);
        assert_eq!(BOSMINER_TLS_DROP_MRS_INSN, 0xD53B_D056);
        assert_eq!(BOSMINER_WORK_RESP_DIV_CBZ_INSN, 0xB400_00A8);
        assert_eq!(BOSMINER_WORK_RESP_DIV_AND_INSN, 0x9240_1C29);
        assert_eq!(BOSMINER_WORK_RESP_DIV_UDIV_INSN, 0x9AC8_0920);
        assert_eq!(BOSMINER_HALT_BOX_STR_11F0_INSN, 0xF908_FA75);
        assert_eq!(BOSMINER_HASHCHAIN_CTOR_STR_XZR_11F0_INSN, 0xF908_FABF);
        assert_eq!(BOSMINER_TLS_DROP_FN_VA, 0x0086_E3D0);
        assert_eq!(BOSMINER_TLS_DROP_INNER_FN_VA, 0x0128_CAA4);
        assert!(BOSMINER_HALT_RS.ends_with("halt.rs"));
        assert_eq!(s19k_braiins_work_resp_index(0x04, 2).unwrap(), 2);
    }

    #[test]
    fn wave57_ldr_11f0_is_box_drop_not_uart_div() {
        assert!(refuse_ldr_11f0_as_uart_div_reader().is_err());
        assert!(refuse_movz_11f0_as_field_addend().is_err());
        assert!(refuse_749200_halt_box_as_uart_div_writer().is_err());
        assert!(refuse_unnamed_0x11c0_value_as_chip_count().is_err());
        assert!(admit_bosminer_hashchain_div_is_self_plus_0x11f0().is_ok());
        assert_eq!(BOSMINER_LDR_11F0_HITS, 6);
        assert_eq!(BOSMINER_LDR_11F0_PAIR_11F8_HITS, 6);
        assert_eq!(BOSMINER_LDR_11F0_INSN, 0xF948_FA75);
        assert_eq!(BOSMINER_LDR_11F8_INSN, 0xF948_FE76);
        assert_eq!(BOSMINER_LDR_11F0_VAS[0], 0x0052_BEF4);
        assert_eq!(BOSMINER_LDR_11F0_VAS[5], 0x005C_60D8);
        assert_eq!(BOSMINER_MOVZ_11F0_MEMCPY_INSN, 0x5282_3E02);
        assert_eq!(BOSMINER_ANTMINER_DRIVER_INIT_XREF_VA, 0x0083_7200);
        assert_eq!(BOSMINER_RX_WRAPPER_PARSE_BL_VA, 0x008F_4B88);
        assert_eq!(BOSMINER_ANTMINER_DRIVER_INIT_STR, "AntminerDriver::init");
    }

    #[test]
    fn wave58_future_memcpy_and_ubfx_are_not_div_or_nonce_fn() {
        assert!(refuse_1270_future_memcpy_as_div_writer().is_err());
        assert!(refuse_ubfx_17_8_as_engine_nonce_fn().is_err());
        assert!(refuse_add90_str88_sp_as_engine_nonce_fn().is_err());
        assert!(refuse_unnamed_0x11c0_value_as_chip_count().is_err());
        assert!(admit_bosminer_hashchain_div_is_self_plus_0x11f0().is_ok());
        assert_eq!(BOSMINER_FUTURE_SNAP_SIZE, 0x1270);
        assert_eq!(BOSMINER_FUTURE_SNAP_SIZE_INSN, 0x5282_4E02);
        assert_eq!(BOSMINER_FUTURE_TAG2_OFF, 0x30);
        assert_eq!(BOSMINER_FUTURE_TAG2_INSN, 0xB900_3289);
        assert_eq!(BOSMINER_FUTURE_RESTORE_TAG2_INSN, 0x5280_0048);
        assert_eq!(BOSMINER_FUTURE_DROP_FN_VA, 0x0050_B9D0);
        assert_eq!(BOSMINER_OBJECT_30_1270_MEMCPY_HITS, 54);
        assert_eq!(BOSMINER_UBFX_17_8_HITS, 5);
        assert_eq!(BOSMINER_UBFX_17_8_INSN, 0x5311_60C6);
        assert_eq!(BOSMINER_UBFX_17_8_VAS[0], 0x0058_2B30);
        assert_eq!(BOSMINER_ADD90_STR88_NONSP_HITS, 0);
        assert_eq!(BOSMINER_ADD90_STR88_SP_HITS, 4);
        assert_eq!(BOSMINER_ADD90_STR88_SP_INSN, 0xF900_47E8);
        assert_eq!(BOSMINER_ADD90_SP_INSN, 0x9102_43FF);
        assert_eq!(BOSMINER_REG_STR_LSL3_HITS, 0);
    }

    #[test]
    fn wave59_factory_x1_is_engine_clone_not_text_str() {
        assert!(admit_bosminer_factory_x1_is_engine_template().is_ok());
        assert!(admit_bosminer_dispatch_1366_baud_is_3125k().is_ok());
        assert!(refuse_876398_str88_as_engine_nonce_fn().is_err());
        assert!(refuse_str118_and_strw_11c0_as_named_writers().is_err());
        assert!(refuse_unnamed_0x11c0_value_as_chip_count().is_err());
        assert_eq!(BOSMINER_CLONE_SRC_MOV_INSN, 0xAA01_03F4);
        assert_eq!(BOSMINER_CLONE_DEST_MOV_INSN, 0xAA00_03F3);
        assert_eq!(BOSMINER_FACTORY_X1_SAVE_INSN, 0xAA01_03F8);
        assert_eq!(BOSMINER_FACTORY_X1_LDR70_INSN, 0xF940_3B08);
        assert_eq!(BOSMINER_FUTURE_STR88_INSN, 0xF900_4668);
        assert_eq!(BOSMINER_STR118_ADRP_TEXT_HITS, 0);
        assert_eq!(BOSMINER_STRW_11C0_NONSP_HITS, 0);
        assert_eq!(BOSMINER_SPLIT_11C0_OBJ_HITS, 0);
        assert_eq!(BOSMINER_DISPATCH_BAUD_3125K, 3_125_000);
        assert_eq!(BOSMINER_DISPATCH_BAUD_MOVZ_INSN, 0x5295_E109);
        assert_eq!(BOSMINER_DISPATCH_BAUD_MOVK_INSN, 0x72A0_05E9);
        assert_eq!(BOSMINER_AM3_FACTORY_BL_HITS, 0);
        assert_eq!(BOSMINER_BM1366_VT_HASH_FN_VA, 0x008B_BFB0);
        assert_eq!(BOSMINER_ENGINE_MIDSTATE_LOG_OFF, 0x70);
    }

    #[test]
    fn wave60_factory_blr_is_dispatch_store_15f8_is_stack() {
        assert!(admit_bosminer_factory_addr_only_dispatch_store().is_ok());
        assert!(refuse_factory_15f8_as_heap_div_writer().is_err());
        assert!(refuse_slice10_str88_as_engine_nonce_fn().is_err());
        assert!(admit_bosminer_factory_x1_is_engine_template().is_ok());
        assert_eq!(BOSMINER_FACTORY_ADDR_ADRP_INSN, 0x90FF_FD08);
        assert_eq!(BOSMINER_FACTORY_ADDR_ADD_INSN, 0x9132_A108);
        assert_eq!(BOSMINER_FACTORY_WORKER_NEW_BL_INSN, 0x9402_31E5);
        assert_eq!(BOSMINER_FACTORY_WORKER_NEW_DEST_INSN, 0xAA17_03E0);
        assert_eq!(BOSMINER_FACTORY_SNAP_SIZE, 0x15F8);
        assert_eq!(BOSMINER_FACTORY_SNAP_SIZE_INSN, 0x5282_BF02);
        assert_eq!(BOSMINER_FACTORY_SNAP_DEST_ADD_INSN, 0x9101_03E9);
        assert_eq!(BOSMINER_FACTORY_SNAP_ORR_DEST_INSN, 0xB27D_0120);
        assert_eq!(BOSMINER_DROP_LDR8_BLR_FN_VA, 0x008D_809C);
        assert_eq!(BOSMINER_SLICE10_STR88_HITS, 7);
        assert_eq!(BOSMINER_SLICE10_STR88_INSN, 0xF900_4668);
        assert_eq!(BOSMINER_SLICE10_ADD_INSN, 0x9100_4108);
        assert_eq!(BOSMINER_AM3_FACTORY_BL_HITS, 0);
    }

    #[test]
    fn wave61_factory_blr_is_hashmap_get_value_plus_8() {
        assert!(admit_bosminer_factory_blr_is_get_value_plus_8().is_ok());
        assert!(refuse_sp1640_clone_as_named_div_integer().is_err());
        assert!(admit_bosminer_factory_addr_only_dispatch_store().is_ok());
        assert_eq!(BOSMINER_HASHMAP_GET_FN_VA, 0x0087_87A8);
        assert_eq!(BOSMINER_HASHMAP_GET_KEY_OFF, 0x19C);
        assert_eq!(BOSMINER_FACTORY_LDR8_INSN, 0xF940_0437);
        assert_eq!(BOSMINER_FACTORY_BLR_INSN, 0xD63F_02E0);
        assert_eq!(BOSMINER_FACTORY_GET_BL_INSN, 0x9401_0D53);
        assert_eq!(BOSMINER_FACTORY_PREP_BL_INSN, 0x9400_1830);
        assert_eq!(BOSMINER_FACTORY_GET_OUTER_BL_INSN, 0x97FE_DC15);
        assert_eq!(BOSMINER_SP1640_CLONE_BL_INSN, 0x9400_2342);
        assert_eq!(BOSMINER_SP1640_CLONE_SRC_INSN, 0xAA18_03E1);
        assert_eq!(BOSMINER_SP1640_CLONE_ADD_INSN, 0x9119_0000);
        assert_eq!(BOSMINER_FACTORY_GET_CALLER_VA, 0x0083_5220);
        assert_ne!(BOSMINER_HASHMAP_GET_KEY_OFF, BOSMINER_HASHCHAIN_DIV_OFF);
    }

    #[test]
    fn wave62_prep_is_vec_clone_x1_is_spawn_local738() {
        assert!(refuse_83b3a0_as_engine_88_copy().is_err());
        assert!(admit_bosminer_factory_x1_is_spawn_local738().is_ok());
        assert!(refuse_93cc3c_as_factory_x1().is_err());
        assert!(admit_bosminer_value_plus8_is_bm1366_vt0().is_ok());
        assert!(admit_bosminer_factory_blr_is_get_value_plus_8().is_ok());
        assert_eq!(BOSMINER_PREP_ADD_F0_INSN, 0x9103_C020);
        assert_eq!(BOSMINER_PREP_ADD_10_INSN, 0x9100_4280);
        assert_eq!(BOSMINER_PREP_STR88_HITS, 0);
        assert_eq!(BOSMINER_VEC_CLONE_LEN_LDR_INSN, 0xF940_0813);
        assert_eq!(BOSMINER_VEC_CLONE_PTR_LDR_INSN, 0xF940_0415);
        assert_eq!(BOSMINER_FACTORY_X1_LDR_SP78_INSN, 0xF940_3FE8);
        assert_eq!(BOSMINER_FACTORY_X1_MOV_INSN, 0xAA18_03E1);
        assert_eq!(BOSMINER_FACTORY_DEST_MOV_INSN, 0xAA17_03E0);
        assert_eq!(BOSMINER_FACTORY_CTX_MOV_INSN, 0xAA00_03F6);
        assert_eq!(BOSMINER_FACTORY_SPAWN_BLR_INSN, 0xD63F_02E0);
        assert_eq!(BOSMINER_FACTORY_SPAWN_DEST_ADD_INSN, 0x9101_A3E8);
        assert_eq!(BOSMINER_PREP_SRC_MOV_INSN, 0xAA13_03E1);
        assert_eq!(BOSMINER_93CC3C_SRC_ADD_INSN, 0x9108_C000);
        assert_eq!(BOSMINER_DISPATCH_VT0_LDR_INSN, 0xF945_754A);
        assert_eq!(BOSMINER_DISPATCH_1366_STP_INSN, 0xA902_ABE8);
        assert_eq!(BOSMINER_BM1366_VT0_FN_VA, 0x008D_BDF4);
        assert_eq!(BOSMINER_INSERT_VALUE_ORR8_INSN, 0xB27D_02A3);
        assert_ne!(BOSMINER_BM1366_VT0_FN_VA, 0x0087_6CA8);
    }

    #[test]
    fn wave63_vt0_is_prep_boxer_not_88_writer() {
        assert!(admit_bosminer_vt0_is_prep_boxer().is_ok());
        assert!(refuse_dbdf4_as_engine_88_writer().is_err());
        assert!(admit_bosminer_value_plus8_is_bm1366_vt0().is_ok());
        assert_eq!(BOSMINER_VT0_LDRB_228_INSN, 0x3948_A008);
        assert_eq!(BOSMINER_VT0_CMP1_INSN, 0x7100_051F);
        assert_eq!(BOSMINER_VT0_ADD_229_INSN, 0x9108_A668);
        assert_eq!(BOSMINER_VT0_COPY_230_INSN, 0x5280_4602);
        assert_eq!(BOSMINER_VT0_BOX_250_INSN, 0x5280_4A00);
        assert_eq!(BOSMINER_VT0_MEMCPY_BL_INSN, 0x940B_B46B);
        assert_eq!(BOSMINER_VT0_PANIC_LINE_INSN, 0x5280_0461);
        assert_eq!(BOSMINER_VT0_TAG_OFF, 0x228);
        assert_eq!(BOSMINER_VT0_U16_OFF, 0x229);
        assert_eq!(BOSMINER_VT0_COPY_SIZE, 0x230);
        assert_eq!(BOSMINER_VT0_BOX_SIZE, 0x250);
        assert_eq!(BOSMINER_VT0_STR88_HITS, 0);
        assert_eq!(BOSMINER_VT0_BL_HITS, 0);
        assert_ne!(BOSMINER_VT0_TAG_OFF, BOSMINER_ENGINE_NONCE_FN_OFF);
    }

    #[test]
    fn wave64_tag228_ones_are_two_strb_not_prep() {
        assert!(admit_bosminer_tag228_ones_are_two_strb().is_ok());
        assert!(refuse_5f5a20_7c_as_vt0_tag().is_err());
        assert!(refuse_prep_22c_as_vt0_tag().is_err());
        assert!(admit_bosminer_vt0_is_prep_boxer().is_ok());
        assert_eq!(BOSMINER_TAG228_STRB_HITS, 32);
        assert_eq!(BOSMINER_TAG228_STRB_WZR_HITS, 16);
        assert_eq!(BOSMINER_TAG1_STRB_HITS, 2);
        assert_eq!(BOSMINER_TAG1_A_MOVZ_INSN, 0x5280_002A);
        assert_eq!(BOSMINER_TAG1_A_STRB_INSN, 0x3908_A26A);
        assert_eq!(BOSMINER_TAG1_B_MOVZ_INSN, 0x5280_0028);
        assert_eq!(BOSMINER_TAG1_B_STRB_INSN, 0x3908_A2E8);
        assert_eq!(BOSMINER_TAG7C_MOVZ_INSN, 0x5280_0F88);
        assert_eq!(BOSMINER_TAG7C_STRB_INSN, 0x3908_A268);
        assert_eq!(BOSMINER_PREP_STRB_22C_INSN, 0x3908_B275);
        assert_eq!(BOSMINER_TAG1_A_BL_HITS, 0);
        assert_ne!(BOSMINER_VT0_TAG_OFF, 0x22C);
    }

    #[test]
    fn wave65_neither_tag1_strb_is_hashchain_prep_copies_w228() {
        assert!(refuse_7493e4_as_hashchain_tag228().is_err());
        assert!(refuse_6079d4_as_hashchain_tag228().is_err());
        assert!(admit_bosminer_prep_copies_hashchain_w228().is_ok());
        assert!(admit_bosminer_tag228_ones_are_two_strb().is_ok());
        assert_eq!(BOSMINER_HALT_SPLIT_ADD_INSN, 0x9140_0417);
        assert_eq!(BOSMINER_PREP_LDRW_228_INSN, 0xB942_2A9C);
        assert_eq!(BOSMINER_PREP_STRW_228_INSN, 0xB902_2A7C);
        assert_eq!(BOSMINER_TAG1_A_X19_MOV_INSN, 0xAA00_03F3);
        assert_eq!(BOSMINER_TAG1_A_ADD250_INSN, 0x9109_4276);
        assert_eq!(BOSMINER_TAG1_A_OFF_19C_HITS, 0);
        assert_eq!(BOSMINER_TAG1_A_OFF_11F0_HITS, 0);
        assert_eq!(BOSMINER_HALT_BOX_STR_11F0_INSN, 0xF908_FA75);
        assert_ne!(0x1228_usize, BOSMINER_VT0_TAG_OFF);
    }

    #[test]
    fn wave66_instantiate_2a0_and_878950_230_are_copies() {
        assert!(refuse_825568_2a0_as_first_228_writer().is_err());
        assert!(refuse_878950_230_as_first_228_writer().is_err());
        assert!(refuse_609a60_01000000_as_hashchain_tag().is_err());
        assert!(admit_bosminer_prep_copies_hashchain_w228().is_ok());
        assert_eq!(BOSMINER_INSTANTIATE_SNAP_SIZE, 0x2A0);
        assert_eq!(BOSMINER_INSTANTIATE_SNAP_INSN, 0x5280_5402);
        assert_eq!(BOSMINER_INSTANTIATE_MEMCPY_BL_INSN, 0x940E_8E52);
        assert_eq!(BOSMINER_INSTANTIATE_BUILD_230_INSN, 0x5280_4602);
        assert_eq!(BOSMINER_INSTANTIATE_BUILD_MEMCPY_BL_INSN, 0x940D_40DE);
        assert_eq!(BOSMINER_FACTORY_COPY_230_INSN, 0x5280_4602);
        assert_eq!(BOSMINER_TAG228_W1000000_MOVZ_INSN, 0x52A0_2008);
        assert_eq!(BOSMINER_TAG228_W1000000_STR_INSN, 0xB902_2A68);
        assert_eq!(BOSMINER_INSTANTIATE_BL_HITS, 1);
        assert_eq!(BOSMINER_INSTANTIATE_BUILD_FN_VA, 0x0087_8950);
        assert_ne!(BOSMINER_INSTANTIATE_SNAP_SIZE, BOSMINER_VT0_COPY_SIZE);
    }

    #[test]
    fn wave67_am3_init_has_no_228_store_or_movz1_strw() {
        assert!(admit_am3_hashchain_init_has_no_228_store().is_ok());
        assert!(refuse_movz1_strw_as_hashchain_228().is_err());
        assert!(refuse_825568_2a0_as_first_228_writer().is_err());
        assert_eq!(BOSMINER_AM3_HC_INIT_STR228_HITS, 0);
        assert_eq!(BOSMINER_AM3_HC_INIT_MEMCPY_GE80_HITS, 0);
        assert_eq!(BOSMINER_TAG1_STRW_NONSP_HITS, 0);
        assert_eq!(BOSMINER_AM3_HC_INIT_FNS.len(), 5);
        assert_eq!(BOSMINER_AM3_HC_INIT_FNS[0].0, 0x008C_FAD0);
        assert_eq!(BOSMINER_AM3_HC_INIT_FNS[4].0, 0x008D_236C);
        assert_eq!(BOSMINER_HASHCHAIN_STR88_SELF_PTR_HITS, 5);
    }

    #[test]
    fn wave68_no_split_or_ptr_store_am3_add228_is_panic() {
        assert!(refuse_split_200_strb28_as_hashchain_228().is_err());
        assert!(refuse_add228_strb0_as_hashchain_228().is_err());
        assert!(admit_am3_hashchain_add228_is_panic_ptr().is_ok());
        assert!(admit_am3_hashchain_init_has_no_228_store().is_ok());
        assert_eq!(BOSMINER_SPLIT_200_STRB28_HITS, 0);
        assert_eq!(BOSMINER_ADD228_STRB0_HITS, 0);
        assert_eq!(BOSMINER_AM3_HC_INIT_ADD228_PANIC_HITS, 10);
        assert_eq!(BOSMINER_AM3_HC_INIT_ADD228_INSN, 0x9108_A042);
        assert_eq!(BOSMINER_AM3_HC_INIT_PANIC_LINE_INSN, 0x5280_0441);
        assert_eq!(BOSMINER_AM3_HC_INIT_PANIC_BL_INSN, 0x97EE_0D52);
        assert_eq!(BOSMINER_AM3_HC_INIT_PANIC_LINE, 0x22);
        assert_eq!(BOSMINER_AM3_HC_INIT_ADD228_VAS[0], 0x008D_0160);
        assert_eq!(BOSMINER_AM3_HC_INIT_ADD228_VAS[9], 0x008D_2A18);
    }

    #[test]
    fn wave69_no_regoff_or_visit_store_dest228_memcpy_not_hc() {
        assert!(refuse_movz228_strb_regoff_as_hashchain_228().is_err());
        assert!(refuse_add228_bl_strb_x0_as_hashchain_228().is_err());
        assert!(refuse_9514c8_memcpy200_as_hashchain_228().is_err());
        assert!(admit_dest228_memcpy_is_five_non_hashchain().is_ok());
        assert_eq!(BOSMINER_MOVZ228_STRB_REGOFF_HITS, 0);
        assert_eq!(BOSMINER_ADD228_BL_STRB_X0_0_HITS, 0);
        assert_eq!(BOSMINER_DEST228_MEMCPY_HITS, 5);
        assert_eq!(BOSMINER_DEST228_MEMCPY_ADD_INSN, 0x9108_A2A0);
        assert_eq!(BOSMINER_DEST228_MEMCPY_SIZE, 0x200);
        assert_eq!(BOSMINER_DEST228_MEMCPY_SIZE_INSN, 0x5280_4002);
        assert_eq!(BOSMINER_DEST228_MEMCPY_BL_INSN, 0x9409_DEC3);
        assert_eq!(BOSMINER_CLONE228_MEMCPY_SIZE, 0x1F0);
        assert_eq!(BOSMINER_CLONE228_MEMCPY_SIZE_INSN, 0x5280_3E02);
        assert_eq!(BOSMINER_DEST228_OFF_19C_HITS, 0);
        assert_eq!(BOSMINER_DEST228_OFF_11F0_HITS, 0);
        assert_eq!(BOSMINER_DEST228_MEMCPY_FN_VA, 0x0094_FC6C);
    }

    #[test]
    fn wave70_no_stp_memset_or_wzr_hashchain_default() {
        assert!(refuse_stp_xzr_as_hashchain_228_default().is_err());
        assert!(refuse_1200524_as_memset().is_err());
        assert!(refuse_wzr_228_stores_as_hashchain().is_err());
        assert!(refuse_ticket_mask_836c20_as_hashchain_228().is_err());
        assert_eq!(BOSMINER_STP_XZR_220_228_NONSP_HITS, 0);
        assert_eq!(BOSMINER_STUR_XZR_228_HITS, 0);
        assert_eq!(BOSMINER_STR_XZR_228_NONSP_HITS, 7);
        assert_eq!(BOSMINER_STR_XZR_228_HC_HITS, 0);
        assert_eq!(BOSMINER_STR_XZR_228_INSN, 0xF901_167F);
        assert_eq!(BOSMINER_STR_WZR_228_HITS, 1);
        assert_eq!(BOSMINER_STR_WZR_228_INSN, 0xB902_2ADF);
        assert_eq!(BOSMINER_STRB_WZR_228_NONSP_HITS, 16);
        assert_eq!(BOSMINER_STRB_WZR_228_HC_HITS, 0);
        assert_eq!(BOSMINER_SLOT_SET_FN_VA, 0x0120_0524);
        assert_eq!(BOSMINER_SLOT_SET_BL_HITS, 358);
        assert_eq!(BOSMINER_SLOT_SET_ENTRY_INSN, 0xA9BE_57FE);
        assert_eq!(BOSMINER_TICKET_MASK_STRB_228_INSN, 0x3908_A15F);
        assert_eq!(BOSMINER_TICKET_MASK_STRB_FN_VA, 0x0083_6934);
    }

    #[test]
    fn wave71_no_post_alloc_or_base_memcpy_hashchain_228() {
        assert!(refuse_post_alloc_str228_as_hashchain().is_err());
        assert!(admit_bosminer_btree_str228_is_child_slot().is_ok());
        assert!(refuse_mov_dest_memcpy_ge229_as_hashchain().is_err());
        assert!(refuse_c6c594_2b0_as_hashchain().is_err());
        assert_eq!(BOSMINER_POST_ALLOC_STR228_NONSP_HITS, 3);
        assert_eq!(BOSMINER_POST_ALLOC_STR228_HC_HITS, 0);
        assert_eq!(BOSMINER_POST_ALLOC_STR228_INSN, 0xF901_1728);
        assert_eq!(BOSMINER_BTREE_STR220_228_HITS, 17);
        assert_eq!(BOSMINER_BTREE_STR220_INSN, 0xF901_1015);
        assert_eq!(BOSMINER_BTREE_STR228_INSN, 0xF901_1419);
        assert_eq!(BOSMINER_BTREE_NODE_LEN_OFF, 0x21A);
        assert_eq!(BOSMINER_BTREE_ALLOC2_STR228_INSN, 0xF901_1418);
        assert_eq!(BOSMINER_MOV_DEST_MEMCPY_HC_HITS, 0);
        assert_eq!(BOSMINER_MOV_DEST_228WIN_HITS, 7);
        assert_eq!(BOSMINER_BASE_ADD0_MEMCPY_GE229_HITS, 0);
        assert_eq!(BOSMINER_FUTURE_POLL_MEMCPY_860_INSN, 0x5281_0C02);
        assert_eq!(BOSMINER_C6C594_MEMCPY_2B0_INSN, 0x5280_5602);
        assert_eq!(BOSMINER_POST_ALLOC_STR228_VA, 0x0058_1A00);
        assert_eq!(BOSMINER_C6C594_MEMCPY_2B0_VA, 0x00C6_C9AC);
    }

    #[test]
    fn wave72_prep_three_callers_am3_wrap_is_future() {
        assert!(admit_bosminer_prep_has_three_bl_callers().is_ok());
        assert!(refuse_8258c0_as_first_228_writer().is_err());
        assert!(admit_am3_hashchain_wrapper_is_future_poll().is_ok());
        assert!(refuse_stur_228_as_hashchain().is_err());
        assert_eq!(BOSMINER_PREP_BL_HITS, 3);
        assert_eq!(BOSMINER_PREP_BL_A_INSN, 0x9400_5771);
        assert_eq!(BOSMINER_PREP_BL_B_INSN, 0x9400_569B);
        assert_eq!(BOSMINER_PREP_BL_C_INSN, 0x9400_1830);
        assert_eq!(BOSMINER_PREP_SIB_FN_VA, 0x0082_58C0);
        assert_eq!(BOSMINER_AM3_WRAP_HITS, 5);
        assert_eq!(BOSMINER_AM3_WRAP_LDR10_INSN, 0xB940_1008);
        assert_eq!(BOSMINER_AM3_WRAP_ADD18_INSN, 0x9100_6260);
        assert_eq!(BOSMINER_AM3_WRAP0_BL_INSN, 0x9400_0B23);
        assert_eq!(BOSMINER_STUR_228_ANY_HITS, 0);
        assert_eq!(BOSMINER_AM3_WRAP_FNS[4], (0x008C_CC3C, 0x008D_236C));
    }

    #[test]
    fn wave73_wrap_callers_are_outer_future() {
        assert!(admit_am3_wrap_has_ten_bl_callers().is_ok());
        assert!(admit_am3_wrap_caller_is_outer_future().is_ok());
        assert!(refuse_8e7454_as_hashchain_228().is_err());
        assert_eq!(BOSMINER_AM3_WRAP_BL_HITS, 10);
        assert_eq!(BOSMINER_AM3_WRAP_CALLER_ADD20_INSN, 0x9100_8260);
        assert_eq!(BOSMINER_AM3_WRAP_CALLER_BL_INSN, 0x97FF_965E);
        assert_eq!(BOSMINER_AM3_WRAP_CALLER_FN_VA, 0x008E_7454);
        assert_eq!(BOSMINER_AM3_WRAP_CALLER_STR228_HITS, 0);
        assert_eq!(BOSMINER_AM3_WRAP_CALLER_BL_VA, 0x008E_749C);
    }

    #[test]
    fn wave74_outer_future_box_is_180_not_228_template() {
        assert!(admit_bosminer_outer_future_box_is_180().is_ok());
        assert!(admit_bosminer_vtable_19c6b50_is_thunk_e7454().is_ok());
        assert!(refuse_8cb778_180_as_hashchain_228().is_err());
        assert_eq!(BOSMINER_OUTER_BOX_SIZE, 0x180);
        assert_eq!(BOSMINER_OUTER_BOX_SIZE_INSN, 0x5280_3000);
        assert_eq!(BOSMINER_OUTER_BOX_ALLOC_BL_INSN, 0x97F4_A496);
        assert_eq!(BOSMINER_OUTER_BOX_MEMCPY_180_INSN, 0x5280_3002);
        assert_eq!(BOSMINER_OUTER_BOX_STR228_HITS, 0);
        assert_eq!(BOSMINER_OUTER_BOX_180_HITS, 4);
        assert_eq!(BOSMINER_OUTER_VT_VA, 0x019C_6B50);
        assert_eq!(BOSMINER_OUTER_VT_THUNK, 0x0084_CA74);
        assert_eq!(BOSMINER_OUTER_VT_ADD_INSN, 0x912D_4108);
        assert_eq!(BOSMINER_OUTER_VT_ADRP_HITS, 5);
        assert_eq!(BOSMINER_OUTER_BOX_FNS[3], 0x008C_BB2C);
        assert_eq!(BOSMINER_OUTER_BOX_CALLER_VA, 0x008C_E9DC);
        assert!(BOSMINER_OUTER_BOX_SIZE < 0x228);
        assert!(BOSMINER_OUTER_BOX_SIZE < 0x260);
    }

    #[test]
    fn wave75_ce99c_boxes_and_schedules_dest_is_box_38() {
        assert!(admit_bosminer_8ce99c_boxes_and_schedules().is_ok());
        assert!(admit_bosminer_8b9504_is_runqueue_insert().is_ok());
        assert!(admit_am3_init_dest_is_box_plus_38().is_ok());
        assert!(refuse_8ce99c_as_hashchain_228().is_err());
        assert_eq!(BOSMINER_BOX_SCHED_FN_VA, 0x008C_E99C);
        assert_eq!(BOSMINER_BOX_SCHED_TAG, 0xCC);
        assert_eq!(BOSMINER_BOX_SCHED_TAG_INSN, 0x5280_1982);
        assert_eq!(BOSMINER_BOX_SCHED_BL_INSN, 0x97FF_F367);
        assert_eq!(BOSMINER_BOX_SCHED_ADD160_INSN, 0x9105_82C0);
        assert_eq!(BOSMINER_BOX_SCHED_SPAWN_BL_INSN, 0x97FF_AAC5);
        assert_eq!(BOSMINER_RUNQ_STR18_INSN, 0xF900_0C29);
        assert_eq!(BOSMINER_BOXER_BL_HITS, 4);
        assert_eq!(BOSMINER_AM3_INIT_DEST_BOX_OFF, 0x38);
        assert_eq!(BOSMINER_AM3_INIT_DEST_REMAIN, 0x148);
        assert!(BOSMINER_AM3_INIT_DEST_REMAIN < 0x228);
        assert_eq!(BOSMINER_BOX_SCHED_STR228_HITS, 0);
        assert_eq!(BOSMINER_BOX_SCHED_PARENT_VA, 0x0085_19B8);
        assert_eq!(BOSMINER_BOX_SCHED_ADD200_INSN, 0x9108_02C0);
    }

    #[test]
    fn wave76_8518d0_assembles_108_image_not_hashchain() {
        assert!(admit_bosminer_8518d0_assembles_108_stack_image().is_ok());
        assert!(refuse_8518d0_param2_as_hashchain_pointer().is_err());
        assert!(admit_bosminer_8518d0_bit0_selects_alt_boxer().is_ok());
        assert!(refuse_8518d0_as_hashchain_228().is_err());
        assert_eq!(BOSMINER_PARENT_FN_VA, 0x0085_18D0);
        assert_eq!(BOSMINER_PARENT_ENTRY_INSN, 0xA9BE_7BFD);
        assert_eq!(BOSMINER_PARENT_LDRW0_INSN, 0xB940_0009);
        assert_eq!(BOSMINER_PARENT_IMAGE_ADD_INSN, 0x9106_83E1);
        assert_eq!(BOSMINER_PARENT_IMAGE_SP_OFF, 0x1A0);
        assert_eq!(BOSMINER_PARENT_IMAGE_SIZE, 0x108);
        assert_eq!(BOSMINER_PARENT_CE99C_BL_INSN, 0x9401_F3F9);
        assert_eq!(BOSMINER_PARENT_ALT_BL_INSN, 0x9401_1B48);
        assert_eq!(BOSMINER_PARENT_ALT_FN_VA, 0x0089_86C8);
        assert_eq!(BOSMINER_PARENT_STR228_HITS, 0);
        assert_eq!(BOSMINER_PARENT_BL_HITS, 1);
        assert_eq!(BOSMINER_PARENT_CALLER_VA, 0x0087_965C);
        assert_eq!(BOSMINER_ALT_BOX_FN_VA, 0x008C_C148);
        assert_eq!(BOSMINER_ALT_BOX_VT_VA, 0x019C_6D80);
        assert_eq!(BOSMINER_PARENT_P2_LDR50_INSN, 0xF940_2829);
    }

    #[test]
    fn wave77_8790dc_stages_108_from_am2_s17_msg_event() {
        assert!(admit_bosminer_8790dc_is_am2_s17_hashchain_msg_event().is_ok());
        assert!(admit_bosminer_8790dc_stages_108_at_sp_2cc0().is_ok());
        assert!(refuse_8790dc_2c70_as_hashchain_228_object().is_err());
        assert!(refuse_8790dc_as_hashchain_228().is_err());
        assert_eq!(BOSMINER_MSG_EVT_FN_VA, 0x0087_90DC);
        assert_eq!(BOSMINER_MSG_EVT_ENTRY_INSN, 0xA9BA_7BFD);
        assert_eq!(BOSMINER_MSG_EVT_P1_ADD_HI_INSN, 0x9140_13E0);
        assert_eq!(BOSMINER_MSG_EVT_P1_ADD_LO_INSN, 0x910E_0000);
        assert_eq!(BOSMINER_MSG_EVT_P2_ADD_HI_INSN, 0x9140_0BE1);
        assert_eq!(BOSMINER_MSG_EVT_P2_ADD_LO_INSN, 0x9133_0021);
        assert_eq!(BOSMINER_MSG_EVT_BL_INSN, 0x97FF_609D);
        assert_eq!(BOSMINER_MSG_EVT_SRC_OFF, 0x2C70);
        assert_eq!(BOSMINER_MSG_EVT_SRC_LDR_INSN, 0xF956_3A6A);
        assert_eq!(BOSMINER_MSG_EVT_SRC_CB8_INSN, 0xF956_5E69);
        assert_eq!(BOSMINER_MSG_EVT_STAGE_SP_OFF, 0x2CC0);
        assert_eq!(BOSMINER_MSG_EVT_P1_SP_OFF, 0x4380);
        assert_eq!(BOSMINER_MSG_EVT_STR228_HITS, 0);
        assert_eq!(BOSMINER_MSG_EVT_BL_HITS, 0);
        assert_eq!(BOSMINER_MSG_EVT_VT_VA, 0x019C_0F90);
        assert_eq!(BOSMINER_MSG_EVT_WORKER_BL_INSN, 0x9401_E449);
        assert_eq!(BOSMINER_MSG_EVT_STAGE_SP_OFF, 0x2000 + 0xCC0);
        assert_eq!(BOSMINER_MSG_EVT_P1_SP_OFF, 0x4000 + 0x380);
    }

    #[test]
    fn wave78_am3_add228_is_adrp_panic_loc_tag80() {
        assert!(admit_bosminer_am3_add228_is_panic_loc().is_ok());
        assert!(refuse_am3_add228_as_hashchain_field().is_err());
        assert!(admit_bosminer_am3_init_poll_tag_is_80().is_ok());
        assert_eq!(BOSMINER_AM3_ADD228_ADRP_HITS, 10);
        assert_eq!(BOSMINER_AM3_ADD228_ADRP_INSN, 0xD000_87A2);
        assert_eq!(BOSMINER_AM3_ADD228_LOC_VA, 0x019C_6228);
        assert_eq!(BOSMINER_AM3_ADD228_ADRP_VA, 0x008D_015C);
        assert_eq!(BOSMINER_AM3_INIT_TAG80_HITS, 5);
        assert_eq!(BOSMINER_AM3_INIT_TAG80_INSN, 0x3942_0008);
        assert_eq!(BOSMINER_AM3_INIT_TAG80_VA, 0x008C_FAEC);
        assert_eq!(BOSMINER_AM3_HC_INIT_ADD228_INSN, 0x9108_A042);
        assert_eq!(BOSMINER_AM3_HC_INIT_ADD228_PANIC_HITS, 10);
    }

    #[test]
    fn wave79_instantiate_x1_from_self_260_not_alloc() {
        assert!(admit_bosminer_instantiate_x1_is_slot_deref().is_ok());
        assert!(admit_bosminer_5c78c_loads_hc_from_plus_260().is_ok());
        assert!(refuse_42bb8_as_hashchain_allocator().is_err());
        assert!(refuse_682090_str228_as_hashchain().is_err());
        assert_eq!(BOSMINER_INST_X1_LDR_INSN, 0xF940_0341);
        assert_eq!(BOSMINER_INST_ARC_OFF, 0x2F0);
        assert_eq!(BOSMINER_INST_ARC_LDR_INSN, 0xF941_7909);
        assert_eq!(BOSMINER_WRAP42_FN_VA, 0x0084_2BB8);
        assert_eq!(BOSMINER_WRAP42_BL_INSN, 0x97FF_8A43);
        assert_eq!(BOSMINER_SRC5C_LDR260_INSN, 0xF941_32A9);
        assert_eq!(BOSMINER_SRC5C_BL_INSN, 0x97FF_983E);
        assert_eq!(BOSMINER_SRC5C_STR228_HITS, 0);
        assert_eq!(BOSMINER_INST_STR228_HITS, 0);
        assert_eq!(BOSMINER_FAC_X1_MOV_INSN, 0xAA13_03E1);
        assert_eq!(BOSMINER_VEC228_INSN, 0xF901_1677);
        assert_eq!(BOSMINER_VEC218_INSN, 0xF901_0E60);
        assert_eq!(BOSMINER_SRC5C_FN_VA, 0x0085_C78C);
        assert_eq!(BOSMINER_SRC5C_BL_VA, 0x0085_CAC0);
    }

    #[test]
    fn wave80_5c78c_self_is_300_box_from_parent_3b0() {
        assert!(admit_bosminer_5c78c_self_is_300().is_ok());
        assert!(admit_bosminer_705800_boxes_300_from_parent_3b0().is_ok());
        assert!(refuse_836c34_str260_as_hashchain().is_err());
        assert!(refuse_705800_as_hashchain_228_mint().is_err());
        assert_eq!(BOSMINER_SRC5C_VT_VA, 0x019A_CE88);
        assert_eq!(BOSMINER_SRC5C_VT_HDR_VA, 0x019A_CE70);
        assert_eq!(BOSMINER_SRC5C_DROP_FN_VA, 0x006F_4F2C);
        assert_eq!(BOSMINER_SRC5C_TYPE_SIZE, 0x300);
        assert_eq!(BOSMINER_SRC5C_TYPE_ALIGN, 0x10);
        assert_eq!(BOSMINER_SRC5C_VT_ADRP_VA, 0x0070_596C);
        assert_eq!(BOSMINER_SRC5C_VT_ADRP_INSN, 0xF000_9521);
        assert_eq!(BOSMINER_SRC5C_VT_ADD_INSN, 0x9139_C021);
        assert_eq!(BOSMINER_BOX300_FN_VA, 0x0070_5800);
        assert_eq!(BOSMINER_BOX300_ENTRY_INSN, 0xA9BA_7BFD);
        assert_eq!(BOSMINER_BOX300_SRC_LDR_VA, 0x0070_5890);
        assert_eq!(BOSMINER_BOX300_SRC_LDR_INSN, 0xF941_3298);
        assert_eq!(BOSMINER_BOX300_PARENT_OFF, 0x3B0);
        assert_eq!(BOSMINER_BOX300_PARENT_LDR_INSN, 0xF941_D814);
        assert_eq!(BOSMINER_BOX300_MOVZ_VA, 0x0070_58DC);
        assert_eq!(BOSMINER_BOX300_MOVZ_INSN, 0x5280_6000);
        assert_eq!(BOSMINER_BOX300_MEMCPY_SIZE_INSN, 0x5280_6002);
        assert_eq!(BOSMINER_BOX300_BL_HITS, 0);
        assert_eq!(BOSMINER_CLONE300_FN_VA, 0x0086_79AC);
        assert_eq!(BOSMINER_CLONE300_BL_VA, 0x0070_55C0);
        assert_eq!(BOSMINER_CLONE300_BL_INSN, 0x9405_88FB);
        assert_eq!(BOSMINER_CLONE300_BL_HITS, 1);
        assert_eq!(BOSMINER_STR260_HITS, 52);
        assert_eq!(BOSMINER_STR260_XZR_HITS, 8);
        assert_eq!(BOSMINER_STR260_CLONE_HITS, 9);
        assert_eq!(BOSMINER_STR260_MOVZ300_NEAR_HITS, 0);
        assert_eq!(BOSMINER_TICKET_MASK260_VA, 0x0083_6C34);
        assert_eq!(BOSMINER_TICKET_MASK260_INSN, 0xF901_3148);
        assert_eq!(BOSMINER_TICKET_MASK260_FN_VA, 0x0089_B720);
        assert_eq!(BOSMINER_TICKET_MASK260_ADRP_INSN, 0xB000_0328);
        assert_eq!(BOSMINER_TICKET_MASK260_ADD_INSN, 0x911C_8108);
    }

    #[test]
    fn wave81_705464_parent_3b0_is_src_not_hashchain() {
        assert!(admit_bosminer_705464_stores_src_at_3b0().is_ok());
        assert!(admit_bosminer_705464_copies_hc_to_2e0().is_ok());
        assert!(refuse_3b0_as_hashchain_pointer().is_err());
        assert!(refuse_705464_as_hashchain_228().is_err());
        assert_eq!(BOSMINER_PARENT3C0_FN_VA, 0x0070_5464);
        assert_eq!(BOSMINER_PARENT3C0_ENTRY_INSN, 0xA9BA_7BFD);
        assert_eq!(BOSMINER_PARENT3C0_MOV_SRC_INSN, 0xAA00_03F7);
        assert_eq!(BOSMINER_PARENT3C0_MOV_DST_INSN, 0xAA08_03F6);
        assert_eq!(BOSMINER_PARENT3C0_LDR260_INSN, 0xF941_32FB);
        assert_eq!(BOSMINER_PARENT3C0_STR2A0_INSN, 0xF901_52D7);
        assert_eq!(BOSMINER_PARENT3C0_STR2E0_INSN, 0xF901_72DB);
        assert_eq!(BOSMINER_PARENT3C0_STR3B0_VA, 0x0070_567C);
        assert_eq!(BOSMINER_PARENT3C0_STR3B0_INSN, 0xF901_DAD7);
        assert_eq!(BOSMINER_PARENT3C0_STR3B8_INSN, 0xF901_DED4);
        assert_eq!(BOSMINER_PARENT3C0_STR228_HITS, 0);
        assert_eq!(BOSMINER_PARENT3C0_BL_HITS, 3);
        assert_eq!(BOSMINER_PARENT3C0_TYPE_SIZE, 0x3C0);
        assert_eq!(BOSMINER_PARENT3C0_VT_VA, 0x019A_C9D8);
        assert_eq!(BOSMINER_STR3B0_HITS, 20);
    }

    #[test]
    fn wave82_705464_callers_load_elf_static_objs() {
        assert!(admit_bosminer_705464_callers_load_elf_statics().is_ok());
        assert!(admit_bosminer_call3c0_elf_objs_have_vptr().is_ok());
        assert!(refuse_call3c0_as_hashchain_260_mint().is_err());
        assert!(refuse_call3c0_vptr_as_hashchain_260().is_err());
        assert_eq!(BOSMINER_CALL3C0_A_FN_VA, 0x006F_23A8);
        assert_eq!(BOSMINER_CALL3C0_B_FN_VA, 0x006F_270C);
        assert_eq!(BOSMINER_CALL3C0_C_FN_VA, 0x006F_2C14);
        assert_eq!(BOSMINER_CALL3C0_MOV_DST_INSN, 0xAA08_03F3);
        assert_eq!(BOSMINER_CALL3C0_A_ADRP_INSN, 0x9000_9EE0);
        assert_eq!(BOSMINER_CALL3C0_A_LDR_INSN, 0xF947_6800);
        assert_eq!(BOSMINER_CALL3C0_A_BL_INSN, 0x9400_4BD7);
        assert_eq!(BOSMINER_CALL3C0_B_ADRP_INSN, 0xB000_9EE0);
        assert_eq!(BOSMINER_CALL3C0_B_LDR_INSN, 0xF946_9C00);
        assert_eq!(BOSMINER_CALL3C0_B_BL_INSN, 0x9400_4AFE);
        assert_eq!(BOSMINER_CALL3C0_C_ADRP_INSN, 0xF000_9EC0);
        assert_eq!(BOSMINER_CALL3C0_C_LDR_INSN, 0xF945_0400);
        assert_eq!(BOSMINER_CALL3C0_C_BL_INSN, 0x9400_49BC);
        assert_eq!(BOSMINER_CALL3C0_MOV_X8_INSN, 0xAA13_03E8);
        assert_eq!(BOSMINER_CALL3C0_MOVZ6_INSN, 0x5280_0026);
        assert_eq!(BOSMINER_CALL3C0_SLOT_A_VA, 0x01AC_EED0);
        assert_eq!(BOSMINER_CALL3C0_SLOT_B_VA, 0x01AC_FD38);
        assert_eq!(BOSMINER_CALL3C0_SLOT_C_VA, 0x01AC_DA08);
        assert_eq!(BOSMINER_CALL3C0_OBJ_A_VA, 0x01AE_01C0);
        assert_eq!(BOSMINER_CALL3C0_OBJ_B_VA, 0x01AD_FBC0);
        assert_eq!(BOSMINER_CALL3C0_OBJ_C_VA, 0x01AD_FEC0);
        assert_eq!(BOSMINER_CALL3C0_VPTR_A, 0x0086_33A0);
        assert_eq!(BOSMINER_CALL3C0_VPTR_B, 0x0086_2C84);
        assert_eq!(BOSMINER_CALL3C0_VPTR_C, 0x0086_26A8);
        assert_eq!(BOSMINER_CALL3C0_STR228_HITS, 0);
        assert_eq!(BOSMINER_CALL3C0_STR260_HITS, 0);
        assert_eq!(BOSMINER_CALL3C0_BL_HITS, 0);
        assert_eq!(BOSMINER_CALL3C0_VPTR_STR260_HITS, 0);
        assert_eq!(BOSMINER_CALL3C0_VPTR_BL_HITS, 0);
    }

    #[test]
    fn wave83_867740_simd_covers_static_260() {
        assert!(admit_bosminer_867740_inits_static_obj().is_ok());
        assert!(admit_bosminer_867740_simd_covers_260().is_ok());
        assert!(refuse_867740_strx_260().is_err());
        assert!(refuse_867740_strh228_as_hashchain_tag().is_err());
        assert_eq!(BOSMINER_INIT677_FN_VA, 0x0086_7740);
        assert_eq!(BOSMINER_INIT677_ENTRY_INSN, 0xD102_43FF);
        assert_eq!(BOSMINER_INIT677_MOV_DST_INSN, 0xAA08_03F3);
        assert_eq!(BOSMINER_INIT677_STRH228_VA, 0x0086_78DC);
        assert_eq!(BOSMINER_INIT677_STRH228_INSN, 0x7904_5268);
        assert_eq!(BOSMINER_INIT677_STR2E0_INSN, 0xF901_726B);
        assert_eq!(BOSMINER_INIT677_SIMD260_VA, 0x0086_7914);
        assert_eq!(BOSMINER_INIT677_SIMD260_INSN, 0xAD12_8660);
        assert_eq!(BOSMINER_INIT677_LDP_SRC_INSN, 0xAD40_0520);
        assert_eq!(BOSMINER_INIT677_STR260_HITS, 0);
        assert_eq!(BOSMINER_INIT677_BL_HITS, 3);
        assert_eq!(BOSMINER_INIT677_BL_A_INSN, 0x9400_0FF0);
        assert_eq!(BOSMINER_INIT677_BL_B_INSN, 0x9400_11BD);
        assert_eq!(BOSMINER_INIT677_BL_C_INSN, 0x9400_1334);
    }

    #[test]
    fn wave84_x9_is_local120_260_from_adfb28_plus10() {
        assert!(admit_bosminer_x9_is_local120().is_ok());
        assert!(admit_bosminer_260_from_adfb28_plus_10().is_ok());
        assert!(refuse_adfb28_plus10_as_hashchain().is_err());
        assert!(refuse_beee00_as_static_260_source().is_err());
        assert_eq!(BOSMINER_X9_LDR_SP_B8_VA, 0x0086_78C0);
        assert_eq!(BOSMINER_X9_LDR_SP_B8_INSN, 0xF940_5FE9);
        assert_eq!(BOSMINER_X9_CALLER_ADD170_INSN, 0x9105_C3E8);
        assert_eq!(BOSMINER_X9_CALLER_ADD160_INSN, 0x9105_83E9);
        assert_eq!(BOSMINER_X9_CALLER_STP20_INSN, 0xA902_23E9);
        assert_eq!(BOSMINER_X9_SLOT_VA, 0x01AC_DF20);
        assert_eq!(BOSMINER_X9_SLOT_LDR_INSN, 0xF947_92B5);
        assert_eq!(BOSMINER_X9_SLOT_ADRP_INSN, 0xD000_9355);
        assert_eq!(BOSMINER_X9_OBJ_VA, 0x01AD_FB28);
        assert_eq!(BOSMINER_X9_OBJ_VPTR, 0x0086_31F0);
        assert_eq!(BOSMINER_X9_OBJ_LDR10_INSN, 0xF940_0AA9);
        assert_eq!(BOSMINER_X9_LOCAL110_STR_INSN, 0xF900_C3E9);
        assert_eq!(BOSMINER_X9_SLOT_LDR_HITS, 3);
    }

    #[test]
    fn wave85_no_later_overwrite_1ae0420() {
        assert!(admit_bosminer_true_slot_loads_are_six().is_ok());
        assert!(admit_bosminer_633a0_returns_after_67740().is_ok());
        assert!(refuse_later_overwrite_1ae0420().is_err());
        assert!(refuse_a25760_as_slot_a().is_err());
        assert_eq!(BOSMINER_OW260_ABS_STR_HITS, 0);
        assert_eq!(BOSMINER_OW260_SLOT_STR_HITS, 0);
        assert_eq!(BOSMINER_TRUE_SLOT_LDR_HITS, 6);
        assert_eq!(BOSMINER_TRUE_SLOT_A_ONCE_VA, 0x006F_2434);
        assert_eq!(BOSMINER_TRUE_SLOT_A_ONCE_INSN, 0xF947_6AB5);
        assert_eq!(BOSMINER_INIT633_POST_BL_ADD_INSN, 0x9108_83FF);
        assert_eq!(BOSMINER_INIT633_RET_VA, 0x0086_37A4);
        assert_eq!(BOSMINER_INIT633_RET_INSN, 0xD65F_03C0);
        assert_eq!(BOSMINER_FAKE_SLOT_A25760_VA, 0x01AC_DED0);
        assert_eq!(BOSMINER_FAKE_SLOT_A25760_ADRP_INSN, 0x9000_854A);
    }

    #[test]
    fn wave86_8631f0_is_psu_sret_not_hashchain() {
        assert!(admit_bosminer_8631f0_is_x8_sret_default().is_ok());
        assert!(admit_bosminer_adfb28_size_is_98().is_ok());
        assert!(refuse_8631f0_as_hashchain_ctor().is_err());
        assert!(refuse_adfb28_plus228_as_hashchain_field().is_err());
        assert_eq!(BOSMINER_INIT631_FN_VA, 0x0086_31F0);
        assert_eq!(BOSMINER_INIT631_RET_VA, 0x0086_325C);
        assert_eq!(BOSMINER_INIT631_ENTRY_INSN, 0xB000_5429);
        assert_eq!(BOSMINER_INIT631_MOVZ2_INSN, 0x5280_004A);
        assert_eq!(BOSMINER_INIT631_MOVZ1_INSN, 0x5280_002A);
        assert_eq!(BOSMINER_INIT631_STR88_VA, 0x0086_3228);
        assert_eq!(BOSMINER_INIT631_STR88_INSN, 0xB900_891F);
        assert_eq!(BOSMINER_INIT631_STR10_VA, 0x0086_3244);
        assert_eq!(BOSMINER_INIT631_STR10_INSN, 0xF900_090A);
        assert_eq!(BOSMINER_INIT631_RET_INSN, 0xD65F_03C0);
        assert_eq!(BOSMINER_INIT631_BL_HITS, 0);
        assert_eq!(BOSMINER_INIT631_MAX_STR_OFF, 0x88);
        assert_eq!(BOSMINER_SIBLING_SIZE, 0x98);
        assert_eq!(BOSMINER_SIBLING_NEXT_VA, 0x01AD_FBC0);
        assert_eq!(BOSMINER_SIBLING_228_VA, 0x01AD_FD50);
        assert_eq!(BOSMINER_SIBLING_228_XREF_HITS, 0);
        assert_eq!(BOSMINER_INIT631_BL_CALLERS, 0);
        assert_eq!(BOSMINER_PSU_F64_0_VA, 0x012E_80F0);
        assert_eq!(BOSMINER_PSU_F64_0_BITS, 0x3FB9_9999_9999_999A);
        assert_eq!(BOSMINER_SIBLING_SIMD_LDR_VA, 0x0086_36C4);
        assert_eq!(BOSMINER_SIBLING_SIMD_LDR_INSN, 0x3DC0_02A0);
    }

    #[test]
    fn wave87_uart_version_width_is_midstate_log() {
        assert!(admit_bosminer_bf2478_is_midstate_log_helper().is_ok());
        assert!(admit_bosminer_uart_version_width_is_midstate_log().is_ok());
        assert!(refuse_bip320_16_as_bosminer_uart_version_width().is_err());
        assert!(refuse_bf2478_as_bip320_mask().is_err());
        assert_eq!(BOSMINER_VERWIDTH_FN_VA, 0x00BF_2478);
        assert_eq!(BOSMINER_VERWIDTH_LDRB20_INSN, 0x3940_8008);
        assert_eq!(BOSMINER_VERWIDTH_LDR18_INSN, 0xF940_0C00);
        assert_eq!(BOSMINER_VERWIDTH_B_LOG_INSN, 0x1419_B603);
        assert_eq!(BOSMINER_VERWIDTH_LDR10_INSN, 0xF940_0800);
        assert_eq!(BOSMINER_VERWIDTH_RET_INSN, 0xD65F_03C0);
        assert_eq!(BOSMINER_VERWIDTH_TAG_OFF, 0x20);
        assert_eq!(BOSMINER_ENGINE_MIDSTATE_COUNT_OFF, 0x78);
        assert_eq!(s19k_braiins_uart_version_mask_from_log(0).unwrap(), 0);
        assert_eq!(s19k_braiins_uart_version_mask_from_log(1).unwrap(), 1);
        assert_eq!(s19k_braiins_uart_version_mask_from_log(2).unwrap(), 3);
        assert_eq!(s19k_braiins_uart_version_mask_from_log(3).unwrap(), 7);
        assert_eq!(s19k_braiins_uart_version_bits(0xFFFF, 0).unwrap(), 0);
        assert_eq!(s19k_braiins_uart_version_bits(0xFFFF, 3).unwrap(), 7);
        assert_eq!(
            s19k_braiins_uart_version_from_payload8(0xBEEF_0000_0000_0000),
            0xEFBE
        );
    }

    #[test]
    fn wave88_no_later_bip320_reexpand() {
        assert!(admit_bosminer_five_uart_parse_callers().is_ok());
        assert!(admit_bosminer_bf6c2c_is_registry_submit().is_ok());
        assert!(refuse_bf6c2c_as_bip320_reexpand().is_err());
        assert!(refuse_uart_wrappers_as_bip320_reexpand().is_err());
        assert_eq!(BOSMINER_RESP_CONSUMER_FN_VA, 0x00BF_6C2C);
        assert_eq!(BOSMINER_RESP_CONSUMER_ENTRY_INSN, 0xA9BA_7BFD);
        assert_eq!(BOSMINER_RESP_CONSUMER_MOV_X26_INSN, 0xAA01_03FA);
        assert_eq!(BOSMINER_RESP_CONSUMER_LDR68_INSN, 0xF940_3409);
        assert_eq!(BOSMINER_RESP_CONSUMER_MOVZ78_VA, 0x00BF_6FA0);
        assert_eq!(BOSMINER_RESP_CONSUMER_MOVZ78_INSN, 0x5280_0F08);
        assert_eq!(BOSMINER_UART_WRAP_HITS, 5);
        assert_eq!(BOSMINER_UART_WRAP_SIZE, 0x101C);
        assert_eq!(BOSMINER_UART_WRAP_A_FN_VA, 0x008F_262C);
        assert_eq!(BOSMINER_UART_WRAP_B_FN_VA, 0x008F_36F8);
        assert_eq!(BOSMINER_UART_WRAP_C_FN_VA, 0x008F_47C4);
        assert_eq!(BOSMINER_UART_WRAP_D_FN_VA, 0x008F_5890);
        assert_eq!(BOSMINER_UART_WRAP_E_FN_VA, 0x008F_695C);
        assert_eq!(BOSMINER_UART_PARSE_BL_OFF, 0x3C4);
        assert_eq!(BOSMINER_UART_PARSE_BL_A_INSN, 0x9400_A5AC);
        assert_eq!(BOSMINER_UART_OK_LDR_INSN, 0xB941_A3E8);
        assert_eq!(BOSMINER_UART_OK_TBZ_INSN, 0x3600_1088);
        assert_eq!(BOSMINER_UART_CONS_BL_OFF, 0x5FC);
        assert_eq!(BOSMINER_UART_CONS_BL_A_INSN, 0x940C_1001);
        assert_eq!(BOSMINER_UART_CONS_MOVZ11D0_INSN, 0x5282_3A08);
        assert_eq!(BOSMINER_UART_CONS_ADD_X0_INSN, 0x8B08_0260);
        assert_eq!(BOSMINER_UART_WRAP_LSL13_HITS, 0);
        assert_eq!(BOSMINER_BF6C_LSL13_HITS, 0);
        assert_eq!(BOSMINER_BIP320_MOVP_HITS, 0);
        assert_eq!(BOSMINER_FPGA_RESP_CONSUMER_BL_VA, 0x008A_FA8C);
        assert_eq!(s19k_braiins_uart_version_bits(0xABCD, 0).unwrap(), 0);
    }

    #[test]
    fn wave90_strb228_census_and_engine_abs_log() {
        assert!(admit_bosminer_strb228_census_is_24().is_ok());
        assert!(admit_bosminer_strb228_7c_is_three().is_ok());
        assert!(admit_bosminer_bf26d0_is_engine_abs_log().is_ok());
        assert!(refuse_strb228_7c_as_hashchain_tag().is_err());
        assert!(refuse_c906e8_as_hashchain_228().is_err());
        assert!(refuse_worker_new_as_engine_88_mint().is_err());
        assert_eq!(BOSMINER_STRB228_NONSP_HITS, 24);
        assert_eq!(BOSMINER_STRB228_WZR_HITS, 16);
        assert_eq!(BOSMINER_STRB228_WZR_INSN, 0x3908_A27F);
        assert_eq!(BOSMINER_STRB228_7C_HITS, 3);
        assert_eq!(BOSMINER_STRB228_7C_VA, 0x005F_5A20);
        assert_eq!(BOSMINER_STRB228_7C_MOVZ_INSN, 0x5280_0F88);
        assert_eq!(BOSMINER_STRB228_7C_STRB_INSN, 0x3908_A268);
        assert_eq!(BOSMINER_STRB228_C906_VA, 0x00C9_07D0);
        assert_eq!(BOSMINER_STRB228_C906_INSN, 0x3908_A288);
        assert_eq!(BOSMINER_STRB228_CD67_VA, 0x00CD_6798);
        assert_eq!(BOSMINER_LOG_ABS_FN_VA, 0x00BF_26D0);
        assert_eq!(BOSMINER_LOG_ABS_LDRB80_INSN, 0x3942_0008);
        assert_eq!(BOSMINER_LOG_ABS_LDR78_INSN, 0xF940_3C00);
        assert_eq!(BOSMINER_LOG_ABS_B_INSN, 0x1419_B56D);
        assert_eq!(BOSMINER_LOG_ABS_LDR70_INSN, 0xF940_3800);
        assert_eq!(BOSMINER_WORKER_NEW_STR88_HITS, 0);
        assert_eq!(BOSMINER_FACTORY_STR88_HITS, 0);
    }

    #[test]
    fn wave91_abs_log_callers_and_one_shr_constant() {
        assert!(admit_bosminer_bf26d0_has_seven_bl_callers().is_ok());
        assert!(admit_bosminer_workers_pass_abs_log_to_registry().is_ok());
        assert!(admit_bosminer_fpga_factory_calls_abs_log().is_ok());
        assert!(admit_bosminer_b2639c_is_one_shr_log().is_ok());
        assert!(refuse_one_shr_log_as_uart_registry_size().is_err());
        assert_eq!(BOSMINER_LOG_ABS_BL_CALLERS, 7);
        assert_eq!(BOSMINER_LOG_REL_BL_CALLERS, 1);
        assert_eq!(BOSMINER_LOG_ABS_WORKER_BL_HITS, 5);
        assert_eq!(BOSMINER_LOG_ABS_FPGA_BL_VA, 0x008A_EA7C);
        assert_eq!(BOSMINER_LOG_ABS_FPGA_BL_INSN, 0x940D_0F15);
        assert_eq!(BOSMINER_LOG_ABS_FPGA_MOV_X0_INSN, 0xAA01_03E0);
        assert_eq!(BOSMINER_FPGA_LOG_VALIDATE_FN_VA, 0x0092_F240);
        assert_eq!(BOSMINER_FPGA_LOG_VALIDATE_BL_INSN, 0x9402_01EB);
        assert_eq!(BOSMINER_LOG_ABS_WORKER_A_BL_INSN, 0x940B_C734);
        assert_eq!(BOSMINER_LOG_ABS_WORKER_NEW_BL_INSN, 0x940B_BC27);
        assert_eq!(BOSMINER_LOG_ABS_WORKER_MOV_X0_INSN, 0xAA18_03E0);
        assert_eq!(BOSMINER_LOG_ABS_WORKER_NEW_MOV_X0_INSN, 0xAA19_03E0);
        assert_eq!(BOSMINER_LOG_ABS_WORKER_MOV_X3_INSN, 0xAA00_03E3);
        assert_eq!(BOSMINER_LOG_ABS_WORKER_NEW_REG_BL_INSN, 0x940B_D047);
        assert_eq!(BOSMINER_LOG_ABS_ONESHR_BL_VA, 0x00B2_639C);
        assert_eq!(BOSMINER_LOG_ABS_ONESHR_BL_INSN, 0x9403_30CD);
        assert_eq!(BOSMINER_ONESHR_FN_VA, 0x00B2_6398);
        assert_eq!(BOSMINER_ONESHR_PROLOGUE_INSN, 0xF81F_0FFE);
        assert_eq!(BOSMINER_ONESHR_EPILOGUE_INSN, 0xF841_07FE);
        assert_eq!(BOSMINER_ONESHR_MOVZ_INSN, 0x5280_0028);
        assert_eq!(BOSMINER_ONESHR_LSRV_INSN, 0x9AC0_2100);
        assert_eq!(BOSMINER_ONESHR_RET_INSN, 0xD65F_03C0);
        assert_eq!(BOSMINER_ONESHR_BL_CALLERS, 9);
        assert_eq!(BOSMINER_ONESHR_CALLER_A_VA, 0x0047_C294);
        assert_eq!(BOSMINER_ONESHR_CALLER_A_INSN, 0x941A_A841);
        assert_eq!(BOSMINER_LOG_REL_PARSE_BL_VA, 0x0091_C104);
        assert_eq!(BOSMINER_LOG_REL_PARSE_BL_INSN, 0x940B_58DD);
        assert_eq!(s19k_braiins_one_shr_log(0).unwrap(), 1);
        assert_eq!(s19k_braiins_one_shr_log(1).unwrap(), 0);
        assert_eq!(s19k_braiins_one_shr_log(3).unwrap(), 0);
        assert_eq!(s19k_braiins_uart_registry_size_from_log(0).unwrap(), 0x100);
        assert_ne!(
            s19k_braiins_one_shr_log(0).unwrap(),
            u64::from(s19k_braiins_uart_registry_size_from_log(0).unwrap())
        );
        for (i, &site) in BOSMINER_LOG_ABS_WORKER_BL_VAS.iter().enumerate() {
            let ctor = BOSMINER_AM3_WORKER_CTOR_VAS[i];
            assert!(site > ctor && site < ctor + 0x400, "{site:#x} vs {ctor:#x}");
        }
    }

    #[test]
    fn wave92_oneshr_six_store_three_discard() {
        assert!(admit_bosminer_oneshr_six_store_three_discard().is_ok());
        assert!(refuse_oneshr_flag2_toggle_as_one_shr_result().is_err());
        assert!(s19k_braiins_oneshr_is_fill_log(0).unwrap());
        assert!(!s19k_braiins_oneshr_is_fill_log(1).unwrap());
        assert!(!s19k_braiins_oneshr_is_fill_log(3).unwrap());
        assert_eq!(BOSMINER_ONESHR_STACK_STORE_HITS, 6);
        assert_eq!(BOSMINER_ONESHR_DISCARD_HITS, 3);
        assert_eq!(BOSMINER_ONESHR_STR_3280_INSN, 0xF919_43E0);
        assert_eq!(BOSMINER_ONESHR_STR_2A70_INSN, 0xF915_3BE0);
        assert_eq!(BOSMINER_ONESHR_STR_3280_OFF, 0x3280);
        assert_eq!(BOSMINER_ONESHR_STR_2A70_OFF, 0x2A70);
        assert_eq!(BOSMINER_ONESHR_STR_3280_VA, 0x0047_C29C);
        assert_eq!(BOSMINER_ONESHR_STR_2A70_VA, 0x0047_C454);
        assert_eq!(BOSMINER_ONESHR_DISCARD_SIMD_INSN, 0x3DC7_4BE0);
        assert_eq!(BOSMINER_ONESHR_SIB_FN_VA, 0x00B2_63F4);
        assert_eq!(BOSMINER_ONESHR_SIB_ADD400_INSN, 0x9110_0001);
        assert_eq!(BOSMINER_ONESHR_SIB_BL_HITS, 3);
        assert_eq!(BOSMINER_ONESHR_FLAG2_SET_INSN, 0x3900_0AC8);
        assert_eq!(BOSMINER_ONESHR_FLAG2_CLR_INSN, 0x3900_0ADF);
        assert_eq!(BOSMINER_ONESHR_PRE_ADD_A_INSN, 0x8B14_0320);
    }

    #[test]
    fn wave93_layouts_and_oneshr_stack_not_live() {
        assert!(admit_s19k_bosminer_layouts().is_ok());
        assert!(refuse_3280_oneshr_str_as_live_consumer().is_err());
        assert!(refuse_2a70_ldxr_as_oneshr_consumer().is_err());
        assert_eq!(S19K_BOSMINER_JOB.size, 0x80);
        assert_eq!(S19K_BOSMINER_ENGINE.nonce_fn, 0x88);
        assert_eq!(S19K_BOSMINER_FILL.prefix, 0x50);
        assert_eq!(S19K_BOSMINER_HASHCHAIN.div, 0x11F0);
        assert_eq!(BOSMINER_ONESHR_3280_MID_LDST, 0);
        assert_eq!(BOSMINER_ONESHR_3280_OVERWRITE_VA, 0x0047_C68C);
        assert_eq!(BOSMINER_ONESHR_3280_OVERWRITE_INSN, 0xF919_43E8);
        assert_eq!(BOSMINER_ONESHR_2A70_LDR_VA, 0x0047_DE88);
        assert_eq!(BOSMINER_ONESHR_2A70_LDR_INSN, 0xF955_3BE8);
        assert_eq!(BOSMINER_ONESHR_2A70_LDXR_INSN, 0xC85F_7D09);
        assert_eq!(BOSMINER_ONESHR_2A70_RET_BETWEEN, 1);
    }

    #[test]
    fn wave105_oneshr_callers_do_not_consume_x0() {
        assert!(admit_bosminer_oneshr_no_x0_cond_branch().is_ok());
        assert!(refuse_3280_ldr_as_oneshr_consumer().is_err());
        assert!(refuse_2a70_early_ldr_as_oneshr_consumer().is_err());
        assert_eq!(BOSMINER_ONESHR_CALLER_VAS.len(), 9);
        assert_eq!(BOSMINER_ONESHR_CALLER_VAS[0], 0x0047_C294);
        assert_eq!(BOSMINER_ONESHR_CALLER_VAS[8], 0x004F_A4D8);
        assert_eq!(BOSMINER_ONESHR_X0_COND_HITS, 0);
        assert_eq!(BOSMINER_ONESHR_3280_LDR_HITS, 3);
        assert_eq!(BOSMINER_ONESHR_3280_LDR_VA, 0x0047_C76C);
        assert_eq!(BOSMINER_ONESHR_3280_LDR_INSN, 0xF959_43E0);
        assert_eq!(BOSMINER_ONESHR_3280_LDR_NEXT_INSN, 0xF959_63E1);
        assert!(BOSMINER_ONESHR_3280_LDR_VA > BOSMINER_ONESHR_3280_OVERWRITE_VA);
        assert_eq!(BOSMINER_ONESHR_2A70_LDR_HITS, 6);
        assert_eq!(BOSMINER_ONESHR_2A70_EARLY_LDR_VA, 0x0047_B8DC);
        assert_eq!(BOSMINER_ONESHR_2A70_EARLY_LDR_INSN, 0xF955_3BE6);
        assert!(BOSMINER_ONESHR_2A70_EARLY_LDR_VA < BOSMINER_ONESHR_STR_2A70_VA);
    }

    #[test]
    fn wave109_bm1366_callback_is_attribution_raw_nonce_is_separate() {
        assert!(admit_bosminer_work_resp_rev_then_nonce_fn().is_ok());
        assert!(admit_bosminer_work_resp_blr_return_is_nonce().is_err());
        assert!(refuse_plus80_ne1_as_alt_nonce_transform().is_err());
        assert!(refuse_ret_only_as_named_plus88().is_err());
        assert!(admit_bosminer_1366_factory_is_876ca8().is_ok());
        assert!(admit_bosminer_clone_copies_plus88_qword().is_ok());
        assert!(refuse_work_resp_low8_div_as_pool_nonce().is_err());
        assert_eq!(BOSMINER_WORK_RESP_SAVE_X0_INSN, 0xAA00_03F6);
        assert_eq!(BOSMINER_WORK_RESP_STORE_RAW_NONCE_INSN, 0xB900_3278);
        assert_eq!(BOSMINER_WORK_RESP_MOV_X1_NONCE_INSN, 0xAA16_03E1);
        assert_eq!(BOSMINER_WORK_RESP_PLUS80_LDRB_INSN, 0x3942_02A8);
        assert_eq!(BOSMINER_RET_ONLY_SITES, 269);
        assert_eq!(BOSMINER_WORK_RESP_LDR88_INSN, 0xF940_4428);
        assert_eq!(BOSMINER_WORK_RESP_BLR_INSN, 0xD63F_0100);
        let mut prod = vec![
            0u8;
            (BOSMINER_ENGINE88_MOVZ4_VA[5]
                + BOSMINER_ENGINE88_MOVZ_TO_STR80
                + BOSMINER_ENGINE88_STR80_TO_STR88
                - 0x400_000
                + 4) as usize
        ];
        let put = |buf: &mut [u8], va: u64, insn: u32| {
            let o = (va - 0x400_000) as usize;
            buf[o..o + 4].copy_from_slice(&insn.to_le_bytes());
        };
        for &va in &BOSMINER_ENGINE88_MOVZ4_VA {
            put(&mut prod, va, BOSMINER_ENGINE88_MOVZ4_INSN);
            put(
                &mut prod,
                va + BOSMINER_ENGINE88_MOVZ_TO_STR80,
                BOSMINER_ENGINE88_STR80_INSN,
            );
            put(
                &mut prod,
                va + BOSMINER_ENGINE88_MOVZ_TO_STR80 + BOSMINER_ENGINE88_STR80_TO_STR88,
                BOSMINER_ENGINE88_STR88_INSN,
            );
        }
        put(
            &mut prod,
            BOSMINER_ENGINE88_PRODUCER_LDRB_VA,
            BOSMINER_ENGINE88_PRODUCER_LDRB_INSN,
        );
        assert!(admit_bosminer_engine88_producer_family(&prod).is_ok());
        assert!(refuse_engine88_type4_result_as_fill_identity().is_err());
        assert_eq!(BOSMINER_ENGINE88_PRODUCER_HITS, 6);
        assert_eq!(BOSMINER_ENGINE88_WORK_TYPE, 4);
        assert_ne!(
            BOSMINER_ENGINE88_WORK_TYPE,
            u32::from(BOSMINER_WORK_TYPE_VERSION_ROLLING)
        );
        assert_eq!(BOSMINER_ENGINE88_MOVZ4_VA[5], 0x008D_C920);
        assert!(admit_bosminer_fill_type1_plus88_coinstall_absent(0).is_ok());
        assert!(admit_bosminer_fill_type1_plus88_coinstall_absent(1).is_err());
        assert!(refuse_fill_type1_static_plus88_installer().is_err());
        assert_eq!(BOSMINER_FILL_TYPE1_COINSTALLED_88_HITS, 0);
        assert_eq!(BOSMINER_FILL_TYPE1_WIDE_STRB80_STR88_HITS, 0);
        assert_eq!(BOSMINER_BM1366_FACTORY_STR88_IN_FIRST_800, 0);
        let mut clone_blob = vec![0u8; (BOSMINER_FACTORY_CLONE_BL_VA[4] - 0x400_000 + 4) as usize];
        let putc = |buf: &mut [u8], va: u64, insn: u32| {
            let o = (va - 0x400_000) as usize;
            buf[o..o + 4].copy_from_slice(&insn.to_le_bytes());
        };
        putc(
            &mut clone_blob,
            BOSMINER_CLONE_DEST_MOV_VA,
            BOSMINER_CLONE_DEST_MOV_INSN,
        );
        putc(
            &mut clone_blob,
            BOSMINER_CLONE_SRC_MOV_VA,
            BOSMINER_CLONE_SRC_MOV_INSN,
        );
        putc(
            &mut clone_blob,
            BOSMINER_CLONE_LDUR_Q88_VA,
            BOSMINER_CLONE_LDUR_Q88_INSN,
        );
        putc(
            &mut clone_blob,
            BOSMINER_CLONE_STUR_Q88_VA,
            BOSMINER_CLONE_STUR_Q88_INSN,
        );
        for i in 0..BOSMINER_FACTORY_CLONE_BL_HITS {
            let bl_va = BOSMINER_FACTORY_CLONE_BL_VA[i];
            putc(&mut clone_blob, bl_va, BOSMINER_FACTORY_CLONE_BL_INSN[i]);
            putc(
                &mut clone_blob,
                bl_va - BOSMINER_FACTORY_X1_SAVE_TO_CLONE_BL,
                BOSMINER_FACTORY_X1_SAVE_INSN_CLONE,
            );
        }
        assert!(admit_bosminer_factory_clone_bl_family(&clone_blob).is_ok());
        assert!(refuse_clone_q88_as_named_text_identity().is_err());
        assert_eq!(BOSMINER_FACTORY_CLONE_BL_HITS, 5);
        assert_eq!(BOSMINER_FACTORY_CLONE_BL_STRIDE, 0x588);
        assert_eq!(BOSMINER_FACTORY_CLONE_BL_VA[1], 0x0087_6D24);
        assert_eq!(BOSMINER_BM1366_FACTORY_FN_VA, 0x0087_6CA8);
        let mut prep_blob = vec![
            0u8;
            (BOSMINER_HASHMAP_STR88_VA[10]
                .max(BOSMINER_AM3_STR88_VA[9])
                .max(BOSMINER_WRAP_CLONE_BL_VA)
                .max(BOSMINER_PROD_CALL_X1_MOV_VA)
                .max(BOSMINER_RUSTC_HEAP_THUNK1_BODY_VA)
                .max(BOSMINER_RUSTC_HEAP_THUNK2_B_VA)
                .max(BOSMINER_DURATION_NEW_STR10_VA)
                .max(BOSMINER_POLL_ERR_PACK_B_VA)
                .max(BOSMINER_POLL_SUSPEND_RET_VA)
                .max(BOSMINER_FAT_SLOT30_OTHER_LDR30_VA)
                - 0x400_000
                + 4) as usize
        ];
        let putp = |buf: &mut [u8], va: u64, insn: u32| {
            let o = (va - 0x400_000) as usize;
            buf[o..o + 4].copy_from_slice(&insn.to_le_bytes());
        };
        putp(
            &mut prep_blob,
            BOSMINER_PREP_X20_MOV_VA,
            BOSMINER_PREP_X20_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PREP_Q88_LDUR_VA,
            BOSMINER_PREP_Q88_LDUR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PREP_Q88_DEST_ADD_VA,
            BOSMINER_PREP_Q88_DEST_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PREP_Q88_STUR_VA,
            BOSMINER_PREP_Q88_STUR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_GET_X19_FROM_X2_VA,
            BOSMINER_GET_X19_FROM_X2_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_GET_PREP_X1_VA,
            BOSMINER_GET_PREP_X1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_PREP_BL_VA,
            BOSMINER_FACTORY_PREP_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_CONSTRUCT_X0_ADD_VA,
            BOSMINER_PROD_CONSTRUCT_X0_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_CALL_X2_ADD_VA,
            BOSMINER_PROD_CALL_X2_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_CALL_X1_MOV_VA,
            BOSMINER_PROD_CALL_X1_MOV_INSN,
        );
        assert!(admit_bosminer_prep_q88_from_x1(&prep_blob).is_ok());
        assert!(admit_bosminer_get_caller_x2_is_prep_source(&prep_blob).is_ok());
        assert!(admit_bosminer_prod_two_templates(&prep_blob).is_ok());
        assert!(refuse_prep_x2_as_factory_x1().is_err());
        assert!(refuse_prep_q88_dest_as_factory_dest().is_err());
        assert_eq!(BOSMINER_PREP_Q88_STUR_INSN, 0x3C88_8165);
        assert_eq!(BOSMINER_PREP_Q88_DEST_ADD_INSN, 0x9108_C3EB);
        assert_eq!(BOSMINER_PREP_Q88_STACK_BASE, 0x230);
        assert_eq!(BOSMINER_PREP_TEMPLATE_STACK_OFF, 0x2E0);
        assert_eq!(BOSMINER_GET_PREP_X1_INSN, BOSMINER_PREP_SRC_MOV_INSN);
        assert_eq!(
            BOSMINER_PROD_CALL_X1_MOV_INSN,
            BOSMINER_FACTORY_X1_FROM_X24_INSN
        );
        assert_ne!(BOSMINER_PREP_Q88_STUR_INSN, BOSMINER_CLONE_STUR_Q88_INSN);
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_CLONE_DEST_MOV_VA,
            BOSMINER_WRAP_CLONE_DEST_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_CLONE_SRC_MOV_VA,
            BOSMINER_WRAP_CLONE_SRC_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_CLONE_BL_VA,
            BOSMINER_WRAP_CLONE_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_CTX_MOV_VA,
            BOSMINER_FACTORY_CTX_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_WRAP_SRC_MOV_VA,
            BOSMINER_PROD_WRAP_SRC_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_WRAP_BL_VA,
            BOSMINER_PROD_WRAP_BL_INSN,
        );
        assert!(admit_bosminer_87fb4c_wraps_clone(&prep_blob).is_ok());
        assert!(admit_bosminer_prod_prep_source_is_x22_clone(&prep_blob).is_ok());
        assert!(refuse_prod_sp2e0_as_factory_x24_clone().is_err());
        assert_eq!(BOSMINER_WRAP_CLONE_BL_INSN, 0x97FF_D8F5);
        assert_eq!(BOSMINER_PROD_WRAP_SRC_MOV_INSN, 0xAA16_03E1);
        assert_eq!(BOSMINER_PROD_WRAP_BL_INSN, 0x9400_066D);
        assert_eq!(BOSMINER_SP1640_CLONE_FN_VA, 0x0087_FB4C);
        assert_ne!(
            BOSMINER_PROD_WRAP_SRC_MOV_INSN,
            BOSMINER_FACTORY_X1_FROM_X24_INSN
        );
        let mut vt = vec![0u8; (BOSMINER_E02C_VTABLE_FILE_OFF[1] + 8) as usize];
        let putq = |buf: &mut [u8], off: u64, val: u64| {
            let o = off as usize;
            buf[o..o + 8].copy_from_slice(&val.to_le_bytes());
        };
        for &off in &BOSMINER_E02C_VTABLE_FILE_OFF {
            putq(&mut vt, off, BOSMINER_PROD_FN_VA);
            putq(
                &mut vt,
                off - BOSMINER_E02C_SIZE_BEFORE_SLOT,
                BOSMINER_E02C_TYPE_SIZE as u64,
            );
            putq(
                &mut vt,
                off - BOSMINER_E02C_SIZE_BEFORE_SLOT + 8,
                BOSMINER_E02C_TYPE_ALIGN as u64,
            );
        }
        assert!(admit_bosminer_e02c_is_0x2a0_vtable_method(&vt).is_ok());
        assert!(refuse_e02c_vtable_as_named_plus88().is_err());
        assert_eq!(BOSMINER_E02C_VTABLE_HITS, 2);
        assert_eq!(BOSMINER_E02C_TYPE_SIZE, BOSMINER_INSTANTIATE_SNAP_SIZE);
        assert_eq!(BOSMINER_FIXTURE_RS.len(), 0x43);
        assert_eq!(BOSMINER_HARDWARE_RS.len(), 0x2E);
        assert_eq!(BOSMINER_E02C_FIXTURE_LINE, 258);
        assert_eq!(BOSMINER_E02C_HARDWARE_LINE, 352);
        assert!(BOSMINER_FIXTURE_RS.ends_with("fixture.rs"));
        assert!(BOSMINER_HARDWARE_RS.ends_with("hardware.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_CTX_290_LDR_VA,
            BOSMINER_CTX_290_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CTX_290_THEN_88_VA,
            BOSMINER_CTX_290_THEN_88_INSN,
        );
        putp(&mut prep_blob, BOSMINER_SP88_LDR_VA, BOSMINER_SP88_LDR_INSN);
        assert!(admit_bosminer_ctx_290_then_88(&prep_blob).is_ok());
        assert!(refuse_ctx_self_plus88_as_method0_load().is_err());
        assert_eq!(BOSMINER_CTX_290_LDR_INSN, 0xF941_4AC9);
        assert_eq!(BOSMINER_CTX_290_THEN_88_INSN, 0xF940_4529);
        assert_eq!(BOSMINER_SP88_LDR_INSN, 0xF940_47E1);
        assert_eq!(BOSMINER_CTX_X22_PLUS88_HITS, 0);
        putp(
            &mut prep_blob,
            BOSMINER_PROD_MAP_LDR_VA,
            BOSMINER_PROD_MAP_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_MAP_LDR_VA + 4,
            BOSMINER_PROD_WRAP_SRC_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_GET_BL_VA,
            BOSMINER_PROD_GET_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_ADD_C0_VA,
            BOSMINER_HASHMAP_GET_ADD_C0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_A8_LDR_VA,
            BOSMINER_HASHMAP_GET_A8_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_KEY_ADD_VA,
            BOSMINER_HASHMAP_GET_KEY_ADD_INSN,
        );
        assert!(admit_bosminer_ctx_290_is_hashmap_get_self(&prep_blob).is_ok());
        assert!(refuse_ctx_290_as_hashchain_engine().is_err());
        assert!(refuse_hashmap_plus88_as_engine_nonce_fn().is_err());
        assert_eq!(BOSMINER_PROD_MAP_LDR_INSN, 0xF941_4AC0);
        assert_eq!(BOSMINER_PROD_GET_BL_INSN, 0x97FF_E9C8);
        assert_eq!(BOSMINER_HASHMAP_GET_ADD_C0_INSN, 0x9103_0000);
        assert_eq!(BOSMINER_HASHMAP_GET_KEY_ADD_INSN, 0x9106_7033);
        assert_eq!(BOSMINER_HASHMAP_GET_FN_VA, 0x0087_87A8);
        assert_eq!(BOSMINER_HC290_STR298_INSN, 0xF901_4EF9);
        assert_ne!(BOSMINER_PROD_MAP_LDR_VA, BOSMINER_HC290_STR_VA);
        for i in 0..BOSMINER_AM3_STR88_HITS {
            putp(
                &mut prep_blob,
                BOSMINER_AM3_STR88_VA[i],
                BOSMINER_AM3_STR88_INSN[i],
            );
        }
        for &h in &BOSMINER_AM3_TAG70_HELPER_VA {
            putp(
                &mut prep_blob,
                h + BOSMINER_AM3_TAG70_HELPER_LDRB_OFF,
                BOSMINER_AM3_TAG70_HELPER_LDRB_INSN,
            );
        }
        for &va in &BOSMINER_AM3_STR88_ADD18_VA {
            putp(
                &mut prep_blob,
                va - BOSMINER_AM3_STR88_ADD18_BEFORE,
                BOSMINER_AM3_STR88_ADD18_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_AM3_STR88_MOVZ4_BEFORE,
                BOSMINER_AM3_STR88_MOVZ4_INSN,
            );
        }
        putp(
            &mut prep_blob,
            BOSMINER_AM3_STR88_SLICE10_CLONE_VA - BOSMINER_AM3_STR88_SLICE10_ADD_BEFORE,
            BOSMINER_SLICE10_ADD_INSN,
        );
        assert!(admit_bosminer_am3_str88_census(&prep_blob).is_ok());
        assert!(admit_bosminer_am3_str88_result_family(&prep_blob).is_ok());
        assert!(admit_bosminer_am3_str88_add18_family(&prep_blob).is_ok());
        assert!(refuse_am3_str88_as_hashmap_plus88().is_err());
        assert!(refuse_am3_str88_as_engine_nonce_text().is_err());
        assert_eq!(BOSMINER_AM3_STR88_HITS, 10);
        assert_eq!(BOSMINER_AM3_STR88_RESULT_HITS, 3);
        assert_eq!(BOSMINER_AM3_STR88_ADD18_HITS, 2);
        assert_eq!(BOSMINER_AM3_STR88_ZERO_INSN, 0xF900_467F);
        assert_eq!(BOSMINER_AM3_STR88_FIELD_INSN, 0xF900_4669);
        assert_eq!(BOSMINER_AM3_STR88_DEST_A8_HITS, 0);
        for i in 0..BOSMINER_HASHMAP_STR88_HITS {
            putp(
                &mut prep_blob,
                BOSMINER_HASHMAP_STR88_VA[i],
                BOSMINER_HASHMAP_STR88_INSN[i],
            );
        }
        for &va in &BOSMINER_HASHMAP_STR88_FAMILY_VA {
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_ADD_A8_BEFORE,
                BOSMINER_HASHMAP_STR88_ADD_A8_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_ADD_C0_BEFORE,
                BOSMINER_HASHMAP_STR88_ADD_C0_INSN,
            );
        }
        assert!(admit_bosminer_hashmap_str88_census(&prep_blob).is_ok());
        assert!(admit_bosminer_hashmap_str88_family(&prep_blob).is_ok());
        assert!(refuse_hashmap_str88_as_engine_nonce_text().is_err());
        assert_eq!(BOSMINER_HASHMAP_STR88_HITS, 11);
        assert_eq!(BOSMINER_HASHMAP_STR88_FAMILY_STRIDE, 0x8B8);
        assert_eq!(BOSMINER_HASHMAP_STR88_FAMILY_INSN, 0xF900_4674);
        assert_eq!(BOSMINER_HASHMAP_STR88_ADD_A8_INSN, 0x9102_A260);
        for i in 0..BOSMINER_HASHMAP_STR88_FAMILY_HITS {
            let va = BOSMINER_HASHMAP_STR88_FAMILY_VA[i];
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_BL_BEFORE,
                BOSMINER_HASHMAP_STR88_BL_INSN[i],
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_LDRB8_BEFORE,
                BOSMINER_HASHMAP_STR88_LDRW_SP110_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_TBZ_BEFORE,
                BOSMINER_HASHMAP_STR88_TBZ_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_LDP_BEFORE,
                BOSMINER_HASHMAP_STR88_LDP_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_SRET_ADD_BEFORE,
                BOSMINER_HASHMAP_STR88_SRET_ADD_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_SELF_B8_BEFORE,
                BOSMINER_HASHMAP_STR88_SELF_B8_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_ADD88_BEFORE,
                BOSMINER_HASHMAP_STR88_ADD88_INSN,
            );
            putp(
                &mut prep_blob,
                va - BOSMINER_HASHMAP_STR88_ADD90_BEFORE,
                BOSMINER_HASHMAP_STR88_ADD90_INSN,
            );
        }
        assert!(admit_bosminer_hashmap_x20_is_result_ok(&prep_blob).is_ok());
        assert!(refuse_hashmap_x20_as_dest_plus88_addr().is_err());
        assert!(refuse_hashmap_x20_as_dest_plus90_addr().is_err());
        assert_eq!(BOSMINER_HASHMAP_STR88_HELPER_VA, 0x0086_1090);
        assert_eq!(BOSMINER_HASHMAP_STR88_LDP_INSN, 0xA951_DFF4);
        assert_eq!(BOSMINER_HASHMAP_STR88_OK_SP, 0x118);
        assert_eq!(BOSMINER_HASHMAP_STR88_SELF_B8_OFF, 0xB8);
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_LDR_INNER_VA,
            BOSMINER_HASHMAP_HELPER_LDR_INNER_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_SAVE_X0_VA,
            BOSMINER_HASHMAP_HELPER_SAVE_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_SRET_MOV_VA,
            BOSMINER_HASHMAP_HELPER_SRET_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_ADD10_VA,
            BOSMINER_HASHMAP_HELPER_ADD10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_CLONE_BL_VA,
            BOSMINER_HASHMAP_HELPER_CLONE_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_OK_STR_VA,
            BOSMINER_HASHMAP_HELPER_OK_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_OK_HI_VA,
            BOSMINER_HASHMAP_HELPER_OK_HI_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_HELPER_TAG_VA,
            BOSMINER_HASHMAP_HELPER_TAG_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_CLONE_ALLOC_SZ_VA,
            BOSMINER_HASHMAP_CLONE_ALLOC_SZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN_VA,
            BOSMINER_HASHMAP_CLONE_ALLOC_ALIGN_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_STR88_SLICE10_REST_VA - BOSMINER_HASHMAP_STR88_SLICE10_REST_ADD_BEFORE,
            BOSMINER_SLICE10_ADD_INSN,
        );
        assert!(admit_bosminer_hashmap_helper_ok_is_b8_clone(&prep_blob).is_ok());
        assert!(admit_bosminer_hashmap_str88_rest_census(&prep_blob).is_ok());
        assert!(refuse_hashmap_helper_ok_as_engine_nonce().is_err());
        assert_eq!(BOSMINER_HASHMAP_STR88_REST_HITS, 8);
        assert_eq!(BOSMINER_HASHMAP_HELPER_CLONE_FN_VA, 0x008B_60AC);
        assert_eq!(BOSMINER_HASHMAP_HELPER_OK_STR_INSN, 0xF900_0660);
        assert_eq!(BOSMINER_HASHMAP_CLONE_ALLOC_SIZE, 0x18);
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_NODE_LDR_VA,
            BOSMINER_HASHMAP_18_NODE_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_NODE_ADD10_VA,
            BOSMINER_HASHMAP_18_NODE_ADD10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_PAIR_LO_VA,
            BOSMINER_HASHMAP_18_PAIR_LO_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_PAIR_HI_VA,
            BOSMINER_HASHMAP_18_PAIR_HI_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_DEALLOC_X0_VA,
            BOSMINER_HASHMAP_18_DEALLOC_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_DEALLOC_BL_VA,
            BOSMINER_HASHMAP_18_DEALLOC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_RET_X0_VA,
            BOSMINER_HASHMAP_18_RET_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_18_RET_X1_VA,
            BOSMINER_HASHMAP_18_RET_X1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK0_VA,
            BOSMINER_RUSTC_HEAP_THUNK0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_5DE708_BL_VA,
            BOSMINER_HASHMAP_5DE708_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_5DE708_LDR_A0_VA,
            BOSMINER_HASHMAP_5DE708_LDR_A0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_115C680_LDR88_VA,
            BOSMINER_HASHMAP_115C680_LDR88_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_115C694_LDR_A8_VA,
            BOSMINER_HASHMAP_115C694_LDR_A8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_115C6B0_STR_A8_VA,
            BOSMINER_HASHMAP_115C6B0_STR_A8_INSN,
        );
        assert!(admit_bosminer_hashmap_18_is_dealloc_node(&prep_blob).is_ok());
        assert!(refuse_hashmap_18_as_alloc().is_err());
        assert!(admit_bosminer_hashmap_5de708_is_result_x0(&prep_blob).is_ok());
        assert!(admit_bosminer_hashmap_115c698_is_field_rewrite(&prep_blob).is_ok());
        assert_eq!(BOSMINER_RUSTC_HEAP_THUNK0_VA, 0x005F_4A7C);
        assert_eq!(BOSMINER_HASHMAP_5DE708_BL_TGT, 0x0058_6CD8);
        assert_eq!(BOSMINER_HASHMAP_115C698_STR_INSN, 0xF900_46A8);
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA,
            BOSMINER_RUSTC_HEAP_THUNK0_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK0_BODY_VA + 4,
            BOSMINER_RUSTC_HEAP_THUNK0_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK0_LDP_VA,
            BOSMINER_RUSTC_HEAP_THUNK0_LDP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK0_B_VA,
            BOSMINER_RUSTC_HEAP_THUNK0_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_DISP_VA,
            BOSMINER_RUSTC_HEAP_DISP_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_DEALLOC_ARM_VA,
            BOSMINER_RUSTC_HEAP_DEALLOC_CBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK1_BODY_VA,
            BOSMINER_RUSTC_HEAP_THUNK1_SUB_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_62672C_LDR_VA,
            BOSMINER_HASHMAP_62672C_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_626730_B_VA,
            BOSMINER_HASHMAP_626730_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_626AA8_PANIC_BL_VA,
            BOSMINER_HASHMAP_626AA8_PANIC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PANIC_DTOR_MOVZ_VA,
            BOSMINER_PANIC_DTOR_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_654690_LDR90_VA,
            BOSMINER_HASHMAP_654690_LDR90_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_654698_B_VA,
            BOSMINER_HASHMAP_654698_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_9F3ED8_LDR_VA,
            BOSMINER_HASHMAP_9F3ED8_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_B824C0_ADD8_VA,
            BOSMINER_HASHMAP_B824C0_ADD8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_B824BC_PANIC_BL_VA,
            BOSMINER_HASHMAP_B824BC_PANIC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_115C784_LDR_A8_VA,
            BOSMINER_HASHMAP_115C784_LDR_A8_INSN,
        );
        assert!(admit_bosminer_heap_thunk0_is_tail_trampoline(&prep_blob).is_ok());
        assert!(refuse_heap_thunk0_as_realloc().is_err());
        assert!(admit_bosminer_hashmap_str88_rest_named().is_ok());
        assert!(admit_bosminer_hashmap_626aac_is_x0_from_x23(&prep_blob).is_ok());
        assert!(refuse_hashmap_626aac_as_panic_4538b0_return().is_err());
        assert!(admit_bosminer_hashmap_654c10_is_x24_from_plus90(&prep_blob).is_ok());
        assert!(admit_bosminer_hashmap_9f3f00_is_stack_x8(&prep_blob).is_ok());
        assert!(admit_bosminer_hashmap_b824c8_is_x8_plus8(&prep_blob).is_ok());
        assert!(refuse_hashmap_b824c8_as_panic_4538b0_return().is_err());
        assert!(admit_bosminer_hashmap_115c788_is_field_rewrite(&prep_blob).is_ok());
        assert!(refuse_hashmap_rest_dests_as_engine_nonce_text().is_err());
        assert_eq!(BOSMINER_RUSTC_HEAP_THUNK0_B_TGT, 0x00BC_9F10);
        assert_eq!(BOSMINER_RUSTC_HEAP_DEALLOC_CBZ_INSN, 0xB400_12A0);
        assert_eq!(BOSMINER_HASHMAP_626AAC_STR_INSN, 0xF900_4660);
        assert_eq!(BOSMINER_HASHMAP_654C10_STR_INSN, 0xF900_4678);
        assert_eq!(BOSMINER_HASHMAP_9F3ED8_SP_OFF, 0x58);
        assert_eq!(BOSMINER_HASHMAP_B824C0_ADD8_INSN, 0x9100_2109);
        assert_eq!(BOSMINER_PANIC_DTOR_MSG.len(), 0x24);
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_BODY_VA,
            BOSMINER_RUSTC_HEAP_THUNK2_SUB_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_CMP_VA,
            BOSMINER_RUSTC_HEAP_THUNK2_CMP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_SAVE_VA,
            BOSMINER_RUSTC_HEAP_THUNK2_SAVE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_B_VA,
            BOSMINER_RUSTC_HEAP_THUNK2_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_B_TGT,
            BOSMINER_RUSTC_HEAP_THUNK2_TGT_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_TGT_CBZ_VA,
            BOSMINER_RUSTC_HEAP_THUNK2_TGT_CBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_VA,
            BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_RUSTC_HEAP_THUNK2_TGT_MUL_VA,
            BOSMINER_RUSTC_HEAP_THUNK2_TGT_MUL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_626FB0_ADD20_VA,
            BOSMINER_HASHMAP_626FB0_ADD20_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_626FC0_B_VA,
            BOSMINER_HASHMAP_626FC0_B_INSN,
        );
        assert!(admit_bosminer_heap_thunk2_is_size_product(&prep_blob).is_ok());
        assert!(refuse_heap_thunk2_as_dummy_trampoline().is_err());
        assert!(refuse_heap_thunk2_as_dealloc().is_err());
        assert!(admit_bosminer_hashmap_626aac_second_arm_is_x8_plus20(&prep_blob).is_ok());
        assert_eq!(BOSMINER_RUSTC_HEAP_THUNK2_B_TGT, 0x00BC_9E18);
        assert_eq!(BOSMINER_RUSTC_HEAP_THUNK2_TGT_UMULH_INSN, 0x9BC1_7C02);
        assert_eq!(BOSMINER_HASHMAP_626FB0_ADD20_INSN, 0x9100_8100);
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_X23_LDR_VA,
            BOSMINER_SPAWN_X23_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_SRET_ADD_VA,
            BOSMINER_SPAWN_SRET_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_BLR_VA,
            BOSMINER_SPAWN_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_OK_LDR_VA,
            BOSMINER_SPAWN_OK_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_X24_STASH_VA,
            BOSMINER_SPAWN_X24_STASH_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_X24_LDR_VA,
            BOSMINER_SPAWN_X24_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PROD_CALL_X1_MOV_VA,
            BOSMINER_PROD_CALL_X1_MOV_INSN,
        );
        assert!(admit_bosminer_fill_plus88_template_is_spawn_x24(&prep_blob).is_ok());
        assert!(refuse_fill_type1_adrp_identity_installer().is_err());
        assert_eq!(BOSMINER_SPAWN_X23_LDR_INSN, 0xF940_0037);
        assert_eq!(BOSMINER_SPAWN_OK_SP, 0x78);
        assert_eq!(BOSMINER_ADRP_ADD_STR88_HITS, 0);
        assert_eq!(BOSMINER_ADRP_LDR_TEXT_STR88_NONSP_HITS, 0);
        assert_eq!(BOSMINER_E02C_METHODS_STR88_HITS, 0);
        assert_eq!(BOSMINER_SPAWN_BLR_VA, BOSMINER_FACTORY_SPAWN_BLR_VA);
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_HIT_ADD8_VA,
            BOSMINER_HASHMAP_GET_HIT_ADD8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_HIT_XZR_VA,
            BOSMINER_HASHMAP_GET_HIT_XZR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_HIT_X0_VA,
            BOSMINER_HASHMAP_GET_RET_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_HIT_X1_VA,
            BOSMINER_HASHMAP_GET_RET_X1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_HIT_RET_VA,
            BOSMINER_HASHMAP_GET_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_MISS_TAG_VA,
            BOSMINER_HASHMAP_GET_MISS_TAG_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_MISS_X0_VA,
            BOSMINER_HASHMAP_GET_RET_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_MISS_X1_VA,
            BOSMINER_HASHMAP_GET_RET_X1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_MISS_RET_VA,
            BOSMINER_HASHMAP_GET_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_TBZ_VA,
            BOSMINER_SPAWN_TBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_DEFAULT_ALIGN_VA,
            BOSMINER_SPAWN_DEFAULT_ALIGN_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_DEFAULT_SIZE_VA,
            BOSMINER_SPAWN_DEFAULT_SIZE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_DEFAULT_ALLOC_BL_VA,
            BOSMINER_SPAWN_DEFAULT_ALLOC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_MISS_TYPEINFO_ADRP_VA,
            BOSMINER_SPAWN_MISS_TYPEINFO_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_MISS_TYPEINFO_ADD_VA,
            BOSMINER_SPAWN_MISS_TYPEINFO_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_MISS_TYPEINFO_STR_VA,
            BOSMINER_SPAWN_MISS_TYPEINFO_STR_INSN,
        );
        assert!(admit_bosminer_hashmap_get_returns_tag_payload(&prep_blob).is_ok());
        assert!(admit_bosminer_spawn_x23_is_payload_qword0(&prep_blob).is_ok());
        assert!(refuse_spawn_x23_as_first_load_identity_text().is_err());
        assert_eq!(BOSMINER_SPAWN_DEFAULT_SIZE, 0x50);
        assert_eq!(BOSMINER_SPAWN_TBZ_TGT, 0x0087_E278);
        assert_eq!(BOSMINER_SPAWN_DEFAULT_ALLOC_BL_TGT, 0x005F_4A78);
        assert_eq!(BOSMINER_SPAWN_MISS_PAYLOAD0_VA, 0x019B_DE50);
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_SRC_MOV_VA,
            BOSMINER_HASHMAP_INSERT_SRC_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_HASH_BL_VA,
            BOSMINER_HASHMAP_INSERT_HASH_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_HASH_BL_VA,
            BOSMINER_HASHMAP_GET_HASH_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_LDR_Q_VA,
            BOSMINER_HASHMAP_INSERT_LDR_Q_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_LDR_X10_VA,
            BOSMINER_HASHMAP_INSERT_LDR_X10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_STUR_Q_VA,
            BOSMINER_HASHMAP_INSERT_STUR_Q_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_STUR_X18_VA,
            BOSMINER_HASHMAP_INSERT_STUR_X18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_ORR8_VA,
            BOSMINER_HASHMAP_INSERT_ORR8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_CALL_BL_VA,
            BOSMINER_HASHMAP_INSERT_CALL_BL_INSN,
        );
        assert!(admit_bosminer_hashmap_insert_copies_18_from_entry8(&prep_blob).is_ok());
        assert!(refuse_hashmap_insert_as_plus88_identity().is_err());
        assert_eq!(BOSMINER_HASHMAP_INSERT_FN_VA, 0x008D_A510);
        assert_eq!(BOSMINER_HASHMAP_INSERT_VALUE_SIZE, 0x18);
        assert_eq!(BOSMINER_HASHMAP_HASH_FN_VA, 0x008B_8C84);
        assert_eq!(BOSMINER_HASHMAP_INSERT_NONSP_STR88_HITS, 0);
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_QWORD0_ADRP_VA,
            BOSMINER_ENTRY8_QWORD0_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_QWORD0_ADD_VA,
            BOSMINER_ENTRY8_QWORD0_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_QWORD0_STP_VA,
            BOSMINER_ENTRY8_QWORD0_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_1366_STP_VA,
            BOSMINER_ENTRY8_1366_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_SRC_ADD_VA,
            BOSMINER_ENTRY8_SRC_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_INSERT_BL_VA,
            BOSMINER_ENTRY8_INSERT_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_LDP_SRC_VA,
            BOSMINER_ENTRY8_LDP_SRC_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_SP_MOV_VA,
            BOSMINER_ENTRY8_SP_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_STP_SP_VA,
            BOSMINER_ENTRY8_STP_SP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_QWORD0_FN_VA,
            BOSMINER_FACTORY4_PROLOGUE_INSN,
        );
        assert!(admit_bosminer_entry8_qword0_is_factory4(&prep_blob).is_ok());
        assert!(refuse_entry8_qword0_as_identity_text().is_err());
        assert_eq!(BOSMINER_ENTRY8_QWORD0_FN_VA, 0x0087_7D40);
        assert_eq!(BOSMINER_FACTORY_CLONE_BL_VA[4], 0x0087_7DBC);
        assert_eq!(BOSMINER_VT0_250_NONSP_STR88_HITS, 0);
        assert_eq!(BOSMINER_BM1366_DISPATCH_MOVZ_INSN, 0x5282_6CCA);
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_FRAME_VA,
            BOSMINER_FACTORY4_FRAME_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_876_FRAME_VA,
            BOSMINER_FACTORY_876_FRAME_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_SNAP_SIZE_VA,
            BOSMINER_FACTORY4_SNAP_SIZE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_SNAP_SIZE_VA,
            BOSMINER_FACTORY_SNAP_SIZE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_WORKER_NEW_BL_VA,
            BOSMINER_FACTORY4_WORKER_NEW_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_WORKER_NEW_BL_VA,
            BOSMINER_FACTORY_WORKER_NEW_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_CLONE_BL_VA,
            BOSMINER_FACTORY_CLONE_BL_INSN[4],
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_876_CLONE_BL_VA,
            BOSMINER_FACTORY_CLONE_BL_INSN[1],
        );
        putp(
            &mut prep_blob,
            BOSMINER_BM1366_DISPATCH_MOVZ_VA,
            BOSMINER_BM1366_DISPATCH_MOVZ_INSN,
        );
        assert!(admit_bosminer_1366_uses_two_factory_monomorphs(&prep_blob).is_ok());
        assert!(refuse_factory4_as_876ca8().is_err());
        assert_eq!(BOSMINER_FACTORY4_FN_VA, 0x0087_7D40);
        assert_eq!(BOSMINER_BM1366_FACTORY_FN_VA, 0x0087_6CA8);
        assert_eq!(BOSMINER_FACTORY4_SNAP_SIZE, 0x1608);
        assert_eq!(BOSMINER_FACTORY_SNAP_SIZE, 0x15F8);
        assert_eq!(BOSMINER_FACTORY4_FRAME, 0x6C0);
        assert_eq!(BOSMINER_FACTORY_876_FRAME, 0x690);
        assert_eq!(BOSMINER_FACTORY4_WORKER_NEW_VA, 0x0090_4434);
        assert_eq!(BOSMINER_FACTORY_876_WORKER_NEW_VA, 0x0090_3534);
        assert_eq!(BOSMINER_FACTORY_CLONE_TGT, 0x0087_5F54);
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_FRAME_VA,
            BOSMINER_WORKER_NEW_876_FRAME_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_FRAME_VA,
            BOSMINER_WORKER_NEW_FACTORY4_FRAME_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_876_COPY1600_VA,
            BOSMINER_FACTORY_876_COPY1600_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_COPY1610_VA,
            BOSMINER_FACTORY4_COPY1610_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_876_COPY230_VA,
            BOSMINER_FACTORY_COPY_230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_COPY230_VA,
            BOSMINER_FACTORY_COPY_230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_876_ALLOC1890_VA,
            BOSMINER_FACTORY_876_ALLOC1890_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_ALLOC18A0_VA,
            BOSMINER_FACTORY4_ALLOC18A0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_COPY1A8_VA,
            BOSMINER_WORKER_NEW_876_COPY1A8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_CA00_VA,
            BOSMINER_WORKER_NEW_FACTORY4_CA00_INSN,
        );
        assert!(admit_bosminer_worker_new_monomorphs_split(&prep_blob).is_ok());
        assert!(refuse_worker_new_factory4_as_876().is_err());
        assert_eq!(BOSMINER_WORKER_NEW_876_FRAME, 0xEE0);
        assert_eq!(BOSMINER_WORKER_NEW_FACTORY4_FRAME, 0xF00);
        assert_eq!(BOSMINER_FACTORY_876_COPY1600, 0x1600);
        assert_eq!(BOSMINER_FACTORY4_COPY1610, 0x1610);
        assert_eq!(BOSMINER_FACTORY_876_ALLOC1890, 0x1890);
        assert_eq!(BOSMINER_FACTORY4_ALLOC18A0, 0x18A0);
        assert_eq!(BOSMINER_WORKER_NEW_876_COPY1A8, 0x1A8);
        assert_eq!(BOSMINER_WORKER_NEW_FACTORY4_CA00, 0xCA00);
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_LDR_W8_VA,
            BOSMINER_WORKER_NEW_FACTORY4_LDR_W8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_MOVK_VA,
            BOSMINER_WORKER_NEW_FACTORY4_MOVK_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_CMP_VA,
            BOSMINER_WORKER_NEW_FACTORY4_CMP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_BNE_VA,
            BOSMINER_WORKER_NEW_FACTORY4_BNE_INSN,
        );
        assert!(admit_bosminer_factory4_ca00_is_1e9(&prep_blob).is_ok());
        assert!(refuse_ca00_as_factory4_type_tag().is_err());
        assert_eq!(BOSMINER_WORKER_NEW_FACTORY4_1E9, 1_000_000_000);
        assert_eq!(BOSMINER_CA00_MOVZ_W9_HITS, 230);
        assert_eq!(
            (0x3B9A_u32 << 16) | u32::from(BOSMINER_WORKER_NEW_FACTORY4_CA00),
            1_000_000_000
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_COPY1A8_VA,
            BOSMINER_WORKER_NEW_876_COPY1A8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_MEMCPY_BL_VA,
            BOSMINER_WORKER_NEW_876_MEMCPY_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_MEMCPY_BL_VA,
            BOSMINER_WORKER_NEW_FACTORY4_MEMCPY_BL_INSN,
        );
        assert!(admit_bosminer_worker_new_copy1a8_shared(&prep_blob).is_ok());
        assert!(refuse_copy1a8_as_factory_type_param().is_err());
        assert_eq!(BOSMINER_WORKER_NEW_COPY1A8_TO_MEMCPY, 0x3C);
        assert_eq!(BOSMINER_WORKER_NEW_1A8_MOVZ_HITS, 64);
        assert_eq!(BOSMINER_WORKER_NEW_MEMCPY_TGT, 0x00BC_8FE0);
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_SNAP_DEST_ADD_VA,
            BOSMINER_FACTORY_SNAP_DEST_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_SNAP_DEST_ADD_VA,
            BOSMINER_FACTORY_SNAP_DEST_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_VA,
            BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_SNAP_SRC_HIGH_ADD_VA,
            BOSMINER_FACTORY_SNAP_SRC_HIGH_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_876_SNAP_SRC_LOW_ADD_VA,
            BOSMINER_FACTORY_876_SNAP_SRC_LOW_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_SNAP_SRC_LOW_ADD_VA,
            BOSMINER_FACTORY4_SNAP_SRC_LOW_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_PLUS10_MOVZ_VA,
            BOSMINER_ENTRY8_PLUS10_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_PLUS10_MOVK_VA,
            BOSMINER_ENTRY8_PLUS10_MOVK_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_PLUS10_STR_VA,
            BOSMINER_ENTRY8_PLUS10_STR_INSN,
        );
        assert!(admit_bosminer_factory4_snap_extra_is_tail_16(&prep_blob).is_ok());
        assert!(refuse_entry8_plus10_as_snap_extra16().is_err());
        assert_eq!(BOSMINER_FACTORY_SNAP_DEST_OFF, 0x40);
        assert_eq!(BOSMINER_FACTORY_SNAP_SRC_LOW, 0x640);
        assert_eq!(BOSMINER_FACTORY4_SNAP_SRC_LOW, 0x650);
        assert_eq!(BOSMINER_ENTRY8_PLUS10_VALUE, 0x002F_AF08);
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STR_15F8_VA,
            BOSMINER_WORKER_NEW_876_STR_15F8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STR_1600_VA,
            BOSMINER_WORKER_NEW_876_STR_1600_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_STR_15F8_VA,
            BOSMINER_WORKER_NEW_FACTORY4_STR_15F8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_STR_1600_VA,
            BOSMINER_WORKER_NEW_FACTORY4_STR_1600_INSN,
        );
        assert!(admit_bosminer_snap_extra16_is_worker_new_tail(&prep_blob).is_ok());
        assert!(refuse_tail16_as_entry8_plus10().is_err());
        assert_eq!(BOSMINER_WORKER_NEW_TAIL_Q0_OFF, 0x15F8);
        assert_eq!(BOSMINER_WORKER_NEW_TAIL_Q1_OFF, 0x1600);
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_MOV_X24_X0_VA,
            BOSMINER_WORKER_NEW_876_MOV_X24_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_MOV_X22_X8_VA,
            BOSMINER_WORKER_NEW_876_MOV_X22_X8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STR_X24_SP30_VA,
            BOSMINER_WORKER_NEW_876_STR_X24_SP30_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_LDR_X9_SP30_VA,
            BOSMINER_WORKER_NEW_876_LDR_X9_SP30_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STR_13B8_VA,
            BOSMINER_WORKER_NEW_876_STR_13B8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_MOV_X0_X24_VA,
            BOSMINER_WORKER_NEW_876_MOV_X0_X24_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_CALL_BL_VA,
            BOSMINER_WORKER_NEW_876_CALL_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STR_SP5F0_VA,
            BOSMINER_WORKER_NEW_876_STR_SP5F0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_LDR_X21_SP5F0_VA,
            BOSMINER_WORKER_NEW_876_LDR_X21_SP5F0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_VA,
            BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN,
        );
        putp(&mut prep_blob, BOSMINER_AF08_CMP_VA, BOSMINER_AF08_CMP_INSN);
        putp(
            &mut prep_blob,
            BOSMINER_AF08_CLASS11_VA,
            BOSMINER_AF08_CLASS11_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_AF08_CLASS10_VA,
            BOSMINER_AF08_CLASS10_INSN,
        );
        assert!(admit_bosminer_876_tail_15f8_is_arg0(&prep_blob).is_ok());
        assert!(refuse_2faf08_as_worker_new_tail().is_err());
        assert!(refuse_factory4_1600_as_876_arg0().is_err());
        assert_eq!(BOSMINER_WORKER_NEW_876_CALL_TGT, 0x00BF_33A4);
        assert_eq!(BOSMINER_WORKER_NEW_FACTORY4_1209, 0x1209);
        assert_eq!(BOSMINER_AF08_MOVZ_W8_HITS, 4);
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_876_MOV_X23_X0_VA,
            BOSMINER_FACTORY_MOV_X23_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_MOV_X23_X0_VA,
            BOSMINER_FACTORY_MOV_X23_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_WORKER_NEW_DEST_VA,
            BOSMINER_FACTORY_MOV_X0_X23_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_MOV_X0_X23_VA,
            BOSMINER_FACTORY_MOV_X0_X23_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_CALL_TGT,
            BOSMINER_BF33A4_FRAME_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_SIZE_VA,
            BOSMINER_BF33A4_SIZE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_ALIGN_VA,
            BOSMINER_BF33A4_ALIGN_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_ALLOC_BL_VA,
            BOSMINER_BF33A4_ALLOC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STR20_VA,
            BOSMINER_BF33A4_STR20_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_RET_VA,
            BOSMINER_BF33A4_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_MOVZ_1209_VA,
            BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_ADD_1209_VA,
            BOSMINER_WORKER_NEW_876_ADD_1209_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_MOVZ_1208_VA,
            BOSMINER_WORKER_NEW_COPY1208_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1208_VA,
            BOSMINER_WORKER_NEW_COPY1208_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_ADD_1209_VA,
            BOSMINER_WORKER_NEW_FACTORY4_ADD_1209_INSN,
        );
        assert!(admit_bosminer_factory_x23_is_self_and_bf33a4_is_70_box(&prep_blob).is_ok());
        assert!(refuse_bf33a4_as_identity().is_err());
        assert_eq!(BOSMINER_BF33A4_SIZE, 0x70);
        assert_eq!(BOSMINER_WORKER_NEW_COPY1208, 0x1208);
        assert_eq!(BOSMINER_WORKER_NEW_FACTORY4_1209, 0x1209);
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STR10_VA,
            BOSMINER_BF33A4_STR10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STRB18_VA,
            BOSMINER_BF33A4_STRB18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STP60_VA,
            BOSMINER_BF33A4_STP60_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STP48_VA,
            BOSMINER_BF33A4_STP48_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STRQ0_VA,
            BOSMINER_BF33A4_STRQ0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_FACTORY4_BL_VA,
            BOSMINER_BF33A4_FACTORY4_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_FACTORY4_STR_SP610_VA,
            BOSMINER_BF33A4_FACTORY4_STR_SP610_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_COPY1AF_VA,
            BOSMINER_WORKER_NEW_COPY1AF_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_COPY1AF_VA,
            BOSMINER_WORKER_NEW_COPY1AF_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_SRC840_VA,
            BOSMINER_WORKER_NEW_876_SRC840_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_SRC860_VA,
            BOSMINER_WORKER_NEW_FACTORY4_SRC860_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STR_11E0_VA,
            BOSMINER_WORKER_NEW_876_STR_11E0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STR_1200_VA,
            BOSMINER_WORKER_NEW_876_STR_1200_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_STRB_1208_VA,
            BOSMINER_WORKER_NEW_876_STRB_1208_INSN,
        );
        assert!(admit_bosminer_bf33a4_box_fields_and_1208_header(&prep_blob).is_ok());
        assert!(refuse_1208_as_object_base_memcpy().is_err());
        assert!(refuse_factory_self_as_hashchain_ldr().is_err());
        assert_eq!(BOSMINER_BF33A4_BL_HITS, 6);
        assert_eq!(BOSMINER_WORKER_NEW_COPY1AF, 0x1AF);
        assert_eq!(BOSMINER_FACTORY_SELF_X23_LDR_HITS, 0);
        putp(
            &mut prep_blob,
            BOSMINER_F11F26F8_FN_VA,
            BOSMINER_F11F26F8_LSR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_F11F26F8_LSL_VA,
            BOSMINER_F11F26F8_LSL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_F11F26F8_STP0_VA,
            BOSMINER_F11F26F8_STP0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_F11F26F8_STR20_VA,
            BOSMINER_F11F26F8_STR20_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_F11F26F8_RET_VA,
            BOSMINER_F11F26F8_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_INIT_DEST_ADD_VA,
            BOSMINER_BF33A4_INIT_DEST_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_INIT_ARG_VA,
            BOSMINER_BF33A4_INIT_ARG_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_LDURQ0_VA,
            BOSMINER_BF33A4_LDURQ0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_LDURQ1_VA,
            BOSMINER_BF33A4_LDURQ1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_876_BLOB840_VA,
            BOSMINER_WORKER_NEW_876_BLOB840_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_BLOB_PLUS7_VA,
            BOSMINER_WORKER_NEW_BLOB_PLUS7_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_BLOB860_VA,
            BOSMINER_WORKER_NEW_FACTORY4_BLOB860_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_610_DROP_ADD_VA,
            BOSMINER_FACTORY4_610_DROP_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_610_DROP_BL_VA,
            BOSMINER_FACTORY4_610_DROP_BL_INSN,
        );
        assert!(admit_bosminer_11f26f8_zeros_tag2_and_1af_is_7_plus_1a8(&prep_blob).is_ok());
        assert!(refuse_q0q1_as_identity_text().is_err());
        assert!(refuse_1af_as_asic_frame().is_err());
        assert_eq!(BOSMINER_BF33A4_INIT_TAG, 2);
        assert_eq!(BOSMINER_WORKER_NEW_1AF_PREFIX, 7);
        assert_eq!(BOSMINER_FACTORY4_610_DROP_TGT, 0x00B4_1D80);
        putp(
            &mut prep_blob,
            BOSMINER_B41D80_LDR_SLOT_VA,
            BOSMINER_B41D80_LDR_SLOT_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_B41D80_SIZE_VA,
            BOSMINER_B41D80_SIZE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_B41D80_ALIGN_VA,
            BOSMINER_B41D80_ALIGN_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_B41D80_B_DEALLOC_VA,
            BOSMINER_B41D80_B_DEALLOC_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_LDP_Q12_VA,
            BOSMINER_BF33A4_LDP_Q12_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STURQ2_VA,
            BOSMINER_BF33A4_STURQ2_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_PREFIX_LDR_VA,
            BOSMINER_FACTORY4_PREFIX_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_PREFIX_STR_VA,
            BOSMINER_FACTORY4_PREFIX_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_EC8_STR_VA,
            BOSMINER_876_EC8_STR_INSN,
        );
        assert!(admit_bosminer_b41d80_is_70_drop_and_q2_from_sp(&prep_blob).is_ok());
        assert!(refuse_7byte_prefix_as_55aa_header().is_err());
        assert!(refuse_q2_as_identity_text().is_err());
        assert_eq!(BOSMINER_B41D80_BL_HITS, 54);
        assert_eq!(BOSMINER_876_BLOB840_STR_HITS, 0);
        assert_eq!(BOSMINER_B41D80_FN_VA, 0x00B4_1D80);
        putp(
            &mut prep_blob,
            BOSMINER_887C34_FN_VA,
            BOSMINER_887C34_FRAME_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_SIZE_VA,
            BOSMINER_887C34_SIZE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_ALIGN_VA,
            BOSMINER_887C34_ALIGN_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_ALLOC_BL_VA,
            BOSMINER_887C34_ALLOC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_MOV_X1_X0_VA,
            BOSMINER_887C34_MOV_X1_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_RET_VA,
            BOSMINER_887C34_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_XZR_VA,
            BOSMINER_FACTORY4_XZR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_887C34_BL_VA,
            BOSMINER_FACTORY4_887C34_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_STR600_VA,
            BOSMINER_FACTORY4_STR600_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_LDR600_VA,
            BOSMINER_FACTORY4_LDR600_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_STR_EC8_FROM600_VA,
            BOSMINER_FACTORY4_STR_EC8_FROM600_INSN,
        );
        putp(&mut prep_blob, BOSMINER_876_XZR_VA, BOSMINER_876_XZR_INSN);
        putp(
            &mut prep_blob,
            BOSMINER_876_887C34_BL_VA,
            BOSMINER_876_887C34_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_STR5E0_VA,
            BOSMINER_876_STR5E0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BBD3DC_FN_VA,
            BOSMINER_BBD3DC_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BBD3DC_LDAXR_VA,
            BOSMINER_BBD3DC_LDAXR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BBD3DC_ADD48_VA,
            BOSMINER_BBD3DC_ADD48_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BBD3DC_LDAXR1_VA,
            BOSMINER_BBD3DC_LDAXR1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BBD3DC_RET_VA,
            BOSMINER_BBD3DC_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_BBD3DC_BL_VA,
            BOSMINER_876_BBD3DC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_STR_EC0_VA,
            BOSMINER_876_STR_EC0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_BBD3DC_BL_VA,
            BOSMINER_FACTORY4_BBD3DC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_STR_EE0_VA,
            BOSMINER_FACTORY4_STR_EE0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_STR_EE8_VA,
            BOSMINER_FACTORY4_STR_EE8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STRQ0_SP_VA,
            BOSMINER_BF33A4_STRQ0_SP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STRQ1_SP10_VA,
            BOSMINER_BF33A4_STRQ1_SP10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_BF33A4_STURQ1_28_VA,
            BOSMINER_BF33A4_STURQ1_28_INSN,
        );
        assert!(admit_bosminer_887c34_is_98_box_and_q2_is_zero_shuffle(&prep_blob).is_ok());
        assert!(refuse_factory4_prefix_as_bbd3dc_pair().is_err());
        assert!(refuse_876_ec8_as_840_prefix().is_err());
        assert_eq!(BOSMINER_887C34_BL_HITS, 5);
        assert_eq!(BOSMINER_BBD3DC_BL_HITS, 11);
        assert_eq!(BOSMINER_887C34_SIZE, 0x98);
        assert_eq!(BOSMINER_887C34_FN_VA, 0x0088_7C34);
        putp(
            &mut prep_blob,
            BOSMINER_887C34_MOVZ8_VA,
            BOSMINER_887C34_MOVZ8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_STRQ0_VA,
            BOSMINER_887C34_STRQ0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_STP20_VA,
            BOSMINER_887C34_STP20_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_STP40_VA,
            BOSMINER_887C34_STP40_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_STP58_VA,
            BOSMINER_887C34_STP58_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_STR68_VA,
            BOSMINER_887C34_STR68_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_LDAXR_VA,
            BOSMINER_887C34_LDAXR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_STR90_VA,
            BOSMINER_887C34_STR90_INSN,
        );
        assert!(admit_bosminer_887c34_arcinner_fields(&prep_blob).is_ok());
        assert!(refuse_98_arg58_as_7byte_prefix().is_err());
        assert_eq!(BOSMINER_887C34_ARG_OFF, 0x58);
        assert_eq!(BOSMINER_887C34_USIZE8_OFFS, [0x20, 0x40, 0x68]);
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_BLOB_PLUS7_VA,
            BOSMINER_FACTORY4_BLOB_PLUS7_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_1AF_SRC_VA,
            BOSMINER_FACTORY4_1AF_SRC_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_BLOB860_VA,
            BOSMINER_WORKER_NEW_FACTORY4_BLOB860_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_PREFIX_STR_VA,
            BOSMINER_FACTORY4_PREFIX_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_MOVZ8_VA,
            BOSMINER_887C34_MOVZ8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_887C34_STP20_VA,
            BOSMINER_887C34_STP20_INSN,
        );
        assert!(admit_bosminer_1af_prefix_unwritten_and_8_is_layout_align(&prep_blob).is_ok());
        assert!(refuse_factory4_prefix_as_887c34_arc().is_err());
        assert!(refuse_8_as_vec_capacity().is_err());
        assert_eq!(BOSMINER_FACTORY4_ARC_BLOB_GAP, 0x20);
        assert_eq!(BOSMINER_FACTORY4_BLOB860_STR_HITS, 0);
        assert_eq!(BOSMINER_887C34_LAYOUT_SIZE_OFFS, [0x18, 0x38, 0x60]);
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_VA,
            BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1209_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_MOVZ_1208_VA,
            BOSMINER_WORKER_NEW_COPY1208_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_DEST1209_ADD_VA,
            BOSMINER_FACTORY4_DEST1209_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_STRB_1208_VA,
            BOSMINER_FACTORY4_STRB_1208_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_STR_13B8_VA,
            BOSMINER_FACTORY4_STR_13B8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_STR_13B8_VA,
            BOSMINER_876_STR_13B8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKER_NEW_FACTORY4_COPY1AF_VA,
            BOSMINER_WORKER_NEW_COPY1AF_INSN,
        );
        assert!(admit_bosminer_1af_is_pad7_then_aligned_1a8(&prep_blob).is_ok());
        assert!(refuse_1af_as_wire_header_or_vec_len().is_err());
        assert_eq!(BOSMINER_WORKER_NEW_1AF_ALIGNED, 0x1210);
        assert_eq!(BOSMINER_WORKER_NEW_1AF_END, 0x13B8);
        putp(
            &mut prep_blob,
            BOSMINER_876_LDRB_ARG1_C8_VA,
            BOSMINER_876_LDRB_ARG1_C8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_MOV_W4_W26_VA,
            BOSMINER_876_MOV_W4_W26_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_LDRB_ARG1_C8_VA,
            BOSMINER_FACTORY4_LDRB_ARG1_C8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_BOX_STR_5F0_VA,
            BOSMINER_876_BOX_STR_5F0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_BOX_LDR_5F0_VA,
            BOSMINER_876_BOX_LDR_5F0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_LDRB_BOX18_VA,
            BOSMINER_876_LDRB_BOX18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_LDRB_BOX18_VA,
            BOSMINER_FACTORY4_LDRB_BOX18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_MOV_W20_W22_VA,
            BOSMINER_FACTORY4_MOV_W20_W22_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_1A8_SRC_VA,
            BOSMINER_876_1A8_SRC_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_1A8_SRC_VA,
            BOSMINER_FACTORY4_1A8_SRC_INSN,
        );
        assert!(admit_bosminer_1208_is_arg1_c8_and_1a8_is_local(&prep_blob).is_ok());
        assert!(refuse_1208_u8_as_midstate_or_55aa().is_err());
        assert_eq!(BOSMINER_WORKER_NEW_ARG1_C8, 0xC8);
        assert_eq!(BOSMINER_WORKER_NEW_ARG1_158, 0x158);
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_MATCH_LDRB_VA,
            BOSMINER_HASHCHAIN_C8_MATCH_LDRB_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_CMP1_VA,
            BOSMINER_HASHCHAIN_C8_CMP1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_CMP3_VA,
            BOSMINER_HASHCHAIN_C8_CMP3_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_CMP2_VA,
            BOSMINER_HASHCHAIN_C8_CMP2_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_SET1_VA,
            BOSMINER_HASHCHAIN_C8_SET1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_STR1_VA,
            BOSMINER_HASHCHAIN_C8_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_SET3_VA,
            BOSMINER_HASHCHAIN_C8_SET3_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_C8_SET2_VA,
            BOSMINER_HASHCHAIN_C8_SET2_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_REGISTRY_WRAP_DEST_VA,
            BOSMINER_876_REGISTRY_WRAP_DEST_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_REGISTRY_WRAP_BL_VA,
            BOSMINER_876_REGISTRY_WRAP_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY4_REGISTRY_WRAP_DEST_VA,
            BOSMINER_FACTORY4_REGISTRY_WRAP_DEST_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_876_1A8_SRC_VA,
            BOSMINER_876_1A8_SRC_INSN,
        );
        assert!(admit_bosminer_c8_is_state_tag_and_1a8_is_registry(&prep_blob).is_ok());
        assert!(refuse_c8_as_bool().is_err());
        assert_eq!(BOSMINER_HASHCHAIN_C8_CMP3_HITS, 77);
        assert_eq!(BOSMINER_REGISTRY_WRAP_FN_VA, 0x00BF_7798);
        putp(
            &mut prep_blob,
            BOSMINER_C8_TAG1_CBNZ_VA,
            BOSMINER_C8_TAG1_CBNZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_TAG_NE3_B_VA,
            BOSMINER_C8_TAG_NE3_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_ASYNC_DONE_ADRP_VA,
            BOSMINER_C8_ASYNC_DONE_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_ASYNC_DONE_ADD_VA,
            BOSMINER_C8_ASYNC_DONE_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_ASYNC_DONE_BL_VA,
            BOSMINER_C8_ASYNC_DONE_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_ASYNC_PANIC_BL_VA,
            BOSMINER_C8_ASYNC_PANIC_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_NESTED_ADD_VA,
            BOSMINER_C8_NESTED_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ASYNC_DONE_HELPER_ADD_VA,
            BOSMINER_ASYNC_DONE_HELPER_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ASYNC_PANIC_HELPER_ADD_VA,
            BOSMINER_ASYNC_PANIC_HELPER_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_COMPLETE_RET_VA,
            BOSMINER_C8_COMPLETE_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_PENDING_RET_VA,
            BOSMINER_C8_PENDING_RET_INSN,
        );
        assert!(admit_bosminer_c8_tags_are_command_rs_async_poll(&prep_blob).is_ok());
        assert!(refuse_c8_as_hashchain_running_or_starting().is_err());
        assert_eq!(bosminer_c8_async_tag_name(1), Some("Completed"));
        assert_eq!(bosminer_c8_async_tag_name(2), Some("Panicked"));
        assert_eq!(bosminer_c8_async_tag_name(3), Some("Suspended"));
        assert_eq!(bosminer_c8_async_tag_name(0), Some("Unresumed"));
        assert_eq!(bosminer_c8_async_tag_name(4), None);
        assert_eq!(BOSMINER_C8_ASYNC_FN_LINE, 700);
        assert_eq!(BOSMINER_C8_NESTED_ASYNC_LINE, 719);
        assert_eq!(BOSMINER_ASYNC_DONE_MSG.len(), BOSMINER_ASYNC_DONE_MSG_LEN);
        assert_eq!(BOSMINER_ASYNC_PANIC_MSG.len(), BOSMINER_ASYNC_PANIC_MSG_LEN);
        assert!(BOSMINER_HAL_COMMAND_RS.ends_with("bosminer-hal/src/command.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_VT230_LDR_VA,
            BOSMINER_C8_POLL_VT230_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_VT10_ADD_VA,
            BOSMINER_C8_POLL_VT10_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_ADD30_VA,
            BOSMINER_C8_POLL_ADD30_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_ADD70_VA,
            BOSMINER_C8_POLL_ADD70_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_ADD18_VA,
            BOSMINER_C8_POLL_ADD18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_BM1366_ADD_VA,
            BOSMINER_C8_POLL_BM1366_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_BM136X_ADD_VA,
            BOSMINER_C8_POLL_BM136X_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_POLL_BM1397_ADD_VA,
            BOSMINER_C8_POLL_BM1397_ADD_INSN,
        );
        for i in 0..6 {
            putp(
                &mut prep_blob,
                BOSMINER_C8_POLL_BL_VAS[i],
                BOSMINER_C8_POLL_BL_INSNS[i],
            );
        }
        assert!(admit_bosminer_c8_async_polled_from_hashchain_drivers(&prep_blob).is_ok());
        assert!(refuse_c8_async_as_named_write_register().is_err());
        assert_eq!(BOSMINER_C8_POLL_BL_HITS, 6);
        assert_eq!(BOSMINER_C8_POLL_BM1366_LINE, 127);
        assert_eq!(BOSMINER_C8_POLL_BM136X_LINE, 107);
        assert_eq!(BOSMINER_C8_POLL_BM1397_LINE, 147);
        assert_eq!(BOSMINER_C8_FUTURE_OFF_BM1366, 0x30);
        assert_eq!(BOSMINER_C8_FUTURE_OFF_BM136X, 0x70);
        assert_eq!(BOSMINER_C8_FUTURE_OFF_BM1397, 0x18);
        assert_eq!(
            BOSMINER_BM136X_FIELDSET_MSG.len(),
            BOSMINER_BM136X_FIELDSET_MSG_LEN
        );
        assert!(BOSMINER_C8_POLL_BM1397_RS.ends_with("hashchain/bm1397.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_C8_CTX8_LDR_VA,
            BOSMINER_C8_CTX8_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_FUT_ZERO_VA,
            BOSMINER_C8_FUT_ZERO_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_FUT_IMM_STR_VA,
            BOSMINER_C8_FUT_IMM_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_STATE_ZERO_F8_VA,
            BOSMINER_C8_STATE_ZERO_F8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_FUT10_STR_VA,
            BOSMINER_C8_FUT10_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_STATE_ZERO_138_VA,
            BOSMINER_C8_STATE_ZERO_138_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C8_STATE_ZERO_E0_VA,
            BOSMINER_C8_STATE_ZERO_E0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_WRAP_LOC_ADRP_VA,
            BOSMINER_REGISTRY_WRAP_LOC_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_WRAP_LOC_ADD_VA,
            BOSMINER_REGISTRY_WRAP_LOC_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_WRAP_NEW_BL_VA,
            BOSMINER_REGISTRY_WRAP_NEW_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_WRAP_STR110_VA,
            BOSMINER_REGISTRY_WRAP_STR110_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_WRAP_ADD118_VA,
            BOSMINER_REGISTRY_WRAP_ADD118_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_WRAP_ADD168_VA,
            BOSMINER_REGISTRY_WRAP_ADD168_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_WRAP_STR1A8_VA,
            BOSMINER_REGISTRY_WRAP_STR1A8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_1E9_MOVZ_VA,
            BOSMINER_REGISTRY_1E9_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_REGISTRY_1E9_MOVK_VA,
            BOSMINER_REGISTRY_1E9_MOVK_INSN,
        );
        assert!(admit_bosminer_plus230_is_ctx_ptr_and_1a8_wrap_fields(&prep_blob).is_ok());
        assert!(refuse_plus230_as_vtable_or_1a8_end_as_interior().is_err());
        assert_eq!(
            BOSMINER_C8_FUTURE_OFF_BM1366 + BOSMINER_WORKER_NEW_ARG1_C8,
            BOSMINER_C8_FUT_PLUS_C8_BM1366
        );
        assert_eq!(
            BOSMINER_C8_FUTURE_OFF_BM136X + BOSMINER_WORKER_NEW_ARG1_C8,
            BOSMINER_C8_FUT_PLUS_C8_BM136X
        );
        assert_eq!(
            BOSMINER_C8_FUTURE_OFF_BM1397 + BOSMINER_WORKER_NEW_ARG1_C8,
            BOSMINER_C8_FUT_PLUS_C8_BM1397
        );
        assert_eq!(BOSMINER_REGISTRY_WRAP_LINE, 109);
        assert_eq!(BOSMINER_REGISTRY_1A8_OFF_110, 0x110);
        assert_eq!(BOSMINER_REGISTRY_1A8_OFF_118, 0x118);
        assert_eq!(BOSMINER_REGISTRY_1A8_OFF_168, 0x168);
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_MOVZ10_VA,
            BOSMINER_HC_PLUS230_MOVZ10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_STR_VA,
            BOSMINER_HC_PLUS230_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS238_ZERO_VA,
            BOSMINER_HC_PLUS238_ZERO_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS240_STR_VA,
            BOSMINER_HC_PLUS240_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS240_MOVK_VA,
            BOSMINER_HC_PLUS240_MOVK_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS258_SELF_VA,
            BOSMINER_HC_PLUS258_SELF_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_LOC_ADD_VA,
            BOSMINER_HC_PLUS230_LOC_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_SIMD_118_LDP_VA,
            BOSMINER_WRAP_SIMD_118_LDP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_SIMD_118_STP_VA,
            BOSMINER_WRAP_SIMD_118_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_SIMD_168_LDP_VA,
            BOSMINER_WRAP_SIMD_168_LDP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_SIMD_168_STP_VA,
            BOSMINER_WRAP_SIMD_168_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WRAP_STP158_VA,
            BOSMINER_WRAP_STP158_INSN,
        );
        assert!(admit_bosminer_plus230_init_usize10_and_wrap_simd(&prep_blob).is_ok());
        assert!(refuse_plus230_as_named_io_ptr_or_168_as_registry_new().is_err());
        assert_eq!(BOSMINER_HC_PLUS230_INIT_LINE, 323);
        assert_eq!(BOSMINER_HC_PLUS230_INIT_VALUE, 0x10);
        assert_eq!(BOSMINER_HC_PLUS240_1E8, 0x05F5_E100);
        assert_eq!(BOSMINER_WRAP_SIMD_118_LEN, 32);
        assert_eq!(BOSMINER_WRAP_SIMD_168_LEN, 32);
        assert_eq!(BOSMINER_WRAP_STP158_LEN, 16);
        putp(
            &mut prep_blob,
            BOSMINER_POLL_FUT0_LDR_VA,
            BOSMINER_POLL_FUT0_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_FUT8_STR_VA,
            BOSMINER_POLL_FUT8_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_STATE_LDRB_VA,
            BOSMINER_POLL_STATE_LDRB_INSN,
        );
        assert!(admit_bosminer_poll_230_is_hc_usize10_and_188_unwritten(&prep_blob).is_ok());
        assert!(refuse_poll_230_as_heap_ptr_projection().is_err());
        assert_eq!(BOSMINER_POLL_230_PLUS10_SUM, 0x20);
        assert_eq!(BOSMINER_WRAP_1A8_UNWRITTEN_OFF, 0x188);
        assert_eq!(BOSMINER_WRAP_1A8_UNWRITTEN_LEN, 32);
        assert_eq!(
            BOSMINER_REGISTRY_1A8_OFF_168 as usize + BOSMINER_WRAP_SIMD_168_LEN,
            BOSMINER_WRAP_1A8_UNWRITTEN_OFF as usize
        );
        assert_eq!(BOSMINER_POLL_STATE_OFF, 0x2A);
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_NOW_BL_VA,
            BOSMINER_C0D4AC_NOW_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_STR8_VA,
            BOSMINER_C0D4AC_STR8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_STR18_VA,
            BOSMINER_C0D4AC_STR18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_STR30_VA,
            BOSMINER_C0D4AC_STR30_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_STP20_VA,
            BOSMINER_C0D4AC_STP20_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SYSNOW_W0_VA,
            BOSMINER_SYSNOW_W0_INSN,
        );
        putp(&mut prep_blob, BOSMINER_SYSNOW_B_VA, BOSMINER_SYSNOW_B_INSN);
        putp(
            &mut prep_blob,
            BOSMINER_TIMESPEC_1E9_MOVZ_VA,
            BOSMINER_TIMESPEC_1E9_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_TIMESPEC_1E9_MOVK_VA,
            BOSMINER_TIMESPEC_1E9_MOVK_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_DURATION_NEW_1E9_MOVZ_VA,
            BOSMINER_DURATION_NEW_1E9_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_DURATION_NEW_1E9_MOVK_VA,
            BOSMINER_DURATION_NEW_1E9_MOVK_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_DURATION_NEW_STR10_VA,
            BOSMINER_DURATION_NEW_STR10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS260_MOVZ_VA,
            BOSMINER_HC_PLUS260_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS260_RET_VA,
            BOSMINER_HC_PLUS260_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS260_STR_VA,
            BOSMINER_HC_PLUS260_STR_INSN,
        );
        assert!(admit_bosminer_230_usize_not_time_and_168_is_now_scale_prefix(&prep_blob).is_ok());
        assert!(refuse_230_or_168_as_instant_or_duration().is_err());
        assert_eq!(BOSMINER_NANOS_PER_SEC, 1_000_000_000);
        assert_eq!(BOSMINER_CLOCK_REALTIME, 0);
        assert_eq!(BOSMINER_DURATION_NEW_LINE, 201);
        assert_eq!(BOSMINER_TIMESPEC_NOW_LINE_137, 137);
        assert_eq!(BOSMINER_C0D4AC_NOW_OFF, 0x28);
        assert!(BOSMINER_C0D4AC_NOW_OFF as usize >= BOSMINER_WRAP_SIMD_168_LEN);
        assert_eq!(BOSMINER_DURATION_NEW_BL_HITS, 8);
        assert_eq!(BOSMINER_HC_PLUS260_FN_VA, 0x0089_B720);
        assert_eq!(BOSMINER_INVALID_TIMESTAMP_MSG.len(), 17);
        assert!(BOSMINER_UNIX_TIME_RS.ends_with("unix/time.rs"));
        assert!(BOSMINER_CORE_TIME_RS.ends_with("core/src/time.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_FPGA_ADD_C8_VA,
            BOSMINER_C0D4AC_FPGA_ADD_C8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_FPGA_BL0_VA,
            BOSMINER_C0D4AC_FPGA_BL0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_FPGA_ADD_230_VA,
            BOSMINER_C0D4AC_FPGA_ADD_230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D478_FPGA_BL_VA,
            BOSMINER_C0D478_FPGA_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_UART_BL0_VA,
            BOSMINER_C0D4AC_UART_BL0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_WRAP_ADD230_VA,
            BOSMINER_C0D4AC_WRAP_ADD230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_WRAP_BL0_VA,
            BOSMINER_C0D4AC_WRAP_BL0_INSN,
        );
        assert!(admit_bosminer_c0d4ac_is_48_and_37_split_fpga_uart_wrap(&prep_blob).is_ok());
        assert!(refuse_168_as_full_c0d4ac_or_fpga_as_uart_only().is_err());
        assert_eq!(BOSMINER_C0D4AC_SIZE, 0x48);
        assert_eq!(BOSMINER_C0D4AC_BL_HITS, 37);
        assert_eq!(BOSMINER_C0D4AC_FPGA_HITS, 6);
        assert_eq!(BOSMINER_C0D4AC_UART_HITS, 25);
        assert_eq!(BOSMINER_C0D4AC_WRAP_HITS, 6);
        assert_eq!(
            BOSMINER_C0D4AC_FPGA_SECOND_DEST - BOSMINER_C0D4AC_FPGA_FIRST_DEST,
            BOSMINER_C0D4AC_SIZE
        );
        assert!(BOSMINER_WRAP_SIMD_168_LEN < BOSMINER_C0D4AC_SIZE as usize);
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_FPGA_HOST_VA,
            BOSMINER_C0D4AC_FPGA_HOST_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4AC_FPGA_HOST_SUB_VA,
            BOSMINER_C0D4AC_FPGA_HOST_SUB_INSN,
        );
        assert!(admit_bosminer_c0d4ac_is_now_scale_cell_not_timespec(&prep_blob).is_ok());
        assert!(refuse_c0d4ac_or_plus230_as_timespec_size().is_err());
        assert_eq!(BOSMINER_TIMESPEC_SIZE, 16);
        assert_ne!(BOSMINER_C0D4AC_SIZE, BOSMINER_TIMESPEC_SIZE);
        assert_eq!(BOSMINER_C0D4AC_UART_WORKER_LINE, 68);
        assert_eq!(BOSMINER_C0D4AC_FPGA_HOST_VA, BOSMINER_FPGA_DIV_CALLER_VA);
        assert_eq!(BOSMINER_HC_PLUS230_INIT_VALUE, BOSMINER_TIMESPEC_SIZE);
        assert_eq!(BOSMINER_POLL_230_PLUS10_SUM, BOSMINER_TIMESPEC_SIZE * 2);
        assert!(BOSMINER_C0D4AC_UART_WORKER_RS.ends_with("worker.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_NESTED_CMD_ADRP_VA,
            BOSMINER_HC_PLUS230_NESTED_CMD_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_NESTED_CMD_ADD_VA,
            BOSMINER_HC_PLUS230_NESTED_CMD_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_NESTED_CMD_BL_VA,
            BOSMINER_HC_PLUS230_NESTED_CMD_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_METRICS_223_ADRP_VA,
            BOSMINER_METRICS_223_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_METRICS_223_ADD_VA,
            BOSMINER_METRICS_223_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_METRICS_223_BL_VA,
            BOSMINER_METRICS_223_BL_INSN,
        );
        assert!(
            admit_bosminer_230_owner_nests_command_647_and_48_not_stop_watch(&prep_blob).is_ok()
        );
        assert!(refuse_c0d4ac_as_metrics_stop_watch_or_hashes_time_mean().is_err());
        assert_eq!(BOSMINER_HC_PLUS230_NESTED_CMD_LINE, 647);
        assert_eq!(BOSMINER_METRICS_223_LINE, 223);
        assert_eq!(BOSMINER_HASHES_TIME_MEAN_ELEMENTS, 2);
        assert_ne!(
            BOSMINER_METRICS_223_BL_TGT,
            BOSMINER_REGISTRY_1E9_INIT_FN_VA
        );
        assert!(BOSMINER_METRICS_RS.ends_with("metrics.rs"));
        assert_eq!(BOSMINER_METRICS_STOP_WATCH, "stop_watch");
        assert!(BOSMINER_HC_PLUS230_NESTED_CMD_RS.ends_with("command.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_WORKPAIR_110_ADRP_VA,
            BOSMINER_WORKPAIR_110_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKPAIR_110_ADD_VA,
            BOSMINER_WORKPAIR_110_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORKPAIR_RET_VA,
            BOSMINER_WORKPAIR_RET_INSN,
        );
        putp(&mut prep_blob, BOSMINER_WRAP_FN_START_VA, 0xA9BA_7BFD);
        putp(
            &mut prep_blob,
            BOSMINER_C0D4E0_SWAP_FN_VA,
            BOSMINER_C0D4E0_LDRB_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_C0D4E0_BL_VA,
            BOSMINER_C0D4E0_BL_INSN,
        );
        assert!(admit_bosminer_c0d4ac_is_copy_and_workpair_is_wrap_sibling(&prep_blob).is_ok());
        assert!(refuse_c0d4ac_as_workpair_or_named_from_drop_glue().is_err());
        assert!(BOSMINER_C0D4AC_IS_COPY);
        assert_eq!(BOSMINER_DROP_IN_PLACE_HITS, 0);
        assert_eq!(BOSMINER_WORKPAIR_C0D4AC_BL_HITS, 0);
        assert_eq!(BOSMINER_WORKPAIR_LINE_110, 110);
        assert!(BOSMINER_WORKPAIR_RS.ends_with("workpair.rs"));
        assert_eq!(BOSMINER_C0D4E0_BL_HITS, 1);
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_X10_FROM_X19_VA,
            BOSMINER_HC_PLUS230_X10_FROM_X19_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_RET_VA,
            BOSMINER_HC_PLUS230_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_JUMP_TABLE_BR_VA,
            BOSMINER_JUMP_TABLE_BR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_LDR238_VA,
            BOSMINER_HC_PLUS230_CONSUMER_LDR238_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_LDR230_VA,
            BOSMINER_HC_PLUS230_CONSUMER_LDR230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_VT40_VA,
            BOSMINER_HC_PLUS230_CONSUMER_VT40_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_BLR_VA,
            BOSMINER_HC_PLUS230_CONSUMER_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_FUT40_STR_VA,
            BOSMINER_POLL_FUT40_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_TICKET_ADRP_VA,
            BOSMINER_HASHCHAIN_TICKET_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_TICKET_ADD_VA,
            BOSMINER_HASHCHAIN_TICKET_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHCHAIN_TICKET_BL_VA,
            BOSMINER_HASHCHAIN_TICKET_BL_INSN,
        );
        assert!(admit_bosminer_230_is_vt40_x0_and_poll_stores_fut40(&prep_blob).is_ok());
        assert!(refuse_230_as_ticket_mask_or_work_time_or_poll_mutating_hc().is_err());
        assert_eq!(BOSMINER_HASHCHAIN_TICKET_LINE, 298);
        assert_eq!(BOSMINER_HASHCHAIN_TICKET_COL, 9);
        assert_eq!(BOSMINER_POLL_FUT40_OFF, 0x40);
        assert_eq!(BOSMINER_HC_PLUS230_VT_OFF, 0x40);
        assert!(BOSMINER_HC_PLUS230_RET_VA < BOSMINER_HC_PLUS230_LOC_ADD_VA);
        assert!(BOSMINER_HASHCHAIN_TICKET_ADRP_VA > BOSMINER_HC_PLUS230_CONSUMER_BLR_VA);
        assert_eq!(BOSMINER_C8_FUT10_STR_VA, BOSMINER_POLL_FUT40_STR_VA);
        assert!(BOSMINER_HASHCHAIN_TICKET_LOG.contains("ticket mask"));
        putp(&mut prep_blob, BOSMINER_FAT_BLR_VA, BOSMINER_FAT_BLR_INSN);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_MOV_X24_X0_VA,
            BOSMINER_FAT_MOV_X24_X0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_MOV_X23_X1_VA,
            BOSMINER_FAT_MOV_X23_X1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CLONE_MEMCPY_MOVZ_VA,
            BOSMINER_CLONE_MEMCPY_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CLONE_MEMCPY_BL_VA,
            BOSMINER_CLONE_MEMCPY_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CLONE_MEMCPY_FN_VA,
            BOSMINER_CLONE_MEMCPY_ENTRY_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_PAIR_STR230_VA,
            BOSMINER_FAT_PAIR_STR230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_PAIR_STR238_VA,
            BOSMINER_FAT_PAIR_STR238_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_28_LDR_VA,
            BOSMINER_VT_SLOT_28_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_30_LDR_VA,
            BOSMINER_VT_SLOT_30_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_38_LDR_VA,
            BOSMINER_VT_SLOT_38_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_48_LDR_VA,
            BOSMINER_VT_SLOT_48_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_50_LDR_VA,
            BOSMINER_VT_SLOT_50_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_78_LDR_VA,
            BOSMINER_VT_SLOT_78_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CMD_472_ADRP_VA,
            BOSMINER_CMD_472_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CMD_472_ADD_VA,
            BOSMINER_CMD_472_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_SHUFFLE_STR238_VA,
            BOSMINER_FUTURE_SHUFFLE_STR238_INSN,
        );
        assert!(admit_bosminer_238_is_fat_vtable_and_clone_installs_pair(&prep_blob).is_ok());
        assert!(refuse_238_as_single_callback_or_x0_as_construct_usize10().is_err());
        assert_eq!(BOSMINER_FAT_VT_SLOT_HITS, 7);
        assert_eq!(BOSMINER_CLONE_MEMCPY_SIZE, 0x230);
        assert_eq!(BOSMINER_CMD_472_LINE, 472);
        assert_eq!(BOSMINER_FAT_VT_SLOTS[3], 0x40);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_X1_LDR_VA,
            BOSMINER_FAT_SLOT30_X1_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_SRET_ADD_VA,
            BOSMINER_FAT_SLOT50_SRET_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_STP_VA,
            BOSMINER_FAT_STP_28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT40_STP_VA,
            BOSMINER_FAT_STP_28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_STP_VA,
            BOSMINER_FAT_STP_40_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_PACK_ADRP_VA,
            BOSMINER_FAT_SLOT28_PACK_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_PACK_ADD_VA,
            BOSMINER_FAT_SLOT28_PACK_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_336_ADRP_VA,
            BOSMINER_FAT_SLOT78_336_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_336_ADD_VA,
            BOSMINER_FAT_SLOT78_336_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CMD_119_ADRP_VA,
            BOSMINER_CMD_119_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CMD_119_ADD_VA,
            BOSMINER_CMD_119_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_WORK_RESP_DIV_FN_VA,
            BOSMINER_WORK_RESP_DIV_LDR_INSN,
        );
        assert!(admit_bosminer_fat_slots_pair_sret_and_cmd119_is_div(&prep_blob).is_ok());
        assert!(refuse_fat_slots_as_named_hashchip_methods().is_err());
        assert_eq!(BOSMINER_FAT_PAIR_RETURN_HITS, 6);
        assert_eq!(BOSMINER_FAT_SRET_HITS, 1);
        assert_eq!(BOSMINER_CMD_119_LINE, 119);
        assert_eq!(BOSMINER_HASHCHAIN_336_LINE, 336);
        assert_eq!(BOSMINER_HAL_COMMAND_MODULE, "bosminer_hal::command");
        assert_eq!(BOSMINER_HASHCHIP_LABEL, "Hashchip:");
        assert_eq!(BOSMINER_TUNER_WRITE_REG, "write_reg");
        assert!(BOSMINER_CMD_119_ADRP_VA < BOSMINER_WORK_RESP_DIV_FN_VA);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_PAIR_RELOAD28_VA,
            BOSMINER_FAT_PAIR_RELOAD28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_PAIR_RELOAD58_VA,
            BOSMINER_FAT_PAIR_RELOAD58_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_JOIN_B_VA,
            BOSMINER_FAT_SLOT28_JOIN_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT40_JOIN_B_VA,
            BOSMINER_FAT_SLOT40_JOIN_B_INSN,
        );
        for &va in &BOSMINER_DYN_FUT_POLL_VAS {
            putp(&mut prep_blob, va, BOSMINER_DYN_FUT_POLL18_INSN);
            if va == 0x0083_6F64 {
                putp(&mut prep_blob, va + 8, BOSMINER_DYN_FUT_SRET_INSN);
                putp(&mut prep_blob, va + 12, BOSMINER_DYN_FUT_CX_MOV_INSN);
                putp(&mut prep_blob, va + 16, BOSMINER_DYN_FUT_BLR_INSN);
            } else {
                putp(&mut prep_blob, va + 4, BOSMINER_DYN_FUT_SRET_INSN);
                putp(&mut prep_blob, va + 8, BOSMINER_DYN_FUT_CX_MOV_INSN);
                putp(&mut prep_blob, va + 12, BOSMINER_DYN_FUT_BLR_INSN);
            }
        }
        assert!(admit_bosminer_fat_pairs_are_dyn_future_poll18_not_cmd700(&prep_blob).is_ok());
        assert!(refuse_fat_pairs_as_result_or_cmd700_poll().is_err());
        assert_eq!(BOSMINER_JUMP_TABLE_CMD700_BL_HITS, 0);
        assert_eq!(BOSMINER_DYN_FUT_POLL_HITS, 6);
        assert_eq!(BOSMINER_DYN_FUT_POLL18_OFF, 0x18);
        assert_eq!(BOSMINER_C8_POLL_BL_HITS, 6);
        assert_eq!(BOSMINER_C8_POLL_FN_VA, 0x008D_684C);
        for &va in &BOSMINER_C8_POLL_BL_VAS {
            assert!(!(0x0083_6000..0x0083_A000).contains(&va));
        }
        for &va in &BOSMINER_POLL_LDR160_VAS {
            let insn = if va == 0x0083_7590 || va == 0x0083_7684 {
                BOSMINER_POLL_LDR160_X24_INSN
            } else {
                BOSMINER_POLL_LDR160_X27_INSN
            };
            putp(&mut prep_blob, va, insn);
            let cmp = if va == 0x0083_7590 || va == 0x0083_7684 {
                BOSMINER_POLL_CMP9_X24_INSN
            } else {
                BOSMINER_POLL_CMP9_X27_INSN
            };
            putp(&mut prep_blob, va + 4, cmp);
        }
        putp(
            &mut prep_blob,
            BOSMINER_POLL_T168_VA,
            BOSMINER_POLL_T168_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_T170_VA,
            BOSMINER_POLL_T170_Q_INSN,
        );
        putp(
            &mut prep_blob,
            0x0083_6F84,
            BOSMINER_POLL_PENDING_MOVZ9_INSN,
        );
        assert!(admit_bosminer_poll_sret20_pending9_t_at_168(&prep_blob).is_ok());
        assert!(refuse_poll_unit_or_pending0_or_named_slot_methods().is_err());
        assert_eq!(BOSMINER_POLL_PENDING_TAG, 9);
        assert_eq!(BOSMINER_POLL_SRET_SIZE, 0x20);
        assert_eq!(BOSMINER_POLL_T_LEN, 0x18);
        assert_eq!(BOSMINER_POLL_CMP9_HITS, 6);
        assert_eq!(BOSMINER_FAT_SLOT_PRE_BLR_LOC_HITS, 0);
        putp(
            &mut prep_blob,
            BOSMINER_POLL_PENDING_STR_X28_VA,
            BOSMINER_POLL_PENDING_STR_X28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_PENDING_MOVZ8_VA,
            BOSMINER_POLL_PENDING_MOVZ8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_PENDING_B_SUSPEND_VA,
            BOSMINER_POLL_PENDING_B_SUSPEND_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_SUSPEND_VA,
            BOSMINER_POLL_SUSPEND_STRB_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_SUSPEND_ADDSP_VA,
            BOSMINER_POLL_SUSPEND_ADDSP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_SUSPEND_RET_VA,
            BOSMINER_POLL_SUSPEND_RET_INSN,
        );
        for &va in &BOSMINER_POLL_CMP8_VAS {
            let insn = if va == 0x0083_7600 || va == 0x0083_76DC {
                BOSMINER_POLL_CMP8_X24_INSN
            } else {
                BOSMINER_POLL_CMP8_X27_INSN
            };
            putp(&mut prep_blob, va, insn);
        }
        putp(
            &mut prep_blob,
            BOSMINER_POLL_READY28_BNE_VA,
            BOSMINER_POLL_READY28_BNE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_ERR_JOIN_VA,
            BOSMINER_POLL_ERR_JOIN_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_ERR_JOIN_B_VA,
            BOSMINER_POLL_ERR_JOIN_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_ERR_PACK_VA,
            BOSMINER_POLL_ERR_PACK_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_ERR_PACK_MOVZ1_VA,
            BOSMINER_POLL_ERR_PACK_MOVZ1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_ERR_PACK_STRQ_VA,
            BOSMINER_POLL_ERR_PACK_STRQ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_ERR_PACK_B_VA,
            BOSMINER_POLL_ERR_PACK_B_INSN,
        );
        assert!(admit_bosminer_poll_tag8_ok_tag9_pending_ret(&prep_blob).is_ok());
        assert!(refuse_pending9_as_unknown_or_named_slot_methods().is_err());
        assert_eq!(BOSMINER_POLL_READY_OK_TAG, 8);
        assert_eq!(s19k_bosminer_poll_word0_arm(8), "ready_ok_continue");
        assert_eq!(s19k_bosminer_poll_word0_arm(9), "pending_return");
        assert_eq!(s19k_bosminer_poll_word0_arm(1), "ready_other_return");
        assert_eq!(BOSMINER_POLL_CMP8_HITS, 7);
        assert_eq!(BOSMINER_POLL_SUSPEND_STATE_OFF, 0x21);
        assert_eq!(BOSMINER_CMD_LOC_LINE_HITS, 27);
        assert_eq!(BOSMINER_CMD_LOC_RECORD_HITS, 104);
        assert_eq!(BOSMINER_CMD_EVENT_LINES, [594, 621, 656, 675]);
        putp(
            &mut prep_blob,
            BOSMINER_SLOT28_PRELUDE_MOVZ8_VA,
            BOSMINER_SLOT28_PRELUDE_MOVZ8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SLOT28_PRELUDE_BL_VA,
            BOSMINER_SLOT28_PRELUDE_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_POLL_CMP8_PRELUDE_VA,
            BOSMINER_POLL_CMP8_X27_INSN,
        );
        assert!(admit_bosminer_cmp8_six_post_poll_one_slot28_prelude(&prep_blob).is_ok());
        assert!(refuse_seventh_cmp8_as_seventh_poll_or_named_slot28().is_err());
        assert_eq!(BOSMINER_POLL_CMP8_POST_POLL_HITS, 6);
        assert_eq!(BOSMINER_POLL_CMP8_PRELUDE_HITS, 1);
        assert_eq!(BOSMINER_SLOT28_PRELUDE_BL_TARGET, 0x0083_1314);
        assert_eq!(BOSMINER_CMD_PANIC_PAD_LINES, [418, 514, 693, 719]);
        assert_eq!(
            BOSMINER_VT_SLOT_28_LDR_VA - BOSMINER_POLL_CMP8_PRELUDE_VA,
            0x14
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_VA,
            BOSMINER_FN831314_ENTRY_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_STP_VA,
            BOSMINER_FN831314_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_LDRB10_VA,
            BOSMINER_FN831314_LDRB10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_CMP4_VA,
            BOSMINER_FN831314_CMP4_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_CMP3_VA,
            BOSMINER_FN831314_CMP3_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_TAG46_ADD40_VA,
            BOSMINER_FN831314_TAG46_ADD40_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_TAG46_B_VA,
            BOSMINER_FN831314_TAG46_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_TAG5_ADD18_VA,
            BOSMINER_FN831314_TAG5_ADD18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_RET_VA,
            BOSMINER_FN831314_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_BL_VAS[0] - 4,
            BOSMINER_FN831314_MOV_X0_X22_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_BL_VAS[1],
            BOSMINER_FN831314_BL2_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN831314_MOV2_VA,
            BOSMINER_FN831314_MOV_X0_X22_INSN,
        );
        assert!(admit_bosminer_831314_is_tag10_drop_dispatcher(&prep_blob).is_ok());
        assert!(refuse_831314_as_slot28_method_or_named_maybedone().is_err());
        assert_eq!(BOSMINER_FN831314_BL_HITS, 2);
        assert_eq!(BOSMINER_FN831314_TAG_OFF, 0x10);
        assert_eq!(s19k_bosminer_831314_tag_arm(3), "drop_pair_at_18");
        assert_eq!(s19k_bosminer_831314_tag_arm(5), "tail_831668_plus18");
        assert_eq!(BOSMINER_FN831314_BODY_LOC_HITS, 0);
        for &(base, ldrb, ldp, ldr, blh, ret) in &[
            (
                BOSMINER_FN831D18_VA,
                BOSMINER_FN831D18_LDRB_INSN,
                BOSMINER_FN831D18_LDP_INSN,
                BOSMINER_FN831D18_LDR0_INSN,
                BOSMINER_FN831D18_BL_HELPER_INSN,
                BOSMINER_FN831D18_RET_VA,
            ),
            (
                BOSMINER_FN831668_VA,
                BOSMINER_FN831668_LDRB_INSN,
                BOSMINER_FN831668_LDP_INSN,
                BOSMINER_FN831668_LDR68_INSN,
                BOSMINER_FN831668_BL_HELPER_INSN,
                BOSMINER_FN831668_RET_VA,
            ),
        ] {
            putp(&mut prep_blob, base, BOSMINER_DROP_SIB_ENTRY_INSN);
            putp(&mut prep_blob, base + 8, ldrb);
            putp(&mut prep_blob, base + 0x10, BOSMINER_DROP_SIB_CMP3_INSN);
            putp(&mut prep_blob, base + 0x18, BOSMINER_DROP_SIB_CMP4_INSN);
            putp(&mut prep_blob, base + 0x20, ldp);
            putp(&mut prep_blob, base + 0x48, ldr);
            putp(&mut prep_blob, base + 0x4C, BOSMINER_DROP_SIB_MOVZ1_INSN);
            putp(&mut prep_blob, base + 0x50, blh);
            putp(&mut prep_blob, ret, 0xD65F_03C0);
        }
        for &va in &BOSMINER_FN831D18_HC68_VAS {
            putp(&mut prep_blob, va - 4, BOSMINER_FN831D18_HC68_ADD_INSN);
        }
        assert!(admit_bosminer_831d18_831668_are_drop_siblings(&prep_blob).is_ok());
        assert!(refuse_drop_sibs_as_one_fn_or_named_slot_or_arc().is_err());
        assert_eq!(
            s19k_bosminer_drop_sib_tag_off(BOSMINER_FN831D18_VA),
            Some(0x19)
        );
        assert_eq!(
            s19k_bosminer_drop_sib_tag_off(BOSMINER_FN831668_VA),
            Some(0x70)
        );
        assert_eq!(BOSMINER_FN831D18_BL_HITS, 12);
        assert_eq!(BOSMINER_FN831668_BL_HITS, 6);
        assert_eq!(BOSMINER_FN831D18_HC68_HITS, 4);
        assert_eq!(BOSMINER_DROP_SIB_BODY_LOC_HITS, 0);
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_VA,
            BOSMINER_FN11F2764_CBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_LDXR_VA,
            BOSMINER_FN11F2764_LDXR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_CBNZ0_VA,
            BOSMINER_FN11F2764_CBNZ0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_STXR1_VA,
            BOSMINER_FN11F2764_STXR1_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_STXR_VA,
            BOSMINER_FN11F2764_STXR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_RET_VA,
            BOSMINER_FN11F2764_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_OVF_MOVZ_VA,
            BOSMINER_FN11F2764_OVF_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_OVF_MOVK_VA,
            BOSMINER_FN11F2764_OVF_MOVK_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_OVF_BL_VA,
            BOSMINER_FN11F2764_OVF_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_JT_PLUS68_SRC240_VA,
            BOSMINER_JT_PLUS68_SRC240_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_JT_PLUS68_ADD10_VA,
            BOSMINER_JT_PLUS68_ADD10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_JT_PLUS68_STR_VA,
            BOSMINER_JT_PLUS68_STR_INSN,
        );
        assert!(admit_bosminer_11f2764_is_refcount_helper_jt68_from_240(&prep_blob).is_ok());
        assert!(refuse_11f2764_as_named_arc_or_jt68_as_hashchain().is_err());
        assert_eq!(s19k_bosminer_refcount_overflow_cap(), 1_000_000_000);
        assert_eq!(BOSMINER_FN11F2764_BL_HITS, 557);
        assert_eq!(BOSMINER_FN11F2764_MOVZ1_PREV_HITS, 537);
        assert_eq!(BOSMINER_FN11F26F8_TO_764_DELTA, 0x6C);
        assert_eq!(BOSMINER_JT_PLUS108_OFF, 0x108);
        assert!(BOSMINER_REFCOUNT_OVERFLOW_MSG.contains("overflow"));
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_VA,
            BOSMINER_FN121E588_ENTRY_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_MOV_X19_VA,
            BOSMINER_FN121E588_MOV_X19_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_MOVZ_VA,
            BOSMINER_FN121E588_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_MOVK_VA,
            BOSMINER_FN121E588_MOVK_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_MRS_VA,
            BOSMINER_FN121E588_MRS_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_ADD_VA,
            BOSMINER_FN121E588_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_LDR_VA,
            BOSMINER_FN121E588_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_CMP1_VA,
            BOSMINER_FN121E588_CMP1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_CMP2_VA,
            BOSMINER_FN121E588_CMP2_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PARK_1226_ADRP_VA,
            BOSMINER_PARK_1226_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_PARK_1226_ADD_VA,
            BOSMINER_PARK_1226_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN121E588_RET_VA,
            BOSMINER_FN121E588_RET_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FN11F2764_TLS_BL_VA,
            BOSMINER_FN11F2764_TLS_BL_INSN,
        );
        assert!(admit_bosminer_121e588_is_parking_lot_tls(&prep_blob).is_ok());
        assert!(refuse_121e588_as_arc_inc_or_drop().is_err());
        assert_eq!(s19k_bosminer_121e588_tls_off(), 0x280);
        assert_eq!(BOSMINER_FN121E588_BL_HITS, 681);
        assert_eq!(BOSMINER_PARK_1226_LINE, 1226);
        assert_eq!(BOSMINER_PARK_1226_COL, 58);
        assert!(BOSMINER_PARK_RS_SUFFIX.ends_with("parking_lot.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_SELF_LDR_VA,
            BOSMINER_FAT_SLOT28_SELF_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_VT_LDR_VA,
            BOSMINER_FAT_SLOT28_VT_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_DATA_LDR_VA,
            BOSMINER_FAT_SLOT28_DATA_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_28_LDR_VA,
            BOSMINER_VT_SLOT_28_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_BLR_VA,
            BOSMINER_FAT_SLOT28_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_STP_VA,
            BOSMINER_FAT_STP_28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT28_JOIN_B_VA,
            BOSMINER_FAT_SLOT28_JOIN_B_INSN,
        );
        assert!(admit_bosminer_slot28_is_zero_arg_fat_future(&prep_blob).is_ok());
        assert!(refuse_slot28_as_named_command_or_packing().is_err());
        assert!(!s19k_bosminer_slot28_extra_x1());
        assert_eq!(BOSMINER_FAT_SLOT28_PATTERN_HITS, 1);
        assert_eq!(BOSMINER_FAT_SLOT28_X1_WRITES, 0);
        assert_eq!(BOSMINER_FAT_SLOT28_JOIN_TARGET, 0x0083_6F60);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_SELF_LDR_VA,
            BOSMINER_FAT_SLOT30_SELF_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_X1_LDR_VA,
            BOSMINER_FAT_SLOT30_X1_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_VT_LDR_VA,
            BOSMINER_FAT_SLOT30_VT_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_DATA_LDR_VA,
            BOSMINER_FAT_SLOT30_DATA_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_30_LDR_VA,
            BOSMINER_VT_SLOT_30_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_BLR_VA,
            BOSMINER_FAT_SLOT30_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_STP_VA,
            BOSMINER_FAT_STP_28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_JOIN_B_VA,
            BOSMINER_FAT_SLOT30_JOIN_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_JOIN_TARGET,
            BOSMINER_FAT_PAIR_RELOAD28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT30_OTHER_LDR30_VA,
            BOSMINER_FAT_SLOT30_OTHER_LDR30_INSN,
        );
        assert!(admit_bosminer_slot30_is_x1_arg_fat_future(&prep_blob).is_ok());
        assert!(refuse_slot30_as_named_send_work_or_other_ldr30().is_err());
        assert!(s19k_bosminer_slot30_extra_x1());
        assert_eq!(BOSMINER_FAT_SLOT30_PATTERN_HITS, 1);
        assert_eq!(BOSMINER_FAT_SLOT30_X1_WRITES, 1);
        assert_eq!(BOSMINER_FAT_SLOT30_JOIN_TARGET, 0x0083_7054);
        assert_eq!(BOSMINER_FAT_SLOT30_PRE_BLR_LOC_HITS, 0);
        putp(
            &mut prep_blob,
            BOSMINER_JT_POLL_CX_MOV_VA,
            BOSMINER_JT_POLL_CX_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_JT_POLL_X19_MOV_VA,
            BOSMINER_JT_POLL_X19_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_JUMP_TABLE_BR_VA,
            BOSMINER_JUMP_TABLE_BR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FRAME10_ERR_LDR_VA,
            BOSMINER_FRAME10_ERR_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FRAME10_ERR_B_VA,
            BOSMINER_FRAME10_ERR_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FRAME10_ERR_TARGET,
            BOSMINER_POLL_ERR_PACK_STP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_OBJ_STP10_VA,
            BOSMINER_HC_OBJ_STP10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_RET_VA,
            BOSMINER_HC_PLUS230_RET_INSN,
        );
        assert!(admit_bosminer_slot30_x1_is_poll_self_frame10(&prep_blob).is_ok());
        assert!(refuse_frame10_as_cmd700_future10_or_hashchain10().is_err());
        assert_eq!(s19k_bosminer_frame10_str_hits(), 0);
        assert_eq!(BOSMINER_FRAME10_STR_HITS, 0);
        assert_eq!(BOSMINER_FRAME10_ERR_TARGET, 0x0083_8CD8);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT38_SELF_LDR_VA,
            BOSMINER_FAT_SLOT38_SELF_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT38_PRE_X1_LDR_VA,
            BOSMINER_FAT_SLOT38_PRE_X1_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT38_VT_LDR_VA,
            BOSMINER_FAT_SLOT38_VT_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT38_DATA_LDR_VA,
            BOSMINER_FAT_SLOT38_DATA_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_38_LDR_VA,
            BOSMINER_VT_SLOT_38_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT38_BLR_VA,
            BOSMINER_FAT_SLOT38_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT38_STP_VA,
            BOSMINER_FAT_STP_58_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT38_POLL_VA,
            BOSMINER_DYN_FUT_POLL18_INSN,
        );
        assert!(admit_bosminer_slot38_is_zero_arg_family_b_fat_future(&prep_blob).is_ok());
        assert!(refuse_slot38_as_x1_sibling_or_named_command().is_err());
        assert!(!s19k_bosminer_slot38_extra_x1());
        assert_eq!(BOSMINER_FAT_SLOT38_PATTERN_HITS, 1);
        assert_eq!(BOSMINER_FAT_SLOT38_X1_WRITES, 0);
        assert_eq!(BOSMINER_FAT_SLOT38_POLL_VA, 0x0083_7674);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT40_SRC18_LDR_VA,
            BOSMINER_FAT_SLOT40_SRC18_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT40_COPY0_STR_VA,
            BOSMINER_FAT_SLOT40_COPY0_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_LDR238_VA,
            BOSMINER_HC_PLUS230_CONSUMER_LDR238_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_LDR230_VA,
            BOSMINER_HC_PLUS230_CONSUMER_LDR230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_VT40_VA,
            BOSMINER_HC_PLUS230_CONSUMER_VT40_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_CONSUMER_BLR_VA,
            BOSMINER_HC_PLUS230_CONSUMER_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT40_STP_VA,
            BOSMINER_FAT_STP_28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT40_JOIN_B_VA,
            BOSMINER_FAT_SLOT40_JOIN_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT40_JOIN_TARGET,
            BOSMINER_DYN_FUT_POLL18_INSN,
        );
        assert!(admit_bosminer_slot40_is_zero_arg_copy18_fat_future(&prep_blob).is_ok());
        assert!(refuse_slot40_as_sret50_or_x1_or_named_command().is_err());
        assert!(!s19k_bosminer_slot40_extra_x1());
        assert_eq!(BOSMINER_FAT_SLOT40_PATTERN_HITS, 1);
        assert_eq!(BOSMINER_FAT_SLOT48_PATTERN_HITS, 1);
        assert_eq!(BOSMINER_FAT_SLOT50_PATTERN_HITS, 0);
        assert_eq!(BOSMINER_FAT_SLOT78_PATTERN_HITS, 1);
        assert_eq!(BOSMINER_FAT_SLOT40_X1_WRITES, 0);
        assert_eq!(BOSMINER_FAT_SLOT40_JOIN_TARGET, 0x0083_6FE4);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_SELF_LDR_VA,
            BOSMINER_FAT_SLOT48_SELF_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_COPY28_STR_VA,
            BOSMINER_FAT_SLOT48_COPY28_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_COPY30_STR_VA,
            BOSMINER_FAT_SLOT48_COPY30_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_VT_LDR_VA,
            BOSMINER_FAT_SLOT48_VT_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_DATA_LDR_VA,
            BOSMINER_FAT_SLOT48_DATA_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_48_LDR_VA,
            BOSMINER_VT_SLOT_48_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_BLR_VA,
            BOSMINER_FAT_SLOT48_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_STP_VA,
            BOSMINER_FAT_STP_40_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT48_POLL_VA,
            BOSMINER_DYN_FUT_POLL18_INSN,
        );
        assert!(admit_bosminer_slot48_is_zero_arg_immediate_fat_future(&prep_blob).is_ok());
        assert!(refuse_slot48_as_copy18_or_named_command().is_err());
        assert!(!s19k_bosminer_slot48_extra_x1());
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_LDP_VA,
            BOSMINER_FAT_SLOT78_LDP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_VT_LDR_VA,
            BOSMINER_FAT_SLOT78_VT_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_DATA_LDR_VA,
            BOSMINER_FAT_SLOT78_DATA_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_78_LDR_VA,
            BOSMINER_VT_SLOT_78_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_BLR_VA,
            BOSMINER_FAT_SLOT78_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_STP_VA,
            BOSMINER_FAT_STP_58_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_JOIN_B_VA,
            BOSMINER_FAT_SLOT78_JOIN_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_JOIN_TARGET,
            BOSMINER_FAT_PAIR_RELOAD58_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT78_JOIN_TARGET + 4,
            BOSMINER_DYN_FUT_POLL18_INSN,
        );
        assert!(admit_bosminer_slot78_is_ldp_family_b_fat_future(&prep_blob).is_ok());
        assert!(refuse_slot78_as_slot30_or_named_hashchain_336().is_err());
        assert!(s19k_bosminer_slot78_extra_x1());
        putp(
            &mut prep_blob,
            BOSMINER_HC_INIT_PLUS18_LDR_VA,
            BOSMINER_HC_INIT_PLUS18_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS230_RET_VA,
            BOSMINER_HC_PLUS230_RET_INSN,
        );
        assert!(admit_bosminer_future18_is_construct_time_fat_host(&prep_blob).is_ok());
        assert!(refuse_future18_as_cmd700_or_named_hashchain_field().is_err());
        assert_eq!(s19k_bosminer_future18_jt_str_hits(), 0);
        assert_eq!(BOSMINER_FAT_SLOT48_POLL_VA, 0x0083_8638);
        assert_eq!(BOSMINER_FAT_SLOT78_JOIN_TARGET, 0x0083_757C);
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_CLONE_VA,
            BOSMINER_FUTURE_CLONE_ENTRY_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_CLONE_MOVZ188_VA,
            BOSMINER_FUTURE_CLONE_MOVZ188_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_CLONE_SRC_ADD_VA,
            BOSMINER_FUTURE_CLONE_SRC_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_CLONE_SIZE_MOVZ_VA,
            BOSMINER_FUTURE_CLONE_SIZE_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_CLONE_MEMCPY_BL_VA,
            BOSMINER_FUTURE_CLONE_MEMCPY_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_CLONE_VT_ADD_VA,
            BOSMINER_FUTURE_CLONE_VT_ADD_INSN,
        );
        assert!(admit_bosminer_future_clone_copies_sp8_and_returns_vtable(&prep_blob).is_ok());
        assert!(refuse_future_clone_as_91000c_or_named_stack_filler().is_err());
        assert_eq!(s19k_bosminer_future_clone_bl_hits(), 0);
        assert_eq!(BOSMINER_FUTURE_VT_SIZE, 0x188);
        assert_eq!(BOSMINER_FUTURE_VT_POLL, 0x0083_6E2C);
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_TMPL_X0_STR_VA,
            BOSMINER_FUTURE_TMPL_X0_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_TMPL_ST21_VA,
            BOSMINER_FUTURE_TMPL_ST21_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE_TMPL_ST22_VA,
            BOSMINER_FUTURE_TMPL_ST22_INSN,
        );
        assert!(admit_bosminer_clone_fills_sp8_x0_as_future18(&prep_blob).is_ok());
        assert!(refuse_sp8_filler_as_separate_fn_or_sib188().is_err());
        assert!(s19k_bosminer_clone_x0_is_future18());
        assert!(!s19k_bosminer_clone_writes_future10());
        assert_eq!(BOSMINER_OWNER260_SIZE, 0x260);
        assert_eq!(BOSMINER_SIB188_VT_ADD_IMM, 0x1A8);
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_MOV28_VA,
            BOSMINER_FAT_SLOT50_MOV28_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_LDR_PRE38_VA,
            BOSMINER_FAT_SLOT50_LDR_PRE38_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_LDUR_M8_VA,
            BOSMINER_FAT_SLOT50_LDUR_M8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_VT_SLOT_50_LDR_VA,
            BOSMINER_VT_SLOT_50_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_SRET_ADD_VA,
            BOSMINER_FAT_SLOT50_SRET_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_BLR_VA,
            BOSMINER_FAT_SLOT50_BLR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_LDP_VA,
            BOSMINER_FAT_SLOT50_LDP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_CMP0_VA,
            BOSMINER_FAT_SLOT50_CMP0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_PREV_CMP9_VA,
            BOSMINER_FAT_SLOT50_PREV_CMP9_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FAT_SLOT50_CONV_BL_VA,
            BOSMINER_FAT_SLOT50_CONV_BL_INSN,
        );
        assert!(admit_bosminer_slot50_is_sret_host30_x1_38(&prep_blob).is_ok());
        assert!(refuse_slot50_as_poll9_or_zero_arg_fat().is_err());
        assert!(s19k_bosminer_slot50_extra_x1());
        assert!(!s19k_bosminer_slot50_is_poll_tag9());
        assert_eq!(BOSMINER_FAT_SLOT50_PATTERN_HITS, 0);
        assert_eq!(BOSMINER_FAT_SLOT50_SRET_SIZE, 0x28);
        assert!(admit_bosminer_owner260_drop_has_fat230().is_ok());
        assert!(refuse_owner260_as_hashchain_or_named_hashboard().is_err());
        assert!(!s19k_bosminer_owner260_is_hashchain());
        assert_eq!(BOSMINER_OWNER260_DROP_FN_VA, 0x0087_3D10);
        assert_eq!(BOSMINER_OWNER260_BOXER_ADD_IMM, 0x798);
        putp(
            &mut prep_blob,
            BOSMINER_SLOT50_CONV_ARM2_ADD_VA,
            BOSMINER_SLOT50_CONV_ADD0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SLOT50_CONV_ARM2_BL_VA,
            BOSMINER_SLOT50_CONV_ARM2_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SLOT50_CONV_ARM3_ADD_VA,
            BOSMINER_SLOT50_CONV_ADD0_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SLOT50_CONV_ARM3_BL_VA,
            BOSMINER_SLOT50_CONV_ARM3_BL_INSN,
        );
        assert!(admit_bosminer_40c2c4_has_4_bls_three_jt160(&prep_blob).is_ok());
        assert!(refuse_40c2c4_as_named_from_backtrace().is_err());
        assert_eq!(s19k_bosminer_40c2c4_bl_hits(), 4);
        assert_eq!(BOSMINER_SLOT50_CONV_JT160_HITS, 3);
        assert_eq!(BOSMINER_BACKTRACE_HELPER_BL_HITS, 171);
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE10_SRC48_LDR_VA,
            BOSMINER_FUTURE10_SRC48_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE10_ALIAS_MOV_VA,
            BOSMINER_FUTURE10_ALIAS_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE10_STR_VA,
            BOSMINER_FUTURE10_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE10_NEST48_ADD_VA,
            BOSMINER_FUTURE10_NEST48_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE10_NEST48_X1_VA,
            BOSMINER_FUTURE10_NEST48_X1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE10_NEST48_BL_VA,
            BOSMINER_FUTURE10_NEST48_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE10_JOIN_B_VA,
            BOSMINER_FUTURE10_JOIN_B_INSN,
        );
        assert!(admit_bosminer_future10_writer_is_poll_copy48(&prep_blob).is_ok());
        assert!(refuse_future10_as_context_or_clone_template().is_err());
        assert_eq!(s19k_bosminer_future10_jt_str_x19_hits(), 0);
        assert!(!s19k_bosminer_future10_is_context());
        assert!(!s19k_bosminer_clone_writes_future10());
        assert_eq!(BOSMINER_FUTURE10_SRC48_OFF, 0x48);
        putp(
            &mut prep_blob,
            BOSMINER_MUTEX_LOCK_POLL_VA,
            BOSMINER_MUTEX_LOCK_POLL_ENTRY_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_MUTEX_LOCK_TAG70_LDRB_VA,
            BOSMINER_MUTEX_LOCK_TAG70_LDRB_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_MUTEX_LOCK_TAG70_STRB_VA,
            BOSMINER_MUTEX_LOCK_TAG70_STRB_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_MUTEX_LOCK_PAD_ADRP_VA,
            BOSMINER_MUTEX_LOCK_PAD_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_MUTEX_LOCK_PAD_ADD_VA,
            BOSMINER_MUTEX_LOCK_PAD_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_MUTEX_LOCK_PAD_BL_VA,
            BOSMINER_MUTEX_LOCK_PAD_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE48_STR_VA,
            BOSMINER_FUTURE48_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE48_SRC240_LDR_VA,
            BOSMINER_FUTURE48_SRC240_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE48_ADD10_VA,
            BOSMINER_FUTURE48_ADD10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FUTURE48_ADD18_VA,
            BOSMINER_FUTURE48_ADD18_INSN,
        );
        assert!(admit_bosminer_future48_is_tokio_mutex_lock(&prep_blob).is_ok());
        assert!(refuse_future48_as_fat_slot_or_c0d4ac_or_lock_owned().is_err());
        assert_eq!(s19k_bosminer_mutex_lock_poll_bl_hits(), 9);
        assert_eq!(BOSMINER_MUTEX_LOCK_LINE, 434);
        assert_eq!(BOSMINER_MUTEX_UNREACHABLE_LINE, 657);
        assert!(BOSMINER_MUTEX_RS_SUFFIX.ends_with("mutex.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_LDR_HOST_VA,
            BOSMINER_HOST240_LDR_HOST_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_LDR148_VA,
            BOSMINER_HOST240_LDR148_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_STR8_VA,
            BOSMINER_HOST240_STR8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS240_STR_VA,
            BOSMINER_HC_PLUS240_STR_INSN,
        );
        assert!(admit_bosminer_host240_is_70_ptr_mutex_at_28(&prep_blob).is_ok());
        assert!(refuse_host240_as_hashchain_1e8_or_as_mutex().is_err());
        assert!(!s19k_bosminer_host240_is_mutex());
        assert!(!s19k_bosminer_host240_is_hashchain());
        assert_eq!(s19k_bosminer_host240_jt_ldr_hits(), 12);
        assert_eq!(s19k_bosminer_host240_ctor70_str_hits(), 1);
        assert_eq!(BOSMINER_HOST240_BOX_SIZE, 0x70);
        assert_eq!(BOSMINER_HOST240_MUTEX_OFF, 0x28);
        assert_eq!(BOSMINER_HOST240_NULL_STR_INSN, 0xF901_227F);
        assert_eq!(BOSMINER_HOST240_DROP_ADD_INSN, 0x9109_0260);
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_ALT48_LDR_VA,
            BOSMINER_HOST240_ALT48_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_ALT48_ADD10_VA,
            BOSMINER_HOST240_ALT48_ADD10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_ALT48_STR_VA,
            BOSMINER_HOST240_ALT48_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_JT68_ADD10_VA,
            BOSMINER_HOST240_JT68_ADD10_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_JT68_STR_VA,
            BOSMINER_HOST240_JT68_STR_INSN,
        );
        assert!(admit_bosminer_host240_plus10_is_common_proj(&prep_blob).is_ok());
        assert!(refuse_mutex_start_as_plus28_or_named_arc().is_err());
        assert_eq!(s19k_bosminer_host240_add10_hits(), 12);
        assert_eq!(s19k_bosminer_host240_add18_hits(), 1);
        assert!(!s19k_bosminer_host248_is_arc());
        assert_eq!(BOSMINER_HOST248_OFF, 0x248);
        assert_eq!(BOSMINER_HOST248_DROP_TGT_VA, 0x0092_462C);
        assert!(admit_bosminer_9247b0_is_counted_fat_drop().is_ok());
        assert!(refuse_9247b0_as_mutex_or_named_vec().is_err());
        assert_eq!(s19k_bosminer_9247b0_bl_hits(), 4);
        assert!(!s19k_bosminer_9247b0_is_mutex_drop());
        assert_eq!(BOSMINER_9247B0_ADD10_CALLERS, 3);
        assert_eq!(BOSMINER_9247B0_LEN_OFF, 0x10);
        assert_eq!(BOSMINER_9247B0_PTR_OFF, 0x08);
        assert_eq!(BOSMINER_9247B0_STRIDE, 0x10);
        assert_eq!(BOSMINER_9247B0_FN_VA, BOSMINER_HOST248_DROP_BL_TGT);
        putp(
            &mut prep_blob,
            BOSMINER_92462C_JT_ADD_VA,
            BOSMINER_92462C_JT_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_92462C_JT_BL_VA,
            BOSMINER_92462C_JT_BL_INSN,
        );
        assert!(admit_bosminer_host248_inner_is_30_not_70(&prep_blob).is_ok());
        assert!(refuse_9247b0_elem_as_mutex_or_248_as_240().is_err());
        assert_eq!(s19k_bosminer_92462c_bl_hits(), 81);
        assert_eq!(s19k_bosminer_host248_inner_size(), 0x30);
        assert!(!s19k_bosminer_9247b0_elem_is_mutex());
        assert_ne!(BOSMINER_HOST240_BOX_SIZE, BOSMINER_HOST248_INNER_SIZE);
        assert_eq!(BOSMINER_92462C_JT_ADD_OFF, 0x270);
        putp(
            &mut prep_blob,
            BOSMINER_LOCK_POLL_SELF_LDR_VA,
            BOSMINER_LOCK_POLL_SELF_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_LOCK_POLL_SELF_STR18_VA,
            BOSMINER_LOCK_POLL_SELF_STR18_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_LOCK_POLL_ACQ_ADD_VA,
            BOSMINER_LOCK_POLL_ACQ_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_LOCK_POLL_ACQ_BL_VA,
            BOSMINER_LOCK_POLL_ACQ_BL_INSN,
        );
        assert!(admit_bosminer_mutex_starts_at_data18_and_248_t_is_20(&prep_blob).is_ok());
        assert!(refuse_mutex_at_data0_or_named_248_t().is_err());
        assert!(s19k_bosminer_mutex_self_is_stored_ptr());
        assert!(!s19k_bosminer_host248_t_is_named());
        assert_eq!(BOSMINER_HOST240_DATA_PREFIX, 0x18);
        assert_eq!(BOSMINER_HOST248_T_SIZE, 0x20);
        assert_eq!(BOSMINER_HOST248_T_BUF_OFF, 0x08);
        assert_eq!(BOSMINER_LOCK_POLL_ACQ_FN_VA, 0x011F_2DE4);
        assert!(admit_bosminer_prefix_opaque_and_elem_box_shaped().is_ok());
        assert!(refuse_prefix_as_named_vec_or_586cd8_as_jt_walker().is_err());
        assert_eq!(s19k_bosminer_prefix_jt_field_ldr_hits(), 0);
        assert_eq!(s19k_bosminer_586cd8_bl_hits(), 66);
        assert!(s19k_bosminer_9247b0_elem_is_box_shaped());
        assert_eq!(BOSMINER_586CD8_STRIDE, 0x18);
        assert_eq!(BOSMINER_586CD8_JT_BL_HITS, 0);
        assert_ne!(BOSMINER_9247B0_STRIDE, BOSMINER_586CD8_STRIDE);
        assert!(admit_bosminer_11f2de4_is_acquire_poll().is_ok());
        assert!(refuse_11f2de4_as_raw_mutex_or_standalone_poll_acquire().is_err());
        assert_eq!(s19k_bosminer_acquire_poll_bl_hits(), 34);
        assert_eq!(s19k_bosminer_acquire_poll_tls_off(), 0x40);
        assert!(!s19k_bosminer_acquire_poll_is_raw_mutex());
        assert_eq!(BOSMINER_ACQUIRE_POLL_FN_VA, BOSMINER_LOCK_POLL_ACQ_FN_VA);
        assert_eq!(BOSMINER_ACQUIRE_POLL_LOC425_LINE, 425);
        assert_eq!(BOSMINER_ACQUIRE_POLL_LOC493_LINE, 493);
        assert_eq!(BOSMINER_ACQUIRE_POLL_COOP_LINE, 345);
        assert!(BOSMINER_BATCH_SEMAPHORE_RS.ends_with("batch_semaphore.rs"));
        assert!(BOSMINER_COOP_MOD_RS.ends_with("coop/mod.rs"));
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_FN_VA,
            BOSMINER_HOST240_CLONE_FN_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_X1_STR_VA,
            BOSMINER_HOST240_CLONE_X1_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_X25_LDR_VA,
            BOSMINER_HOST240_CLONE_X25_LDR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_MEMCPY_MOVZ_VA,
            BOSMINER_HOST240_CLONE_MEMCPY_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_STR230_VA,
            BOSMINER_HOST240_CLONE_STR230_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_STR240_VA,
            BOSMINER_HOST240_CLONE_STR240_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_LDAXR_VA,
            BOSMINER_HOST240_CLONE_LDAXR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_REAL_ENTRY_VA,
            BOSMINER_HOST240_CLONE_REAL_ENTRY_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HOST240_CLONE_REAL_STP1_VA,
            BOSMINER_HOST240_CLONE_REAL_STP1_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HC_PLUS240_STR_VA,
            BOSMINER_HC_PLUS240_STR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_749C58_MOVZ_VA,
            BOSMINER_749C58_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_749C58_X22_MOV_VA,
            BOSMINER_749C58_X22_MOV_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_749C58_STR240_VA,
            BOSMINER_749C58_STR240_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_60B0FC_STRIDE_MOVZ_VA,
            BOSMINER_60B0FC_STRIDE_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_5FE12C_STR240_VA,
            BOSMINER_5FE12C_STR240_INSN,
        );
        assert!(admit_bosminer_host240_clone_str_x25(&prep_blob).is_ok());
        assert!(refuse_cec094_or_51a8c8_as_host240_ctor().is_err());
        assert!(admit_bosminer_clone_real_entry_is_835220(&prep_blob).is_ok());
        assert!(refuse_835234_as_fn_entry_or_70_first_alloc().is_err());
        assert_eq!(s19k_bosminer_host240_clone_str240_unique(), 1);
        assert_eq!(s19k_bosminer_host240_nonsp_nonnull_str_hits(), 54);
        assert_eq!(BOSMINER_HOST240_CLONE_MEMCPY_LEN, 0x230);
        assert_eq!(BOSMINER_HOST240_CLONE_BL_HITS, 0);
        assert_eq!(s19k_bosminer_clone_real_entry_bl_hits(), 1);
        assert_eq!(s19k_bosminer_60b0fc_bl_hits(), 27);
        assert_eq!(s19k_bosminer_681768_bl_hits(), 99);
        assert!(!s19k_bosminer_749c58_is_70());
        assert_eq!(BOSMINER_HOST240_CLONE_REAL_ENTRY_VA, 0x0083_5220);
        assert_eq!(BOSMINER_HOST240_CLONE_CALLER_VA, 0x0087_E1CC);
        assert_eq!(BOSMINER_749C58_ALLOC_SIZE, 0x228);
        assert!(admit_bosminer_sp78_is_sret10_of_blr23().is_ok());
        assert!(refuse_sp78_as_field_or_87deb4_as_named_x24().is_err());
        assert_eq!(s19k_bosminer_87e02c_str78_hits(), 0);
        assert_eq!(s19k_bosminer_87deb4_bl_hits(), 0);
        assert!(!s19k_bosminer_87deb4_is_x24_mint());
        assert_eq!(BOSMINER_SP78_SRET_BASE_OFF, 0x68);
        assert_eq!(BOSMINER_SP78_SRET_PLUS_OFF, 0x10);
        assert_eq!(BOSMINER_SP78_LDR_OFF, 0x78);
        assert_eq!(BOSMINER_87DEB4_FN_VA, 0x0087_DEB4);
        assert_eq!(BOSMINER_87DEB4_VT_VA, 0x019C_8838);
        assert_eq!(BOSMINER_SP78_GET_FN_VA, 0x0087_87A8);
        putp(
            &mut prep_blob,
            BOSMINER_SPAWN_TBZ_VA,
            BOSMINER_SPAWN_TBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_CLONE_GET_TBZ_VA,
            BOSMINER_CLONE_GET_TBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_FACTORY_LDR8_VA,
            BOSMINER_FACTORY_LDR8_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_BL_B_VA,
            BOSMINER_HASHMAP_GET_BL_B_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_THIRD_GET_TBZ_VA,
            BOSMINER_THIRD_GET_TBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SRET18_Q0_CBZ_VA,
            BOSMINER_SRET18_Q0_CBZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_SRET18_Q2_LDAXR_VA,
            BOSMINER_SRET18_Q2_LDAXR_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_GET_MISS_TAG_VA,
            BOSMINER_HASHMAP_GET_MISS_TAG_INSN,
        );
        assert!(admit_bosminer_hashmap_v_is_18_spawn0_factory8(&prep_blob).is_ok());
        assert!(refuse_sret18_as_hashmap_v_or_named_result().is_err());
        assert_eq!(s19k_bosminer_hashmap_get_bl_hits(), 3);
        assert_eq!(s19k_bosminer_hashmap_v_spawn_off(), 0);
        assert_eq!(s19k_bosminer_hashmap_v_factory_off(), 8);
        assert!(!s19k_bosminer_sret18_is_hashmap_v());
        assert!(!s19k_bosminer_v0_is_factory4());
        assert!(!s19k_bosminer_v8_is_vt0());
        assert!(s19k_bosminer_spawn_w0_test_is_tbnz());
        assert_eq!(BOSMINER_CLONE_GET_TBZ_TGT, 0x0083_52D4);
        assert_eq!(BOSMINER_SRET18_Q0_CBZ_TGT, 0x0087_E370);
        assert_eq!(BOSMINER_HASHMAP_GET_BL_B_VA, 0x0083_71F8);
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_V_CTOR_VA,
            BOSMINER_HASHMAP_V_CTOR_PROLOGUE_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_V_1366_MOVZ_VA,
            BOSMINER_HASHMAP_V_1366_MOVZ_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_V_1366_STRH_VA,
            BOSMINER_HASHMAP_V_1366_STRH_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_V_1362_STRH_VA,
            BOSMINER_HASHMAP_V_1362_STRH_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_INSERT_BL_VA,
            BOSMINER_ENTRY8_INSERT_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_INSERT_CALL_BL_VA,
            BOSMINER_HASHMAP_INSERT_CALL_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_HASHMAP_V_WRAPPER_LAST_INSERT_BL_VA,
            BOSMINER_HASHMAP_V_WRAPPER_LAST_INSERT_BL_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_QWORD0_ADRP_VA,
            BOSMINER_ENTRY8_QWORD0_ADRP_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_QWORD0_ADD_VA,
            BOSMINER_ENTRY8_QWORD0_ADD_INSN,
        );
        putp(
            &mut prep_blob,
            BOSMINER_ENTRY8_1366_STP_VA,
            BOSMINER_ENTRY8_1366_STP_INSN,
        );
        assert!(admit_bosminer_hashmap_v_is_chipid_factory_tuple(&prep_blob).is_ok());
        assert!(refuse_hashmap_v_as_occupied_entry_or_named_type().is_err());
        assert_eq!(s19k_bosminer_hashmap_v_key_count(), 7);
        assert!(!s19k_bosminer_hashmap_v_type_named());
        assert_eq!(BOSMINER_HASHMAP_V_INSERT_UNROLL, 7);
        assert_eq!(BOSMINER_HASHMAP_V_KEYS[1], 0x1366);
        assert_eq!(
            s19k_braiins_fill_nonce_word(s19k_braiins_uart_nonce_arg_from_payload8(
                0x0000_0000_DDCC_BBAA
            )),
            0xAABB_CCDD
        );
        assert_ne!(
            s19k_braiins_work_resp_index(0xAABB_CCDD, 1).unwrap() as u32,
            0xAABB_CCDD
        );
    }

    #[test]
    fn wave119_plus80_is_bm1398_6x_work_type_not_pic_or_future() {
        assert!(admit_bosminer_plus80_is_work_type_tag().is_ok());
        assert!(refuse_midstates_work_type_on_braiins_fill_rx(1).is_ok());
        assert!(refuse_midstates_work_type_on_braiins_fill_rx(0).is_err());
        assert!(refuse_midstates_work_type_on_braiins_fill_rx(2).is_err());
        assert!(refuse_pic0x88_as_engine_plus88().is_err());
        assert!(refuse_am3_future_plus80_as_work_type().is_err());
        assert!(refuse_plus80_ne1_as_alt_nonce_transform().is_err());
        assert_eq!(BOSMINER_ENGINE_WORK_TYPE_OFF, 0x80);
        assert_eq!(BOSMINER_WORK_TYPE_VERSION_ROLLING, 1);
        assert_eq!(BOSMINER_WORK_RESP_PLUS80_ADRP_INSN, 0xB000_5040);
        assert_eq!(BOSMINER_WORK_RESP_PLUS80_ADD_INSN, 0x9112_3C00);
        assert_eq!(BOSMINER_WORK_RESP_PLUS80_MOVZ_LEN_INSN, 0x5280_0601);
        assert_eq!(BOSMINER_WORK_RESP_PLUS80_LINE, 344);
        assert_eq!(BOSMINER_WORK_RESP_PLUS80_COL, 21);
        assert_eq!(BOSMINER_WORK_RESP_NOT_WORK_LINE, 319);
        assert_eq!(BOSMINER_WORK_RESP_PLUS80_PANIC_MSG.len(), 48);
        assert_eq!(BOSMINER_BM1398_6X_RS.len(), 48);
        assert!(BOSMINER_BM1398_6X_RS.ends_with("bm1398_6x.rs"));
        assert!(BOSMINER_PIC0X88_RS.ends_with("pic0x88.rs"));
        assert_ne!(
            BOSMINER_AM3_INIT_TAG80_INSN,
            BOSMINER_WORK_RESP_PLUS80_LDRB_INSN
        );
        assert_eq!(BOSMINER_AM3_INIT_TAG80_INSN, 0x3942_0008);
        assert!(admit_s19k_bosminer_layouts().is_ok());
    }

    #[test]
    fn wave120_plus80_is_verwidth_tag_mid_entry() {
        assert!(admit_bosminer_plus80_is_verwidth_tag().is_ok());
        assert!(refuse_verwidth_else_as_uart_fill_path().is_err());
        assert!(refuse_verwidth_mid_entry_as_parse_bl_target().is_err());
        assert_eq!(BOSMINER_ENGINE_VERWIDTH_SELF_OFF, 0x60);
        assert_eq!(BOSMINER_VERWIDTH_TAG_OFF, 0x20);
        assert_eq!(
            BOSMINER_ENGINE_WORK_TYPE_OFF,
            BOSMINER_ENGINE_VERWIDTH_SELF_OFF + BOSMINER_VERWIDTH_TAG_OFF
        );
        assert_eq!(BOSMINER_WORK_RESP_MOV_X21_ENGINE_INSN, 0xAA01_03F5);
        assert_eq!(BOSMINER_WORK_RESP_ADD60_INSN, 0x9101_82A0);
        assert_eq!(BOSMINER_VERWIDTH_PARSE_BL_TARGET_VA, 0x00BF_2478);
        assert_eq!(BOSMINER_VERWIDTH_CMP_VA, 0x00BF_247C);
        assert_eq!(BOSMINER_ENGINE_MIDSTATE_COUNT_OFF, 0x78);
        assert!(admit_bosminer_bf2478_is_midstate_log_helper().is_ok());
    }

    #[test]
    fn wave123_factory_data_cannot_name_plus88() {
        assert!(admit_bosminer_factory_x1_is_runtime_x24().is_ok());
        assert!(refuse_factory_data_as_named_plus88().is_err());
        assert!(refuse_bm1366_str88_result_as_engine_nonce_fn().is_err());
        assert!(refuse_ret_only_as_named_plus88().is_err());
        assert_eq!(BOSMINER_FACTORY_DATA_PTR_HITS, 0);
        assert_eq!(BOSMINER_ADRP_TEXT_NONSP_STR88_RET_HITS, 0);
        assert_eq!(BOSMINER_REV_W0_RET_HITS, 0);
        assert_eq!(BOSMINER_FACTORY_X1_FROM_X24_INSN, 0xAA18_03E1);
        assert_eq!(BOSMINER_HC290_STR_INSN, 0xF901_4AFA);
        assert_eq!(BOSMINER_BM1366_STR88_RESULT_INSN, 0xF900_4660);
        assert_eq!(s19k_braiins_fill_nonce_word(0xAABB_CCDD), 0xAABB_CCDD);
    }

    #[test]
    fn wave125_rustc_metadata_cannot_name_plus88() {
        assert!(refuse_rustc_metadata_as_named_plus88().is_err());
        assert!(!BOSMINER_RUSTC_SECTION_PRESENT);
        assert_eq!(BOSMINER_IDENTITY_STR_HITS, 0);
        assert_eq!(BOSMINER_ELF_SHNUM, 18);
        assert!(BOSMINER_RUSTC_VERSION.contains("1.87.0"));
        assert_eq!(BOSMINER_COMMENT_FILE_OFF, 0x016D_A050);
    }
}
