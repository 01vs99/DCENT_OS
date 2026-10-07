//! Exact held-byte evidence for the framed-dsPIC33EP16GS202 "S9 plus plus"
//! AM1 generation — the compile-time model family whose held production
//! miner binaries are the Antminer S9 Hydro build (2019-09-20) and the
//! Antminer S11 build (2019-08-01) — and for the S11 stock-image
//! payload-selection law (campaign `2026-09-07-antminer-beta-execution`,
//! lane R17). Pure and no-I/O: this module states laws, admits boards and
//! refuses; it never opens an I²C bus, touches a UART, or grants electrical
//! authority.
//!
//! The lane discipline is the R13/R14/R02 doctrine: every constant cites
//! held bytes, ambiguous datums stay `Unproven`/refused, and nothing is
//! inferred from a sibling chip. In particular **the S11 ASIC identity is
//! never inferred here** — no BM1387, BM1390 or BM1391 wire law is admitted
//! for `am1-s11` by this module (see `S11_ASIC_IDENTITY` and
//! `s11_admits_no_asic_wire_law`).
//!
//! ## Held sources (fresh SHA-256, this lane, 2026-09-11)
//!
//! 1. S9 Hydro production `bmminer`:
//!
//!    — 521,076 bytes, SHA-256
//!    `81b89d0833cc5b368682b4ba1880b63f3b61ee992dc49f9402c9d4b0af92ac85`
//!    (`compile_time`: "Antminer S9 Hydro / V1.17", Fri Sep 20 10:34:13 CST 2019).
//! 2. S11 production `bmminer` (7007 payload):
//!    , byte-identical to
//!
//!    — 497,032 bytes, SHA-256
//!    `a9417924750b7f9f2cd998f20d2cd402d542595f547635bcd54155f5aa24b8a2`
//!    (already pinned by `dcentrald-silicon-profiles/src/bm1391_stock_fw.rs::S11_BMMINER_SHA256`).
//! 3. S11 stock launcher + payloads:
//!
//!    and the `7007/` + `xilinx/` payload trees (SHA-256 table below).
//!
//! ## What the held bytes prove
//!
//! Both binaries are one compile-time model family ("S9 plus plus", symbol
//! `set_Voltage_S9_plus_plus_BM1387_54` in both) whose wrappers
//! `enable_pic_dac` / `disable_pic_dac` / `pic_heart_beat_each_chain`
//! tail-call the **framed** `dsPIC33EP16GS202_*` handlers exactly like the
//! T9+ binary adjudicated by lane R02 — unlike the S9i/S9j build, where the
//! same-named wrappers contain the bare PIC16 law and the framed handlers
//! are dead code (R02 `evidence/r02/SOURCE_NOTE.md`). Production call
//! chains in the S9 Hydro build (capstone 5.0.7, fresh disassembly):
//!
//! | wrapper (framed) | production callers |
//! |---|---|
//! | `enable_pic_dac` | `bitmain_c5_init+0x1040` (cold init), `power_on_all_chain+0x22`, `T9_18_CloseAndOpenDC+0x68` |
//! | `pic_heart_beat_each_chain` | `pic_heart_beat_func+0x68` |
//! | `disable_pic_dac` | `power_off_all_chain+0x22`, `check_temp_func+0x12a`, `read_temp_func+0xb86`, init failure `bitmain_c5_init+0x668` |
//! | `set_Voltage_S9_plus_plus_BM1387_54` | `set_voltage_T9_18_into_PIC+0x42/+0x5a` |
//! | `dsPIC33EP16GS202_pic_get_an_voltage2` | `get_avg_voltage+0xbf` |
//! | `getPICvoltageFromValue` | `btm_dynamic_adjust_vol+0x58` |
//!
//! Shared frame laws (identical constants to the R02 T9+ codec, see the
//! cross-check tests at the bottom): heartbeat `55 AA 04 16 00 1A`
//! (`dsPIC33EP16GS202_pic_heart_beat@0x44094`), enable
//! `55 AA 05 15 en crc=BE16(0x1A+en)` with echo/status predicate
//! (`..._enable_pic_dc_dc@0x43cdc`, 3 retries, 10 ms reply wait), version
//! `55 AA 04 17 00 1B` (`..._get_pic_sw_version@0x43a64`, 3 retries,
//! 100 ms wait, 5-byte reply), set-voltage `55 AA 07 10 v 00 00
//! crc=BE16(0x17+v)` with the same bit-7 no-TX refusal
//! (`set_Voltage_S9_plus_plus_BM1387_54@0x2fdd4`), voltage encode/decode
//! pools `100.0 / 32.79 / 364.0704 / 30.72`
//! (`getPICvoltageFromValue@0x2f054`/`getVolValueFromPICvoltage@0x2f0b8`),
//! and the FPGA-IIC word `(bus&3)<<26 | 0x02000000 rd | 0x01000000
//! addr|addr<<8 | 0x00400000 data` (`T9_plus_write_pic_iic@0x51e14`,
//! 1 ms ready poll, ver-14/15 chain-1 adjustment).
//!
//! One generation delta is recorded but NOT implemented (R02 owns the
//! set-voltage codec): the hydro build's set-voltage reply wait is
//! 400 ms (`0x61a80` at `set_Voltage_S9_plus_plus_BM1387_54+0xb6`), while
//! the T9+ set-voltage wait R02 pinned is 100 ms. Both are exact per
//! binary; neither is projected onto the other.
//!
//! ## What is NEW here (and therefore implemented)
//!
//! The hydro build frames an **analog voltage telemetry query** the T9+
//! binary never evidenced (R02 explicitly refused to claim telemetry for
//! that reason): `dsPIC33EP16GS202_pic_get_an_voltage2@0x46064` sends
//! `55 AA 04 29 00 2D` (cmd `0x29`, crc `0x2D` written literally), waits
//! 500 ms (`0x7a120`), retries twice (`movs r6,#2`), reads a 9-byte reply,
//! checks `reply[1] == 0x29` and `reply[2] == 1`, verifies the uniform
//! checksum law (`check_pic_crc@0x45cdc`:
//! `u16(N + cmd + Σ payload) == BE16(reply[N-2], reply[N-1])`), and decodes
//! `volts = BE16(reply[3], reply[4]) * 3.3 * (1/4096) * 4.0`
//! (`decode_an_voltage_buf@0x45ea4`; pool constants `3.3` @`0x46048` and
//! `1/4096` @`0x46050`). Stock failure paths return the literal `0.0`
//! (`0x46260`/`0x46058`); this module refuses with typed errors instead —
//! a fabricated `0.0 V` reading is never emitted (DCENT-only deviation,
//! documented below).

use crate::am1_dspic_adapter as dspic;

/// The one board target this generation module admits. This is a NEW R17
/// row name (no `board_desc` row exists yet; the F02 tuple union has no
/// `am1` hydro row either). Registration in `board_desc.rs` is Lead-owned
/// and is proposed in `evidence/r17/SOURCE_NOTE.md`, not landed here.
pub const S9_HYDRO_BOARD_TARGET: &str = "am1-s9-hydro";

/// Held S9 Hydro production bmminer SHA-256 (see module doc, source 1).
pub const S9_HYDRO_BMMINER_SHA256: &str =
    "81b89d0833cc5b368682b4ba1880b63f3b61ee992dc49f9402c9d4b0af92ac85";

/// Held S11 production bmminer SHA-256 (see module doc, source 2; equals
/// `dcentrald_silicon_profiles::bm1391_stock_fw::S11_BMMINER_SHA256`).
pub const S11_BMMINER_SHA256: &str =
    "a9417924750b7f9f2cd998f20d2cd402d542595f547635bcd54155f5aa24b8a2";

/// Thumb prologue + `bx lr` of every compile-time model predicate that
/// returns **false** in these builds: `movs r0, #0; bx lr` =
/// `00 20 70 47`. Held at, for example, `is_S9@0x3a399` (hydro build) and
/// `is_S9i@0x37ce5` (S11 build).
pub const PREDICATE_FALSE_BYTES: [u8; 4] = [0x00, 0x20, 0x70, 0x47];

/// Thumb `movs r0, #1; bx lr` = `01 20 70 47` for true predicates: the
/// hydro build sets ONLY `is_S9_Hydro@0x3a3b1` (hence BM1387-lineage is
/// first-party for the S9 Hydro, never a jig inference), and the S11 build
/// sets `is_S11@0x37cf1` AND `is_S9_plus@0x37cd9` (the two-flags ambiguity
/// already pinned by `bm1391_stock_fw`).
pub const PREDICATE_TRUE_BYTES: [u8; 4] = [0x01, 0x20, 0x70, 0x47];

/// The hydro build's only true compile-time model predicate.
pub const S9_HYDRO_BUILD_IS_S9_HYDRO: bool = true;
/// The hydro build's `is_S9_plus` byte law (false).
pub const S9_HYDRO_BUILD_IS_S9_PLUS: bool = false;
/// The hydro build's `is_S11` byte law (false).
pub const S9_HYDRO_BUILD_IS_S11: bool = false;
/// The S11 build's `is_S11` byte law (true).
pub const S11_BUILD_IS_S11: bool = true;
/// The S11 build's `is_S9_plus` byte law (true — the documented ambiguity).
pub const S11_BUILD_IS_S9_PLUS: bool = true;
/// The S11 build's `is_S9_Hydro` byte law (false).
pub const S11_BUILD_IS_S9_HYDRO: bool = false;

/// Telemetry query command byte. Held `dsPIC33EP16GS202_pic_get_an_voltage2`
/// writes `0x29` literally (`movs r3,#0x29` @`0x460c2`).
pub const CMD_GET_ANALOG_VOLTAGE: u8 = 0x29;

/// Exact stock telemetry request frame: `55 AA 04 29 00 2D`, written
/// byte-wise through `T9_plus_write_pic_iic` (`0x46092..0x460ea`). The
/// wire is the empty-payload frame law: N=4, cmd=`0x29`, then crc16 BE =
/// `00 2D` (`frame_crc(4, 0x29, &[])` — asserted by test; stock writes
/// the `0x2D` literally @`0x460e0`).
pub const S9_PLUS_TELEMETRY_REQUEST_FRAME: [u8; 6] = [0x55, 0xAA, 0x04, 0x29, 0x00, 0x2D];

/// Stock reply wait before reading the telemetry reply: `0x7a120` µs =
/// 500 ms (`movw r8,#0xa120`@`0x4606a` + `movt r8,#7`@`0x4607a`,
/// `blx usleep`@`0x460f0`).
pub const STOCK_TELEMETRY_REPLY_WAIT_MS: u32 = 500;

/// Stock telemetry retry budget: `movs r6,#2` @`0x4607e` (two attempts,
/// sleep(1) between — `blx sleep` @`0x461b6`).
pub const STOCK_TELEMETRY_RETRY_BUDGET: u8 = 2;

/// Stock reads exactly nine reply bytes (`sp+0x0c..sp+0x14`,
/// nine single-byte IIC reads @`0x460fc..0x46192`).
pub const STOCK_TELEMETRY_REPLY_LEN: usize = 9;

/// Telemetry decode multiplier K1: `3.3` (double @`0x46048`,
/// `vldr d5` @`0x45ed4`).
pub const TELEMETRY_K1_VREF: f64 = 3.3;

/// Telemetry decode multiplier K2: `2^-12 = 1/4096` (double @`0x46050`,
/// `vldr d6` @`0x45ed8`).
pub const TELEMETRY_K2_LSB: f64 = 0.000244140625;

/// Telemetry decode multiplier K3: literal `vmov.f64 d7, #4.000000e+00`
/// @`0x45edc` (the PIC ADC divider ratio).
pub const TELEMETRY_K3_DIVIDER: f64 = 4.0;

/// The S11 build's hashboard-test image also uses this family's voltage
/// law pools; per-facet status for the profile table below.
pub const S9_HYDRO_JIG_NAME: &str = "S9 HASH board";

/// Hydro jig `etc/config/Config.ini` ASIC lines (`AsicType=1387`,
/// `AsicNum=63`, `CoreNum=114`). These are JIG bytes — corroborating only,
/// never identity-establishing (the S11 adjudication proved the same jig
/// text ships under the same "S9 HASH board" title for a different model;
/// `bm1391_stock_fw` and findings.md row "S11"). The hydro's identity is
/// established by the build predicate, not by this file.
pub const S9_HYDRO_JIG_ASIC_TYPE: u32 = 1387;
/// Hydro jig `AsicNum=63` (corroborating only — see above).
pub const S9_HYDRO_JIG_ASIC_NUM: u32 = 63;
/// Hydro jig `CoreNum=114` (corroborating only — see above).
pub const S9_HYDRO_JIG_CORE_NUM: u32 = 114;

/// Hydro cooling law marker: the string
/// `s9_hydro_strong_liquid_cooling_min_pwm_percent` exists in the held
/// production bmminer (unique string scan, 1 hit). The numeric minimum is
/// NOT extracted here (needs a data cross-reference this lane did not
/// perform), so cooling stays [`S9HydroFacet::Unproven`] until that byte
/// is pinned. Recorded so the datum is not lost.
pub const S9_HYDRO_COOLING_LAW_STRING: &str = "s9_hydro_strong_liquid_cooling_min_pwm_percent";

/// The S11 ASIC identity question, encoded so it cannot silently become a
/// claim. Held bytes leave the silicon unsettled: the only production-class
/// miner binary in the image (7007 payload `bmminer`, this generation) is
/// never launched by that payload (`cgminer.sh` ends in
/// `killall -9 bmminer; killall -9 single-board-test; single-board-test&`,
/// byte-cited in `S11_7007_PAYLOAD_LAUNCHES`), and the xilinx payload
/// (`fw/xilinx/angstrom_rootfs.jffs2`, 26,476,544 bytes, SHA-256
/// `89c7985e8fcfe854d24ebe37f62fbfe14a074b4259f1ea1616beba3e11c8d7c8`) is a
/// UBI image (`UBI#` magic) this lane could not extract offline — only
/// `single-board-test`, `ctrl_bd`, `Antminer S11` and `dsPIC33EP16GS202`
/// markers are visible in plaintext. No BM1387/BM1390/BM1391 wire law is
/// admitted for S11 anywhere in this module.
pub const S11_ASIC_IDENTITY: &str = "Unproven";

/// Byte-exact launch law of the S11 7007 payload (`fw/7007/uramdisk.image
/// .gz.tree/etc/init.d/cgminer.sh`, `do_start` tail): the payload always
/// kills both miners and backgrounds `single-board-test`; `bmminer` ships
/// but is never started by this payload.
pub const S11_7007_PAYLOAD_LAUNCHES: &str = "single-board-test";

/// Payload classes the S11 stock installer selects between. Selection law
/// is `fw/runme.sh` (byte-cited in [`select_s11_payload`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S11PayloadClass {
    /// `is7010=1` branch: `/usr/bin/ctrl_bd` contains `XILINX`. The
    /// installer flashes `fw/xilinx/` (UBI rootfs, `BOOT.bin`@mtd0+0x0,
    /// dtb@0x1020000, `uImage`@0x1100000, `angstrom_rootfs.jffs2` staged
    /// through `ubiattach mtd2` + `upgrade-marker.bin`@0x1040000).
    UbiXilinx,
    /// `is7010=0` branch (also the `ctrl_bd`-absent default): the
    /// installer flashes `fw/7007/` (`BOOT.bin`@0x0 len 0x40 blocks,
    /// dtb@0x1A00000, `uImage`@0x2000000, `uramdisk.image.gz`@mtd1+mtd4).
    Uramdisk7007,
}

/// Errors for wrong-generation board admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenerationBoardError {
    /// The standard S9 family production path is the bare PIC16 ABI (R02
    /// held-byte adjudication); the framed generation never applies.
    S9FamilyIsBarePic16,
    /// `am1-s11`: capture-first; identity and payload miner unsettled.
    S11Unsettled,
    /// `am1-t9plus`: owned by `am1_dspic_adapter` (R02) with its own
    /// admission; this module never duplicates it.
    T9PlusOwnedByAdapter,
    /// Not a known am1 target at all.
    UnknownBoard,
}

/// Admission gate for THIS generation's framed-PIC wire laws. Only the
/// S9 Hydro row (R17, capture-first profile) selects it. Everything else
/// is refused with the specific reason, including boards that look
/// adjacent — the refusal tests pin each case.
pub fn admit_generation_board(board_target: &str) -> Result<(), GenerationBoardError> {
    match board_target {
        S9_HYDRO_BOARD_TARGET => Ok(()),
        "am1-s9" | "am1-s9i" | "am1-s9j" => Err(GenerationBoardError::S9FamilyIsBarePic16),
        "am1-s11" => Err(GenerationBoardError::S11Unsettled),
        "am1-t9plus" => Err(GenerationBoardError::T9PlusOwnedByAdapter),
        _ => Err(GenerationBoardError::UnknownBoard),
    }
}

/// Select the S11 stock payload the installer flashes, byte-exactly per
/// `fw/runme.sh`: `is7010 = grep -c XILINX /usr/bin/ctrl_bd`; branch 1
/// flashes `fw/xilinx/`, branch 0 (including a missing `ctrl_bd`, which
/// the script handles by `is7010=0`) flashes `fw/7007/`. The desk law
/// takes the observed `ctrl_bd` content; no content is invented.
pub fn select_s11_payload(ctrl_bd: Option<&[u8]>) -> S11PayloadClass {
    match ctrl_bd {
        Some(bytes) if contains_ascii(bytes, b"XILINX") => S11PayloadClass::UbiXilinx,
        _ => S11PayloadClass::Uramdisk7007,
    }
}

fn contains_ascii(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

/// Typed refusal instead of stock's fabricated `0.0` reading.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TelemetryReplyError {
    /// Reply is not nine bytes.
    WrongLength,
    /// `reply[1] != 0x29` (stock echo check @`0x4619a`).
    CommandEchoMismatch,
    /// `reply[2] != 1` (stock status check @`0x4620e`).
    StatusNotOk,
    /// Uniform checksum law failed (`check_pic_crc` @`0x45cdc`). Stock
    /// returns literal `0.0` on this path (`0x46058`); we refuse.
    CrcMismatch,
    /// Exhausted retries (stock returns literal `0.0`, pool @`0x46260`).
    /// We surface the failure instead.
    Exhausted,
}

/// Admit one 9-byte analog-voltage reply and return the raw ADC word.
/// Checks, in stock order: length, command echo, status byte, then the
/// uniform checksum law. The raw word is returned for the separate
/// decode step so callers can log refused frames without fabricating
/// voltages.
pub fn admit_telemetry_reply(reply: &[u8]) -> Result<u16, TelemetryReplyError> {
    if reply.len() != STOCK_TELEMETRY_REPLY_LEN {
        return Err(TelemetryReplyError::WrongLength);
    }
    if reply[1] != CMD_GET_ANALOG_VOLTAGE {
        return Err(TelemetryReplyError::CommandEchoMismatch);
    }
    if reply[2] != dspic::PIC_ACK_OK {
        return Err(TelemetryReplyError::StatusNotOk);
    }
    // check_pic_crc@0x45cdc: sum = u16(reply[0]) + Σ reply[1..=reply[0]-3],
    // wire = BE16(reply[N-2], reply[N-1]); valid iff equal.
    let n = usize::from(reply[0]);
    let body_end = n.saturating_sub(2);
    if body_end < 2 || body_end > reply.len() {
        return Err(TelemetryReplyError::CrcMismatch);
    }
    let mut sum = u16::from(reply[0]);
    for b in &reply[1..body_end] {
        sum = sum.wrapping_add(u16::from(*b));
    }
    let wire = u16::from(reply[n - 2]) << 8 | u16::from(reply[n - 1]);
    if sum != wire {
        return Err(TelemetryReplyError::CrcMismatch);
    }
    Ok(u16::from(reply[3]) << 8 | u16::from(reply[4]))
}

/// Decode the admitted raw ADC word exactly as
/// `decode_an_voltage_buf@0x45ea4` does: `raw * 3.3 * (1/4096) * 4.0`,
/// in that multiplication order.
pub fn decode_an_voltage(raw: u16) -> f64 {
    (f64::from(raw) * TELEMETRY_K1_VREF * TELEMETRY_K2_LSB) * TELEMETRY_K3_DIVIDER
}

/// Per-facet evidence status for the S9 Hydro row (R13/R14 facet
/// doctrine; nothing inherits from the S9, S9i/S9j, T9+ or S21 lanes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9HydroFacet {
    /// Established by this generation's held production bytes.
    GenerationProven,
    /// Held bytes exist but the numeric datum was not extracted this lane.
    HeldUnextracted,
    /// No held bytes; capture-first.
    Unproven,
}

/// The S9 Hydro row's facet table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9HydroProfile {
    /// Voltage-controller family and frame laws: framed
    /// dsPIC33EP16GS202, production-proven (module doc table).
    pub pic_generation: S9HydroFacet,
    /// ASIC lineage: BM1387-lineage via the compile-time
    /// `is_S9_Hydro()=1` build predicate + the
    /// `set_Voltage_S9_plus_plus_BM1387_54` symbol — first-party, not jig
    /// inference.
    pub asic_lineage: S9HydroFacet,
    /// Hashboard silicon identity string: never stated by a production
    /// binary (no `BM1387`/`BM138x` string in the held bmminer); the jig
    /// `AsicType=1387` is corroborating only.
    pub asic_identity_string: S9HydroFacet,
    /// Chips per chain / chain population: no production capture. Jig
    /// `AsicNum=63` is corroborating only.
    pub population: S9HydroFacet,
    /// Chain transport + reset/GPIO map: no held DTB analysis this lane.
    pub carrier: S9HydroFacet,
    /// Liquid-cooling control law: the string exists
    /// ([`S9_HYDRO_COOLING_LAW_STRING`]), the numeric minimum is
    /// unextracted.
    pub cooling: S9HydroFacet,
    /// Install/storage: the angstrom rootfs is a full production-style
    /// rootfs, but no NAND layout analysis was performed this lane.
    pub install: S9HydroFacet,
}

/// The one S9 Hydro profile.
pub const S9_HYDRO_PROFILE: S9HydroProfile = S9HydroProfile {
    pic_generation: S9HydroFacet::GenerationProven,
    asic_lineage: S9HydroFacet::GenerationProven,
    asic_identity_string: S9HydroFacet::Unproven,
    population: S9HydroFacet::Unproven,
    carrier: S9HydroFacet::Unproven,
    cooling: S9HydroFacet::HeldUnextracted,
    install: S9HydroFacet::Unproven,
};

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Frame law: telemetry request is stock-exact and law-derived.
    // ------------------------------------------------------------------

    #[test]
    fn telemetry_request_frame_is_stock_exact() {
        assert_eq!(
            S9_PLUS_TELEMETRY_REQUEST_FRAME,
            [0x55, 0xAA, 0x04, 0x29, 0x00, 0x2D]
        );
    }

    #[test]
    fn telemetry_request_frame_matches_shared_crc_law() {
        // The literal crc bytes stock writes (0x00 then 0x2D) are the BE16
        // of the shared frame_crc law R02 pinned from T9+:
        // n + cmd + sum(empty payload) = 4 + 0x29 = 0x002D.
        assert_eq!(
            dspic::frame_crc(4, CMD_GET_ANALOG_VOLTAGE, &[]),
            0x002D_u16
        );
        // Empty payload; the wire's fifth byte is the crc HIGH byte.
        let mut frame = vec![0x55u8, 0xAA];
        frame.push(4);
        frame.push(CMD_GET_ANALOG_VOLTAGE);
        let crc = dspic::frame_crc(4, CMD_GET_ANALOG_VOLTAGE, &[]);
        frame.push((crc >> 8) as u8);
        frame.push((crc & 0xFF) as u8);
        assert_eq!(frame, S9_PLUS_TELEMETRY_REQUEST_FRAME.to_vec());
    }

    #[test]
    fn telemetry_request_frame_disjoint_from_r02_commands() {
        // The telemetry command must not collide with any R02 command
        // byte (0x10/0x15/0x16/0x17): a collision would silently alias
        // the two lanes' traffic.
        for cmd in [
            dspic::CMD_SET_VOLTAGE,
            dspic::CMD_ENABLE_DC_DC,
            dspic::CMD_HEARTBEAT,
            dspic::CMD_GET_SOFTWARE_VERSION,
        ] {
            assert_ne!(CMD_GET_ANALOG_VOLTAGE, cmd);
        }
    }

    // ------------------------------------------------------------------
    // Reply admission: positive + every refusal case.
    // ------------------------------------------------------------------

    /// Hand-built valid reply: N=9, cmd 0x29, status 1, raw 0x080C
    /// (= 2060), two filler payload bytes, crc = u16(9 + 0x29 + 1 +
    /// 0x08 + 0x0C + 0xA5 + 0x5A) = u16(0x142) = 0x0142.
    fn valid_reply() -> [u8; 9] {
        let sum: u16 = 9 + 0x29 + 1 + 0x08 + 0x0C + 0xA5 + 0x5A;
        let crc = sum & 0xFF_FF;
        [
            9,
            0x29,
            0x01,
            0x08,
            0x0C,
            0xA5,
            0x5A,
            (crc >> 8) as u8,
            (crc & 0xFF) as u8,
        ]
    }

    #[test]
    fn valid_telemetry_reply_admits_with_raw_word() {
        let reply = valid_reply();
        assert_eq!(admit_telemetry_reply(&reply).unwrap(), 0x080C);
    }

    #[test]
    fn telemetry_reply_wrong_length_refused() {
        let mut reply = valid_reply().to_vec();
        reply.pop();
        assert_eq!(
            admit_telemetry_reply(&reply),
            Err(TelemetryReplyError::WrongLength)
        );
    }

    #[test]
    fn telemetry_reply_echo_mismatch_refused() {
        let mut reply = valid_reply();
        reply[1] = 0x17; // a version reply is never a telemetry reply
        assert_eq!(
            admit_telemetry_reply(&reply),
            Err(TelemetryReplyError::CommandEchoMismatch)
        );
    }

    #[test]
    fn telemetry_reply_status_not_ok_refused() {
        let mut reply = valid_reply();
        reply[2] = 0x00;
        assert_eq!(
            admit_telemetry_reply(&reply),
            Err(TelemetryReplyError::StatusNotOk)
        );
    }

    #[test]
    fn telemetry_reply_crc_mismatch_refused() {
        let mut reply = valid_reply();
        reply[7] ^= 0x40; // corrupt crc high byte
        assert_eq!(
            admit_telemetry_reply(&reply),
            Err(TelemetryReplyError::CrcMismatch)
        );
    }

    #[test]
    fn telemetry_reply_crc_law_matches_stock_check_pic_crc_shape() {
        // The stock checker pre-adds N, then sums reply[1..=N-3], and
        // compares against BE16 of the last two bytes. Verify our
        // admission accepts a reply built strictly by the shared law
        // crc = n + cmd + sum(payload) — proving the two laws agree.
        let payload: [u8; 5] = [0x01, 0x12, 0x34, 0x00, 0x00];
        let n = 9u16;
        let cmd = CMD_GET_ANALOG_VOLTAGE as u16;
        let crc = n + cmd + payload.iter().map(|b| u16::from(*b)).sum::<u16>();
        let reply = [
            9u8,
            CMD_GET_ANALOG_VOLTAGE,
            payload[0],
            payload[1],
            payload[2],
            payload[3],
            payload[4],
            (crc >> 8) as u8,
            (crc & 0xFF) as u8,
        ];
        assert_eq!(admit_telemetry_reply(&reply).unwrap(), 0x1234);
    }

    // ------------------------------------------------------------------
    // Decode law.
    // ------------------------------------------------------------------

    #[test]
    fn an_voltage_decode_is_stock_exact() {
        // 0x080C = 2060; (2060 * 3.3) * (1/4096) * 4.0 = 6.638671875 V.
        let v = decode_an_voltage(0x080C);
        assert_eq!(v, 2060.0 * 3.3 * 0.000244140625 * 4.0);
        assert!((v - 6.638671875).abs() < 1e-9);
        // Full-scale raw word: 4095 -> (4095 * 3.3 / 4096) * 4.
        let full = decode_an_voltage(0x0FFF);
        assert!((full - 13.19677734375).abs() < 1e-9);
    }

    #[test]
    fn an_voltage_decode_scaling_constants_are_stock_literals() {
        assert_eq!(TELEMETRY_K1_VREF, 3.3);
        assert_eq!(TELEMETRY_K2_LSB, 1.0 / 4096.0);
        assert_eq!(TELEMETRY_K3_DIVIDER, 4.0);
    }

    // ------------------------------------------------------------------
    // Voltage-law identity with the R02 T9+ codec (held in both new
    // binaries): the hydro and S11 pools are the SAME four doubles.
    // ------------------------------------------------------------------

    #[test]
    fn voltage_law_pools_identical_to_r02_t9plus_law() {
        // getPICvoltageFromValue@0x2f054 (hydro) / @0x2e3a0 (S11) pools:
        // 100.0, 32.79, 364.0704, 30.72 — identical to the R02 constants.
        assert_eq!(100.0, dspic::LAW_CENTS_SCALE);
        assert_eq!(32.79, dspic::LAW_OFFSET_A);
        assert_eq!(364.0704, dspic::LAW_NUMERATOR);
        assert_eq!(30.72, dspic::LAW_OFFSET_B);
        // And the shared law produces the same held doc point for this
        // generation: 910 cV -> PIC byte 4 (stock truncation semantics).
        assert_eq!(dspic::pic_byte_from_centivolts(910), Ok(4));
    }

    #[test]
    fn generation_set_voltage_wait_delta_is_recorded_not_inherited() {
        // Hydro build: 0x61a80 µs = 400 ms (set_Voltage_S9_plus_plus
        // @0x2fdd4+0xb6). R02's T9+ set-voltage wait is 100 ms. The delta
        // is pinned here so no lane can silently merge them.
        assert_eq!(0x61A80 / 1000, 400);
        assert_ne!(dspic::STOCK_SET_VOLTAGE_REPLY_WAIT_MS, 400);
        // Shared waits that ARE byte-identical across the binaries:
        assert_eq!(dspic::STOCK_HEARTBEAT_REPLY_WAIT_MS, 500);
        assert_eq!(dspic::STOCK_ENABLE_REPLY_WAIT_MS, 10);
        assert_eq!(dspic::STOCK_GET_VERSION_REPLY_WAIT_MS, 100);
    }

    // ------------------------------------------------------------------
    // Compile-time predicate byte laws.
    // ------------------------------------------------------------------

    #[test]
    fn predicate_byte_laws_are_distinct_and_exact() {
        assert_ne!(PREDICATE_FALSE_BYTES, PREDICATE_TRUE_BYTES);
        assert_eq!(PREDICATE_FALSE_BYTES, [0x00, 0x20, 0x70, 0x47]);
        assert_eq!(PREDICATE_TRUE_BYTES, [0x01, 0x20, 0x70, 0x47]);
    }

    #[test]
    fn compile_time_predicate_table_matches_held_bytes() {
        // Hydro build (@0x3a399..0x3a3b8): only is_S9_Hydro is true.
        assert!(S9_HYDRO_BUILD_IS_S9_HYDRO);
        assert!(!S9_HYDRO_BUILD_IS_S9_PLUS);
        assert!(!S9_HYDRO_BUILD_IS_S11);
        // S11 build (@0x37cd5..0x37cf4): is_S11 AND is_S9_plus true.
        assert!(S11_BUILD_IS_S11);
        assert!(S11_BUILD_IS_S9_PLUS);
        assert!(!S11_BUILD_IS_S9_HYDRO);
    }

    // ------------------------------------------------------------------
    // Board admission with per-board refusal reasons.
    // ------------------------------------------------------------------

    #[test]
    fn hydro_board_admits() {
        assert_eq!(admit_generation_board("am1-s9-hydro"), Ok(()));
    }

    #[test]
    fn s9_family_refused_as_bare_pic16() {
        for board in ["am1-s9", "am1-s9i", "am1-s9j"] {
            assert_eq!(
                admit_generation_board(board),
                Err(GenerationBoardError::S9FamilyIsBarePic16)
            );
        }
    }

    #[test]
    fn s11_and_t9plus_refused_for_ownership_reasons() {
        assert_eq!(
            admit_generation_board("am1-s11"),
            Err(GenerationBoardError::S11Unsettled)
        );
        assert_eq!(
            admit_generation_board("am1-t9plus"),
            Err(GenerationBoardError::T9PlusOwnedByAdapter)
        );
        assert_eq!(
            admit_generation_board("am2-s19pro"),
            Err(GenerationBoardError::UnknownBoard)
        );
    }

    // ------------------------------------------------------------------
    // S11 payload-selection law + inference-freedom pin.
    // ------------------------------------------------------------------

    #[test]
    fn s11_payload_selection_is_ctrl_bd_gated() {
        // runme.sh: grep XILINX /usr/bin/ctrl_bd -> xilinx payload.
        assert_eq!(
            select_s11_payload(Some(b"XILINX\n")),
            S11PayloadClass::UbiXilinx
        );
        assert_eq!(
            select_s11_payload(Some(b"7007 single core")),
            S11PayloadClass::Uramdisk7007
        );
        // Missing ctrl_bd is the script's is7010=0 default.
        assert_eq!(select_s11_payload(None), S11PayloadClass::Uramdisk7007);
        // Substring, matching grep semantics.
        assert_eq!(
            select_s11_payload(Some(b"board=XILINX-7010 rev B")),
            S11PayloadClass::UbiXilinx
        );
    }

    #[test]
    fn s11_asic_identity_stays_unproven_and_admits_no_wire_law() {
        // The inference-freedom pin: S11's silicon is Unproven, the 7007
        // payload launches only single-board-test, and no S11 wire
        // command set exists in this module — nothing here may be cited
        // as an S11 ASIC protocol, least of all a BM1390 inference (a jig
        // label cannot choose the ASIC; findings.md row "S11").
        assert_eq!(S11_ASIC_IDENTITY, "Unproven");
        assert_eq!(S11_7007_PAYLOAD_LAUNCHES, "single-board-test");
        // And the admission gate refuses S11 outright, so no wire law in
        // this module is reachable for an S11 board.
        assert_eq!(
            admit_generation_board("am1-s11"),
            Err(GenerationBoardError::S11Unsettled)
        );
    }

    #[test]
    fn s9_hydro_facets_keep_ambiguity_explicit() {
        // Generation-proven facets are distinct from capture-first ones;
        // nothing inherits from the S9/S9i/S9j/T9+/S21 lanes.
        assert_eq!(S9_HYDRO_PROFILE.pic_generation, S9HydroFacet::GenerationProven);
        assert_eq!(S9_HYDRO_PROFILE.asic_lineage, S9HydroFacet::GenerationProven);
        assert_eq!(S9_HYDRO_PROFILE.asic_identity_string, S9HydroFacet::Unproven);
        assert_eq!(S9_HYDRO_PROFILE.population, S9HydroFacet::Unproven);
        assert_eq!(S9_HYDRO_PROFILE.carrier, S9HydroFacet::Unproven);
        assert_eq!(S9_HYDRO_PROFILE.cooling, S9HydroFacet::HeldUnextracted);
        assert_eq!(S9_HYDRO_PROFILE.install, S9HydroFacet::Unproven);
    }

    #[test]
    fn hydro_jig_datums_are_marked_corroborating_only() {
        // The same "S9 HASH board" jig text ships for the S11 (where it
        // proves nothing); for the hydro it is corroboration, never the
        // identity source. These assertions pin the values so any drift
        // is visible.
        assert_eq!(S9_HYDRO_JIG_NAME, "S9 HASH board");
        assert_eq!(S9_HYDRO_JIG_ASIC_TYPE, 1387);
        assert_eq!(S9_HYDRO_JIG_ASIC_NUM, 63);
        assert_eq!(S9_HYDRO_JIG_CORE_NUM, 114);
        assert_eq!(
            S9_HYDRO_PROFILE.population,
            S9HydroFacet::Unproven,
            "jig AsicNum must never promote the population facet"
        );
    }

    #[test]
    fn held_source_pins_are_carried_in_module_constants() {
        assert_eq!(
            S9_HYDRO_BMMINER_SHA256,
            "81b89d0833cc5b368682b4ba1880b63f3b61ee992dc49f9402c9d4b0af92ac85"
        );
        assert_eq!(
            S11_BMMINER_SHA256,
            "a9417924750b7f9f2cd998f20d2cd402d542595f547635bcd54155f5aa24b8a2"
        );
    }
}
