//! S9 SE / BM1393 chip-register packers (desk-only).
//!
//! Numbers from S9k `asic.c` / `set_config_BM1393` / `enable_core_clock_BM1393`
//! / `set_core_number_BM1390` (stale name, BM1393 payload) and matching
//! S9 SE `cgminer` strings. No BC TX.

use crate::s9se_vil::{
    crc5_bits, pack_set_config_all, pack_set_config_single, pack_vil_short, CRC5_VIL_SHORT_BITS,
    HDR_READ_ALL, HDR_READ_SINGLE, VIL_LEN_SHORT,
};
use crate::ticket_mask::{bit_reverse_u32_bytewise, TicketMaskEncoding};

/// CHIP_ADDRESS (`set_core_number_BM1390` writes this).
pub const REG_CHIP_ADDRESS: u8 = 0x00;
/// HASH_COUNTING / PLL0 (`change_high_pll_test` `reg=8`).
pub const REG_PLL0: u8 = 0x08;
/// TICKET_MASK (`set_asic_ticket_mask` `buf[3]=20`).
pub const REG_TICKET_MASK: u8 = 0x14;
/// MISC_CONTROL (`set_misc_control` `buf[3]=24`).
pub const REG_MISC_CONTROL: u8 = 0x18;
/// CORE_CMD (`set_core_cmd_BM1393` / `strcpy(..., "<")`).
pub const REG_CORE_CMD: u8 = 0x3C;
/// PLL0 divider (`change_high_pll_test` `reg=112`).
pub const REG_PLL0_DIVIDER: u8 = 0x70;
pub const REG_PLL1: u8 = 0x60;
pub const REG_PLL1_DIVIDER: u8 = 0x74;
pub const REG_PLL2: u8 = 0x64;
pub const REG_PLL2_DIVIDER: u8 = 0x78;
pub const REG_PLL3: u8 = 0x68;
pub const REG_PLL3_DIVIDER: u8 = 0x7C;

/// `set_default_uart_baud`: `gBM1393_MISC_CONTROL_reg = 14849`.
pub const MISC_CONTROL_DEFAULT: u32 = 14_849; // 0x3A01
/// Baud field of `0x3A01` is 26 (`(0x3A01 >> 8) & 0x1F`).
pub const DEFAULT_BAUDDIV: u8 = 26;
/// `set_misc_control` I²C-enable OR (`16480`).
pub const MISC_I2C_ENABLE_BITS: u32 = 16_480; // 0x4060
/// Baud field: `reg = (reg & 0xFFFFE0FF) | ((bauddiv << 8) & 0x1F00)`.
pub const MISC_BAUD_CLEAR: u32 = 0xFFFF_E0FF;
pub const MISC_BAUD_MASK: u32 = 0x1F00;
pub const MISC_BAUD_SHIFT: u32 = 8;

/// S9k `set_core_number_BM1390@137d4` stores LE 0x00d09313, then
/// replaces its high byte with chip_addr: wire bytes 13 93 d0 addr.
/// Official S9 SE at 0x6fef0..0x6ff2c independently emits the same prefix.
pub const CORE_NUMBER_VALUE_HI: u32 = 0x1393_D000;
/// `enable_core_clock_BM1393`: cmd_type|rw `0x84`, data `0xAA`.
pub const CORE_ENABLE_CMD: u8 = 0x84;
pub const CORE_ENABLE_DATA: u8 = 0xAA;

/// Unused-PLL park (`set_unused_pll`).
pub const UNUSED_PLL_DIVIDER_FILL: u32 = 0x0F0F_0F0F;
pub const UNUSED_PLL_PARK_WORD: u32 = 0x8010_F0F7;
/// Operational divider fill (`(divider-1) | 0x0F0F0F00`).
pub const PLL_DIVIDER_FILL: u32 = 0x0F0F_0F00;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SeRegsError {
    BauddivOutOfRange { bauddiv: u8 },
}

pub fn misc_with_baud(misc: u32, bauddiv: u8) -> Result<u32, S9SeRegsError> {
    if u32::from(bauddiv) > 0x1F {
        return Err(S9SeRegsError::BauddivOutOfRange { bauddiv });
    }
    Ok((misc & MISC_BAUD_CLEAR) | ((u32::from(bauddiv) << MISC_BAUD_SHIFT) & MISC_BAUD_MASK))
}

pub fn misc_with_i2c(misc: u32) -> u32 {
    misc | MISC_I2C_ENABLE_BITS
}

/// VIL 5-byte read (`read_asic_register` `opt_multi_version`): CRC5 over 32 bits.
pub fn pack_read_vil(chip_addr: u8, reg: u8, broadcast: bool) -> [u8; 5] {
    let header = if broadcast {
        HDR_READ_ALL
    } else {
        HDR_READ_SINGLE
    };
    let mut frame = [header, VIL_LEN_SHORT, chip_addr, reg, 0];
    frame[4] = crc5_bits(&frame[..4], CRC5_VIL_SHORT_BITS);
    frame
}

pub fn pack_misc_broadcast(misc: u32) -> [u8; 9] {
    pack_set_config_all(0, REG_MISC_CONTROL, misc)
}

pub fn pack_ticket_mask_broadcast(ticket_mask: u32) -> [u8; 9] {
    // S9k: bswap then per-byte bit-reverse into the register payload.
    // Equivalent to `bit_reverse_u32_bytewise` of the original word.
    let encoded = bit_reverse_u32_bytewise(ticket_mask);
    pack_set_config_all(0, REG_TICKET_MASK, encoded)
}

pub fn pack_core_number(chip_addr: u8) -> [u8; 9] {
    pack_set_config_single(
        0,
        REG_CHIP_ADDRESS,
        CORE_NUMBER_VALUE_HI | u32::from(chip_addr),
    )
}

/// `enable_core_clock_BM1393(..., mode=1, ...)` broadcast CORE_CMD.
/// `.data g_Clock_delay_control` initial byte.
pub const CLOCK_DELAY_INITIAL: u8 = 2;
/// Always OR'd in `set_clock_delay_control`.
pub const CLOCK_DELAY_OR_BIT: u8 = 4;
/// Pulse-mode bit (`|= 2` / `&= ~2`).
pub const CLOCK_DELAY_PULSE_BIT: u8 = 2;

pub fn clock_delay_byte(pulse_mode: bool) -> u8 {
    let mut v = CLOCK_DELAY_INITIAL;
    if pulse_mode {
        v |= CLOCK_DELAY_PULSE_BIT;
    } else {
        v &= !CLOCK_DELAY_PULSE_BIT;
    }
    v | CLOCK_DELAY_OR_BIT
}

/// `set_clock_delay_control` CORE_CMD: broadcast, core_mode, cmd_type 0, rw=1.
pub fn pack_clock_delay_control(pulse_mode: bool) -> [u8; 9] {
    let data = clock_delay_byte(pulse_mode);
    let mut frame = pack_set_config_all(0, REG_CORE_CMD, 0);
    frame[4] = 0x80;
    frame[5] = 0;
    frame[6] = 0x80; // cmd_type 0 | rw_flag<<7
    frame[7] = data;
    frame[8] = crc5_bits(&frame[..8], crate::s9se_vil::CRC5_VIL_SET_CONFIG_BITS);
    frame
}

/// Chip register that returns a CORE_CMD read (`register_process_core_response`).
pub const REG_CORE_RESPONSE: u8 = 0x40;
/// `register_dump_core_reg` / S9 SE `CORE_REG[%d]` strings.
pub const CORE_REG_CLOCK_DELAY: u8 = 0;
pub const CORE_REG_PROCESS_MONITOR_CTRL: u8 = 1;
pub const CORE_REG_PROCESS_MONITOR_DATA: u8 = 2;
pub const CORE_REG_CORE_ERROR: u8 = 3;
pub const CORE_REG_CORE_ENABLE: u8 = 4;
pub const CORE_REG_HASH_CLOCK_CTRL: u8 = 5;
pub const CORE_REG_HASH_CLOCK_COUNTER: u8 = 6;
pub const CORE_REG_SWEEP_CLOCK_CTRL: u8 = 7;
/// `register_build_core_command_read_one` `_REG_WDATA = -1`.
pub const CORE_REG_READ_WDATA: u8 = 0xFF;
/// CORE_REG[0] bitfields (`register_parse_clock_delay_ctrl`).
pub const CORE_REG0_SWPF_MODE: u8 = 1 << 0;
pub const CORE_REG0_MMEN: u8 = 1 << 2;
pub const CORE_REG0_HASH_CLKEN: u8 = 1 << 3;
/// `CLOCK_CNT = 0x%08x freq = 2 * cnt * 6.25`.
pub const HASH_CLOCK_CNT_MHZ: f64 = 12.5;

pub fn core_reg_name(reg: u8) -> Option<&'static str> {
    Some(match reg {
        0 => "Clock Delay Ctrl",
        1 => "Process Monitor Ctrl",
        2 => "Process Monitor Data",
        3 => "Core Error",
        4 => "Core Enable",
        5 => "Hash Clock Control",
        6 => "Hash Clock Counter",
        7 => "Sweep Clock Control",
        _ => return None,
    })
}

pub fn clock_delay_ccdly_sel(v: u8) -> u8 {
    v >> 6
}

pub fn clock_delay_pwth_sel(v: u8) -> u8 {
    (v >> 4) & 3
}

pub fn hash_clock_freq_mhz(clock_cnt: u8) -> f64 {
    f64::from(clock_cnt) * HASH_CLOCK_CNT_MHZ
}

/// `register_build_core_command_read_one` → set-config to one ASIC.
pub fn pack_core_reg_read_one(chip_addr: u8, core_id: u8, core_reg: u8) -> [u8; 9] {
    pack_core_cmd(
        false,
        chip_addr,
        false,
        core_id,
        core_reg & 7,
        false,
        CORE_REG_READ_WDATA,
    )
}

/// `register_build_core_command_write_all` → all cores on one ASIC.
pub fn pack_core_reg_write_all(chip_addr: u8, core_reg: u8, data: u8) -> [u8; 9] {
    pack_core_cmd(false, chip_addr, true, 0, core_reg & 7, true, data)
}

/// S9 SE `set_baud_with_addr@0x71844` default VIL path (flags 0):
/// value bytes `40 21 bauddiv 00`, not `misc_with_baud(0x3A01, …)`.
pub const BAUD_WITH_ADDR_BYTE0: u8 = 0x40;
pub const BAUD_WITH_ADDR_BYTE1: u8 = 0x21;

/// S9 SE `set_baud_one_chain` VIL path: broadcast MISC with baud field
/// inserted into `gBM1393_MISC_CONTROL_reg` (`& ~0x1F00 | bauddiv<<8`).
/// Distinct from `pack_baud_with_addr` (`40 21 bauddiv 00`). Not a TX permit.
pub fn pack_baud_one_chain(bauddiv: u8) -> Result<[u8; 9], S9SeRegsError> {
    let misc = misc_with_baud(MISC_CONTROL_DEFAULT, bauddiv)?;
    Ok(pack_misc_broadcast(misc))
}

/// Single-chip VIL baud frame. Not a TX permit.
pub fn pack_baud_with_addr(chip_addr: u8, bauddiv: u8) -> Result<[u8; 9], S9SeRegsError> {
    if u32::from(bauddiv) > 0x1F {
        return Err(S9SeRegsError::BauddivOutOfRange { bauddiv });
    }
    let mut frame = pack_set_config_single(chip_addr, REG_MISC_CONTROL, 0);
    frame[4] = BAUD_WITH_ADDR_BYTE0;
    frame[5] = BAUD_WITH_ADDR_BYTE1;
    frame[6] = bauddiv;
    frame[7] = 0;
    frame[8] = crc5_bits(&frame[..8], crate::s9se_vil::CRC5_VIL_SET_CONFIG_BITS);
    Ok(frame)
}

/// `set_core_cmd_BM1393`: `buf[0]=0x41|(mode?0x10:0)`, `buf[3]='<'`.
pub fn pack_core_cmd(
    broadcast: bool,
    chip_addr: u8,
    core_mode: bool,
    core_id: u8,
    cmd_type: u8,
    rw: bool,
    data: u8,
) -> [u8; 9] {
    let header = if broadcast { 0x51 } else { 0x41 };
    let mut frame = pack_set_config_all(chip_addr, REG_CORE_CMD, 0);
    frame[0] = header;
    frame[2] = chip_addr;
    frame[3] = REG_CORE_CMD;
    frame[4] = if core_mode { 0x80 } else { 0 };
    frame[5] = core_id;
    frame[6] = cmd_type | (u8::from(rw) << 7);
    frame[7] = data;
    frame[8] = crc5_bits(&frame[..8], crate::s9se_vil::CRC5_VIL_SET_CONFIG_BITS);
    frame
}

pub fn pack_enable_core_clock(core_id: u8) -> [u8; 9] {
    let mut frame = pack_set_config_all(0, REG_CORE_CMD, 0);
    // Overwrite value bytes: [4]=0, [5]=core_id, [6]=0x84, [7]=0xAA.
    frame[4] = 0;
    frame[5] = core_id;
    frame[6] = CORE_ENABLE_CMD;
    frame[7] = CORE_ENABLE_DATA;
    frame[8] = crc5_bits(&frame[..8], crate::s9se_vil::CRC5_VIL_SET_CONFIG_BITS);
    frame
}

pub fn pack_pll0_divider(divider: u8) -> [u8; 9] {
    let value = PLL_DIVIDER_FILL | u32::from(divider.saturating_sub(1));
    pack_set_config_all(0, REG_PLL0_DIVIDER, value)
}

pub fn pack_pll0_word(vil_pll_be: u32) -> [u8; 9] {
    pack_set_config_all(0, REG_PLL0, vil_pll_be)
}

pub fn s9se_ticket_mask_encoding() -> TicketMaskEncoding {
    TicketMaskEncoding::BitReversed
}

/// `set_address` VIL is 5-byte; kept here so init can name one crate path.
pub fn pack_set_address(addr: u8) -> [u8; 5] {
    pack_vil_short(crate::s9se_vil::HDR_SET_ADDR, addr).expect("0x40 is VIL")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misc_default_is_0x3a01() {
        assert_eq!(MISC_CONTROL_DEFAULT, 0x3A01);
        assert_eq!(DEFAULT_BAUDDIV, ((MISC_CONTROL_DEFAULT >> 8) & 0x1F) as u8);
        assert_eq!(DEFAULT_BAUDDIV, 26);
        let with_i2c = misc_with_i2c(MISC_CONTROL_DEFAULT);
        assert_eq!(with_i2c, 0x7A61);
        let baud26 = misc_with_baud(MISC_CONTROL_DEFAULT, 26).unwrap();
        assert_eq!((baud26 >> 8) & 0x1F, 26);
        let cmd = pack_core_cmd(true, 0, true, 0, 0, true, 4);
        assert_eq!(cmd[0], 0x51);
        assert_eq!(cmd[3], REG_CORE_CMD);
        assert_eq!(cmd[4], 0x80);
        assert_eq!(cmd[6], 0x80);
        assert_eq!(cmd[7], 4);
    }

    #[test]
    fn core_number_pins_208_cores_and_addr() {
        let frame = pack_core_number(0x78);
        assert_eq!(frame[0], 0x41);
        assert_eq!(frame[3], REG_CHIP_ADDRESS);
        assert_eq!(frame[4], 0x13);
        assert_eq!(frame[5], 0x93);
        assert_eq!(frame[6], 0xD0);
        assert_eq!(frame[7], 0x78);
    }

    #[test]
    fn clock_delay_pulse_off_is_4_pulse_on_is_6() {
        assert_eq!(clock_delay_byte(false), 4);
        assert_eq!(clock_delay_byte(true), 6);
        let frame = pack_clock_delay_control(false);
        assert_eq!(frame[0], 0x51);
        assert_eq!(frame[3], REG_CORE_CMD);
        assert_eq!(frame[4], 0x80);
        assert_eq!(frame[6], 0x80);
        assert_eq!(frame[7], 4);
    }

    #[test]
    fn enable_core_is_broadcast_core_cmd() {
        let frame = pack_enable_core_clock(51);
        assert_eq!(frame[0], 0x51);
        assert_eq!(frame[3], REG_CORE_CMD);
        assert_eq!(frame[5], 51);
        assert_eq!(frame[6], 0x84);
        assert_eq!(frame[7], 0xAA);
    }

    #[test]
    fn core_reg_map_and_read_write_match_stock() {
        assert_eq!(core_reg_name(0), Some("Clock Delay Ctrl"));
        assert_eq!(core_reg_name(6), Some("Hash Clock Counter"));
        assert_eq!(core_reg_name(8), None);
        assert_eq!(REG_CORE_RESPONSE, 64);
        let read = pack_core_reg_read_one(0x02, 51, CORE_REG_HASH_CLOCK_COUNTER);
        assert_eq!(read[0], 0x41);
        assert_eq!(read[2], 0x02);
        assert_eq!(read[3], REG_CORE_CMD);
        assert_eq!(read[4], 0);
        assert_eq!(read[5], 51);
        assert_eq!(read[6], CORE_REG_HASH_CLOCK_COUNTER);
        assert_eq!(read[7], 0xFF);
        let write = pack_core_reg_write_all(0x02, CORE_REG_HASH_CLOCK_CTRL, 1);
        assert_eq!(write[4], 0x80);
        assert_eq!(write[5], 0);
        assert_eq!(write[6], CORE_REG_HASH_CLOCK_CTRL | 0x80);
        assert_eq!(write[7], 1);
        assert_eq!(clock_delay_ccdly_sel(0xC0), 3);
        assert_eq!(clock_delay_pwth_sel(0x30), 3);
        assert_eq!(hash_clock_freq_mhz(8), 100.0);
        let baud = pack_baud_with_addr(0x02, 1).unwrap();
        assert_eq!(
            &baud[..8],
            &[0x41, 0x09, 0x02, 0x18, 0x40, 0x21, 0x01, 0x00]
        );
        assert_eq!(
            baud[8],
            crc5_bits(&baud[..8], crate::s9se_vil::CRC5_VIL_SET_CONFIG_BITS)
        );
        assert_ne!(
            &baud[4..8],
            &misc_with_baud(MISC_CONTROL_DEFAULT, 1)
                .unwrap()
                .to_be_bytes()
        );
    }

    #[test]
    fn baud_with_addr_is_4021_not_3a01_misc() {
        let frame = pack_baud_with_addr(0x02, 1).unwrap();
        assert_eq!(frame, {
            let mut expected = [0x41, 0x09, 0x02, 0x18, 0x40, 0x21, 0x01, 0x00, 0];
            expected[8] = crc5_bits(&expected[..8], crate::s9se_vil::CRC5_VIL_SET_CONFIG_BITS);
            expected
        });
        assert!(pack_baud_with_addr(0, 0x20).is_err());
    }

    #[test]
    fn baud_one_chain_is_broadcast_misc_not_4021() {
        let chain = pack_baud_one_chain(1).unwrap();
        assert_eq!(chain[0], 0x51);
        assert_eq!(chain[3], REG_MISC_CONTROL);
        let misc = misc_with_baud(MISC_CONTROL_DEFAULT, 1).unwrap();
        assert_eq!(&chain[4..8], &misc.to_be_bytes());
        let per_chip = pack_baud_with_addr(0x02, 1).unwrap();
        assert_ne!(&chain[4..8], &per_chip[4..8]);
        assert_eq!(&per_chip[4..8], &[0x40, 0x21, 0x01, 0x00]);
        assert!(pack_baud_one_chain(0x20).is_err());
    }

    #[test]
    fn ticket_mask_reg_is_0x14_not_bm1387_0x18() {
        assert_eq!(REG_TICKET_MASK, 0x14);
        assert_eq!(s9se_ticket_mask_encoding(), TicketMaskEncoding::BitReversed);
        let frame = pack_ticket_mask_broadcast(0x3F);
        assert_eq!(frame[3], 0x14);
        assert_eq!(&frame[4..8], &[0x00, 0x00, 0x00, 0xFC]);
    }

    #[test]
    fn vil_read_includes_register_byte() {
        let frame = pack_read_vil(0x78, REG_CHIP_ADDRESS, false);
        assert_eq!(frame[0], 0x42);
        assert_eq!(frame[1], 5);
        assert_eq!(frame[2], 0x78);
        assert_eq!(frame[3], 0x00);
        assert_eq!(frame[4], crc5_bits(&frame[..4], 32));
    }
}
