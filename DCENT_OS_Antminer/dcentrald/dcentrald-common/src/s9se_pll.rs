//! S9 SE / BM1393 PLL facts (desk-only).
//!
//! S9 SE `cgminer` carries the same solver strings as S9k
//! `get_pllparam_divider@129D8` / `change_high_pll_test@22DEC`:
//! "using 200M pll", `vil pll data:%s`, VCO walk 2400–2800 MHz, xtal 25 MHz.
//! Frequency program stays refused — no executor.

use crate::s9se_enum::S9SE_ADDR_INTERVAL;
use crate::s9se_regs::{
    pack_pll0_divider, pack_pll0_word, PLL_DIVIDER_FILL, REG_PLL0, REG_PLL0_DIVIDER, REG_PLL1,
    REG_PLL1_DIVIDER, REG_PLL2, REG_PLL2_DIVIDER, REG_PLL3, REG_PLL3_DIVIDER,
    UNUSED_PLL_DIVIDER_FILL, UNUSED_PLL_PARK_WORD,
};
use crate::s9se_vil::{pack_set_config, pack_set_config_all};

/// Same 179-entry bound as S9k `get_plldata_from_index` (`index > 178` fails).
pub const PLL_TABLE_ENTRY_COUNT: usize = 179;
pub const PLL_TABLE_MAX_INDEX: u8 = 178;
pub const PLL_XTAL_MHZ: f64 = 25.0;
pub const PLL_VCO_MIN_MHZ: f64 = 2400.0;
pub const PLL_VCO_MAX_SEARCH_MHZ: f64 = 2800.0;
/// Solver fallback ("using 200M pll"): word `7864593`, divider `15`.
pub const PLL_FALLBACK_WORD: u32 = 0x0078_0111;
pub const PLL_FALLBACK_DIVIDER: u8 = 15;
pub const PLL_SOLVER_FAILURE: i32 = -1;
pub const PLL_ENABLE_BIT_IN_BE_BYTE0: u8 = 0x40;

/// `freq_pll_1393` from unstripped S9k `cgminer` `.data` (`val=0xa82a4`,
/// 179 × 16 B). S9 SE `cgminer` is stripped but carries the same
/// `get_plldata_from_index` / `vil pll data:%s` strings. Column 0 is
/// MHz; column 1 is `vilpll` (`get_plldata_from_index`).
pub const FREQ_PLL_1393: [(u16, u32); 179] = [
    (19, 0x200273),
    (22, 0x200263),
    (26, 0x200253),
    (28, 0x200272),
    (33, 0x200243),
    (40, 0x200252),
    (50, 0x200242),
    (57, 0x200271),
    (66, 0x200261),
    (80, 0x200251),
    (100, 0x200241),
    (125, 0x280241),
    (150, 0x780154),
    (175, 0x380241),
    (200, 0x400241),
    (225, 0x480241),
    (250, 0x500241),
    (275, 0x580241),
    (300, 0x780152),
    (303, 0x610241),
    (306, 0x620241),
    (309, 0x630241),
    (312, 0x640241),
    (315, 0x650241),
    (318, 0x660241),
    (321, 0x670241),
    (325, 0x680241),
    (328, 0x690241),
    (331, 0x6A0241),
    (334, 0x6B0241),
    (337, 0x6C0241),
    (340, 0x6D0241),
    (343, 0x6E0241),
    (346, 0x6F0241),
    (350, 0x540132),
    (353, 0x710241),
    (356, 0x720241),
    (359, 0x730241),
    (362, 0x740241),
    (365, 0x750241),
    (368, 0x760241),
    (371, 0x770241),
    (375, 0x780241),
    (378, 0x790241),
    (381, 0x7A0241),
    (384, 0x7B0241),
    (387, 0x7C0241),
    (390, 0x7D0241),
    (393, 0x7E0241),
    (396, 0x7F0241),
    (400, 0x800241),
    (404, 0x610231),
    (406, 0x410221),
    (408, 0x620231),
    (412, 0x420221),
    (416, 0x640231),
    (418, 0x430221),
    (420, 0x650231),
    (425, 0x440221),
    (429, 0x670231),
    (431, 0x450221),
    (433, 0x680231),
    (437, 0x460221),
    (441, 0x6A0231),
    (443, 0x470221),
    (445, 0x6B0231),
    (450, 0x480221),
    (454, 0x6D0231),
    (456, 0x490221),
    (458, 0x6E0231),
    (462, 0x4A0221),
    (466, 0x700231),
    (468, 0x4B0221),
    (470, 0x710231),
    (475, 0x4C0221),
    (479, 0x730231),
    (481, 0x4D0221),
    (483, 0x740231),
    (487, 0x4E0221),
    (491, 0x760231),
    (493, 0x4F0221),
    (495, 0x770231),
    (500, 0x500221),
    (504, 0x790231),
    (506, 0x510221),
    (508, 0x7A0231),
    (512, 0x520221),
    (516, 0x7C0231),
    (518, 0x530221),
    (520, 0x7D0231),
    (525, 0x540221),
    (529, 0x7F0231),
    (531, 0x550221),
    (533, 0x800231),
    (537, 0x560221),
    (543, 0x570221),
    (550, 0x580221),
    (556, 0x590221),
    (562, 0x5A0221),
    (568, 0x5B0221),
    (575, 0x5C0221),
    (581, 0x5D0221),
    (587, 0x5E0221),
    (593, 0x5F0221),
    (600, 0x600141),
    (606, 0x610221),
    (612, 0x620221),
    (618, 0x630221),
    (625, 0x640221),
    (631, 0x650221),
    (637, 0x660221),
    (643, 0x670221),
    (650, 0x680221),
    (656, 0x690221),
    (662, 0x6A0221),
    (668, 0x6B0221),
    (675, 0x6C0221),
    (681, 0x6D0221),
    (687, 0x6E0221),
    (693, 0x6F0221),
    (700, 0x700221),
    (706, 0x710221),
    (712, 0x720221),
    (718, 0x730221),
    (725, 0x740221),
    (731, 0x750221),
    (737, 0x760221),
    (743, 0x770221),
    (750, 0x780221),
    (756, 0x790221),
    (762, 0x7A0221),
    (768, 0x7B0221),
    (775, 0x7C0221),
    (781, 0x7D0221),
    (787, 0x7E0221),
    (793, 0x7F0221),
    (800, 0x800221),
    (825, 0x420211),
    (850, 0x440211),
    (875, 0x460211),
    (900, 0x6C0131),
    (925, 0x4A0211),
    (950, 0x4C0211),
    (975, 0x4E0211),
    (1000, 0x500211),
    (1025, 0x520211),
    (1050, 0x540211),
    (1075, 0x560211),
    (1100, 0x580211),
    (1125, 0x5A0211),
    (1150, 0x5C0211),
    (1175, 0x5E0211),
    (1200, 0x600211),
    (1300, 0x680211),
    (1400, 0x700211),
    (1500, 0x780211),
    (1600, 0x800211),
    (1700, 0x880211),
    (1800, 0x900211),
    (1900, 0x980211),
    (2000, 0x500111),
    (2100, 0x540111),
    (2200, 0x580111),
    (2300, 0x5C0111),
    (2400, 0x600111),
    (2500, 0x640111),
    (2550, 0xCC0211),
    (2600, 0x680111),
    (2625, 0xD20211),
    (2700, 0x6C0111),
    (2750, 0xDC0211),
    (2800, 0x700111),
    (2850, 0xE40211),
    (2875, 0xE60211),
    (2900, 0x740111),
    (3000, 0x780111),
    (3100, 0x7C0111),
    (3200, 0x800111),
    (3300, 0x840111),
];

/// S9 SE `.data` `freq_high_pll_1393` at `0xa4e28` (file `0x94e28`), 33 × 12 B.
/// Layout: `freq:u32le`, `divider:u8` at +4, `pll_out:u32le` at +5.
/// Byte-identical to the S9k symbol of the same name (`0xa8dd4`, size 396).
pub const HIGH_PLL_TABLE_COUNT: usize = 33;
pub const HIGH_PLL_MAX_INDEX: u8 = 32;
pub const HIGH_PLL_DEFAULT_INDEX: u8 = 4; // 200 MHz
pub const S9SE_CGMINER_HIGH_PLL_FILE_OFF: usize = 0x94E28;
/// The official Bitmain OM 2019-09-18 `cgminer` build (opkg `cgminer-t11
/// 1.0-r1.29`, 614796 B) carries the same 33 × 12 table, shifted deeper into
/// `.data` by the larger September build. Cross-adjudication 2026-08-17.
pub const OFFICIAL_S9SE_CGMINER_HIGH_PLL_FILE_OFF: usize = 0x95A38;
/// Length of the `freq_pll_1393` region sitting immediately before
/// `freq_high_pll_1393` in both S9 SE builds (179 × 16 B) — byte-identical
/// across the July HiveOS and September OM builds.
pub const S9SE_PLL_REGION_LEN: usize = 179 * 16;
pub const S9SE_CGMINER_HIGH_PLL_STRIDE: usize = 12;
/// Both production models use `asic << 2` in the per-ASIC PLL path.
pub const S9K_PLL_ADDR_INTERVAL: u8 = 4;

pub const FREQ_HIGH_PLL_1393: [(u16, u8, u16); 33] = [
    (100, 15, 1500),
    (125, 12, 1500),
    (150, 10, 1500),
    (175, 12, 2100),
    (200, 15, 3000),
    (225, 12, 2700),
    (250, 12, 3000),
    (275, 10, 2750),
    (300, 10, 3000),
    (325, 8, 2600),
    (350, 8, 2800),
    (375, 8, 3000),
    (400, 7, 2800),
    (425, 6, 2550),
    (450, 6, 2700),
    (475, 6, 2850),
    (500, 6, 3000),
    (525, 5, 2625),
    (550, 5, 2750),
    (575, 5, 2870),
    (600, 5, 3000),
    (625, 4, 2500),
    (650, 4, 2600),
    (675, 4, 2700),
    (700, 4, 2800),
    (725, 4, 2900),
    (750, 4, 3000),
    (775, 4, 3100),
    (800, 4, 3200),
    (825, 4, 3300),
    (850, 3, 2550),
    (875, 3, 2625),
    (900, 3, 2700),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9SePllWord {
    pub fbdiv: u8,
    pub refdiv: u8,
    pub postdiv1: u8,
    pub postdiv2: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S9SePllPlan {
    pub divider_reg: u8,
    pub divider_value: u32,
    pub pll_reg: u8,
    pub pll_value: u32,
    pub repeat: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S9SePllError {
    FrequencyProgramRefused,
    ZeroDivider,
    IndexOutOfRange { index: u8 },
    ChipAddressMismatch { asic: u8, chip_addr: u8 },
}

pub fn decode_pll_word(word: u32) -> S9SePllWord {
    S9SePllWord {
        fbdiv: ((word >> 16) & 0xFF) as u8,
        refdiv: ((word >> 8) & 0xFF) as u8,
        postdiv1: ((word >> 4) & 0x0F) as u8,
        postdiv2: (word & 0x0F) as u8,
    }
}

pub fn encode_pll_word(w: S9SePllWord) -> u32 {
    u32::from(w.postdiv2)
        | (u32::from(w.postdiv1) << 4)
        | (u32::from(w.refdiv) << 8)
        | (u32::from(w.fbdiv) << 16)
}

/// `f = 25 MHz × fbdiv / (refdiv × pd1 × pd2 × pll_div)`.
pub fn pll_output_mhz(word: u32, pll_div: u8) -> Option<f64> {
    let w = decode_pll_word(word);
    if w.refdiv == 0 || w.postdiv1 == 0 || w.postdiv2 == 0 || pll_div == 0 {
        return None;
    }
    Some(
        PLL_XTAL_MHZ * f64::from(w.fbdiv)
            / (f64::from(w.refdiv)
                * f64::from(w.postdiv1)
                * f64::from(w.postdiv2)
                * f64::from(pll_div)),
    )
}

/// Operational four-write spine from `change_high_pll_test`:
/// divider@0x70, pll@0x08, divider@0x70, pll@0x08.
pub fn operational_pll_plan(raw_word: u32, divider: u8) -> Result<S9SePllPlan, S9SePllError> {
    if divider == 0 {
        return Err(S9SePllError::ZeroDivider);
    }
    Ok(S9SePllPlan {
        divider_reg: REG_PLL0_DIVIDER,
        divider_value: PLL_DIVIDER_FILL | u32::from(divider - 1),
        pll_reg: REG_PLL0,
        pll_value: raw_word,
        repeat: 2,
    })
}

pub fn refuse_s9se_frequency_program() -> Result<(), S9SePllError> {
    Err(S9SePllError::FrequencyProgramRefused)
}

/// `increase_freq_slowly`: ceil((final-init)/step) points, last clamped.
pub fn freq_climb_mhz(init: u16, final_freq: u16, step: u16) -> Result<Vec<u16>, S9SePllError> {
    if step == 0 {
        return Err(S9SePllError::ZeroDivider);
    }
    if final_freq <= init {
        return Ok(vec![final_freq]);
    }
    let mut out = Vec::new();
    let mut next = init.saturating_add(step);
    while next < final_freq {
        out.push(next);
        next = next.saturating_add(step);
    }
    out.push(final_freq);
    Ok(out)
}

pub fn refuse_pll_index_out_of_table(index: u8) -> Result<(), S9SePllError> {
    if index > PLL_TABLE_MAX_INDEX {
        return Err(S9SePllError::IndexOutOfRange { index });
    }
    Ok(())
}

/// Decode one 12-byte `freq_high_pll_1393` row from the held S9 SE ELF.
pub fn decode_high_pll_row(raw12: &[u8; 12]) -> (u16, u8, u16) {
    let freq = u32::from_le_bytes([raw12[0], raw12[1], raw12[2], raw12[3]]) as u16;
    let divider = raw12[4];
    let pll_out = u32::from_le_bytes([raw12[5], raw12[6], raw12[7], raw12[8]]) as u16;
    (freq, divider, pll_out)
}

pub fn freq_high_pll_1393_row(index: u8) -> Result<(u16, u8, u16), S9SePllError> {
    if index > HIGH_PLL_MAX_INDEX {
        return Err(S9SePllError::IndexOutOfRange { index });
    }
    Ok(FREQ_HIGH_PLL_1393[usize::from(index)])
}

/// `get_index_from_high_pll`: exact row, else first row that brackets `freq`.
/// Out of 100..=900 falls back to the 200 MHz index (stock recurse).
pub fn get_index_from_high_pll(freq_mhz: u16) -> u8 {
    for i in 0..=HIGH_PLL_MAX_INDEX {
        let (row_freq, _, _) = FREQ_HIGH_PLL_1393[usize::from(i)];
        if row_freq == freq_mhz {
            return i;
        }
        if i > 0 {
            let (prev, _, _) = FREQ_HIGH_PLL_1393[usize::from(i - 1)];
            if row_freq > freq_mhz && prev < freq_mhz {
                return i;
            }
        } else if row_freq > freq_mhz {
            return HIGH_PLL_DEFAULT_INDEX;
        }
    }
    HIGH_PLL_DEFAULT_INDEX
}

/// S9 SE `set_frequency_with_addr@0x3cbec` writes **only** PLL0 (`0x08`).
/// It is not the operational 0x70 / 0x08 spine. Not a program permit.
pub fn pack_frequency_with_addr(broadcast: bool, chip_addr: u8, vil_pll: u32) -> [u8; 9] {
    pack_set_config(broadcast, chip_addr, REG_PLL0, vil_pll)
}

/// Both held S9 SE production ELFs and S9k use 60 populated addresses at stride four.
pub fn s9se_chip_addr_from_asic_index(asic: u8) -> Option<u8> {
    (asic < crate::s9se_enum::S9SE_CHIPS_PER_CHAIN).then(|| asic * S9SE_ADDR_INTERVAL)
}

pub fn admit_s9se_chip_address(asic: u8, chip_addr: u8) -> Result<(), S9SePllError> {
    if s9se_chip_addr_from_asic_index(asic) != Some(chip_addr) {
        return Err(S9SePllError::ChipAddressMismatch { asic, chip_addr });
    }
    Ok(())
}

pub fn freq_pll_1393_row(index: u8) -> Result<(u16, u32), S9SePllError> {
    refuse_pll_index_out_of_table(index)?;
    Ok(FREQ_PLL_1393[usize::from(index)])
}

/// Packed frames for the operational spine. Not a TX permit.
pub fn pack_operational_pll_frames(
    raw_word: u32,
    divider: u8,
) -> Result<[[u8; 9]; 4], S9SePllError> {
    let _ = operational_pll_plan(raw_word, divider)?;
    Ok([
        pack_pll0_divider(divider),
        pack_pll0_word(raw_word),
        pack_pll0_divider(divider),
        pack_pll0_word(raw_word),
    ])
}

/// `set_unused_pll`: park PLL1/2/3 (each pair written twice). Not a TX permit.
pub fn pack_unused_pll_park_frames() -> [[u8; 9]; 12] {
    let pairs = [
        (
            REG_PLL1_DIVIDER,
            UNUSED_PLL_DIVIDER_FILL,
            REG_PLL1,
            UNUSED_PLL_PARK_WORD,
        ),
        (
            REG_PLL2_DIVIDER,
            UNUSED_PLL_DIVIDER_FILL,
            REG_PLL2,
            UNUSED_PLL_PARK_WORD,
        ),
        (
            REG_PLL3_DIVIDER,
            UNUSED_PLL_DIVIDER_FILL,
            REG_PLL3,
            UNUSED_PLL_PARK_WORD,
        ),
    ];
    let mut out = [[0u8; 9]; 12];
    let mut i = 0;
    for (dreg, dval, preg, pval) in pairs {
        let d = pack_set_config_all(0, dreg, dval);
        let p = pack_set_config_all(0, preg, pval);
        out[i] = d;
        out[i + 1] = p;
        out[i + 2] = d;
        out[i + 3] = p;
        i += 4;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_is_200mhz() {
        let mhz = pll_output_mhz(PLL_FALLBACK_WORD, PLL_FALLBACK_DIVIDER).unwrap();
        assert!((mhz - 200.0).abs() < 0.01, "mhz={mhz}");
        let w = decode_pll_word(PLL_FALLBACK_WORD);
        assert_eq!(w.fbdiv, 0x78);
        assert_eq!(w.refdiv, 1);
        assert_eq!(w.postdiv1, 1);
        assert_eq!(w.postdiv2, 1);
        assert_eq!(encode_pll_word(w), PLL_FALLBACK_WORD);
    }

    #[test]
    fn table_bound_is_179() {
        assert_eq!(PLL_TABLE_ENTRY_COUNT, 179);
        assert_eq!(FREQ_PLL_1393.len(), 179);
        refuse_pll_index_out_of_table(178).unwrap();
        assert!(refuse_pll_index_out_of_table(179).is_err());
        assert_eq!(freq_pll_1393_row(0).unwrap(), (19, 0x200273));
        assert_eq!(freq_pll_1393_row(14).unwrap(), (200, 0x400241));
        assert_eq!(freq_pll_1393_row(175).unwrap(), (3000, 0x780111));
        assert_ne!(
            freq_pll_1393_row(14).unwrap().1,
            PLL_FALLBACK_WORD,
            "table 200 MHz is not the solver fallback word"
        );
        assert_eq!(freq_pll_1393_row(175).unwrap().1, PLL_FALLBACK_WORD);
    }

    #[test]
    fn operational_plan_is_70_then_08_twice() {
        let plan = operational_pll_plan(PLL_FALLBACK_WORD, 15).unwrap();
        assert_eq!(plan.divider_reg, 0x70);
        assert_eq!(plan.pll_reg, 0x08);
        assert_eq!(plan.repeat, 2);
        assert_eq!(plan.divider_value, 0x0F0F_0F0E);
        let frames = pack_operational_pll_frames(PLL_FALLBACK_WORD, 15).unwrap();
        assert_eq!(frames[0][3], 0x70);
        assert_eq!(frames[1][3], 0x08);
        assert_eq!(frames[2][3], 0x70);
        assert_eq!(frames[3][3], 0x08);
        assert_eq!(
            refuse_s9se_frequency_program(),
            Err(S9SePllError::FrequencyProgramRefused)
        );
        let park = pack_unused_pll_park_frames();
        assert_eq!(park.len(), 12);
        assert_eq!(park[0][3], 0x74);
        assert_eq!(park[1][3], 0x60);
        assert_eq!(park[4][3], 0x78);
        assert_eq!(park[8][3], 0x7C);
        assert_eq!(freq_climb_mhz(100, 250, 50).unwrap(), vec![150, 200, 250]);
        assert_eq!(freq_climb_mhz(100, 120, 50).unwrap(), vec![120]);
    }

    #[test]
    fn high_pll_table_matches_held_s9se_elf() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let bytes = std::fs::read(&path).expect("held S9 SE cgminer");
        let start = S9SE_CGMINER_HIGH_PLL_FILE_OFF;
        let end = start + HIGH_PLL_TABLE_COUNT * S9SE_CGMINER_HIGH_PLL_STRIDE;
        let raw = &bytes[start..end];
        for i in 0..HIGH_PLL_TABLE_COUNT {
            let off = i * S9SE_CGMINER_HIGH_PLL_STRIDE;
            let mut row = [0u8; 12];
            row.copy_from_slice(&raw[off..off + 12]);
            assert_eq!(decode_high_pll_row(&row), FREQ_HIGH_PLL_1393[i], "row {i}");
        }
        assert_eq!(freq_high_pll_1393_row(4).unwrap(), (200, 15, 3000));
        assert_eq!(freq_high_pll_1393_row(19).unwrap(), (575, 5, 2870));
        assert!(freq_high_pll_1393_row(33).is_err());
        assert_eq!(get_index_from_high_pll(200), 4);
        assert_eq!(get_index_from_high_pll(110), 1);
        assert_eq!(get_index_from_high_pll(50), HIGH_PLL_DEFAULT_INDEX);
        // 3000 MHz pll_out at 200 MHz / div 15 is the solver fallback row.
        assert_eq!(freq_pll_1393_row(175).unwrap(), (3000, PLL_FALLBACK_WORD));
    }

    #[test]
    fn official_om_cgminer_tables_match_held_build() {
        let kb = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../");
        let held = std::fs::read(kb.join("rootfs/usr/bin/cgminer")).expect("held S9 SE cgminer");
        let official = std::fs::read(kb.join("om-20190918/rootfs/usr/bin/cgminer"))
            .expect("official OM S9 SE cgminer");

        // The official September build decodes to the exact pinned 33 rows.
        let start = OFFICIAL_S9SE_CGMINER_HIGH_PLL_FILE_OFF;
        let end = start + HIGH_PLL_TABLE_COUNT * S9SE_CGMINER_HIGH_PLL_STRIDE;
        let raw = &official[start..end];
        for i in 0..HIGH_PLL_TABLE_COUNT {
            let off = i * S9SE_CGMINER_HIGH_PLL_STRIDE;
            let mut row = [0u8; 12];
            row.copy_from_slice(&raw[off..off + 12]);
            assert_eq!(decode_high_pll_row(&row), FREQ_HIGH_PLL_1393[i], "row {i}");
        }

        // Cross-build byte equality: the 33 × 12 high table …
        let held_start = S9SE_CGMINER_HIGH_PLL_FILE_OFF;
        let held_high = &held[held_start..held_start + 396];
        assert_eq!(raw, held_high, "freq_high_pll_1393 differs across builds");
        // … and the 179 × 16 freq_pll_1393 region immediately before it.
        let official_pll = &official[start - S9SE_PLL_REGION_LEN..start];
        let held_pll = &held[held_start - S9SE_PLL_REGION_LEN..held_start];
        assert_eq!(
            official_pll, held_pll,
            "freq_pll_1393 region differs across builds"
        );

        // The stock assertion-string set survives in the official build —
        // the RE'd bring-up contract (check_asic_num == 60 et al.) is not a
        // HiveOS-only artifact.
        for needle in [
            b"check_asic_num".as_slice(),
            b"bitmain_soc_init".as_slice(),
            b"send_job".as_slice(),
            b"calculate_asic_number".as_slice(),
            b"T11".as_slice(),
        ] {
            assert!(
                official.windows(needle.len()).any(|w| w == needle),
                "official cgminer missing {:?}",
                String::from_utf8_lossy(needle)
            );
        }
    }

    #[test]
    fn frequency_with_addr_is_pll0_only_not_the_spine() {
        let frame = pack_frequency_with_addr(false, 0x02, 0x0040_0241);
        assert_eq!(frame[0], 0x41);
        assert_eq!(frame[2], 0x02);
        assert_eq!(frame[3], REG_PLL0);
        assert_eq!(&frame[4..8], &[0x00, 0x40, 0x02, 0x41]);
        let bc = pack_frequency_with_addr(true, 0, PLL_FALLBACK_WORD);
        assert_eq!(bc[0], 0x51);
        assert_eq!(bc[3], 0x08);
        let spine = pack_operational_pll_frames(PLL_FALLBACK_WORD, 15).unwrap();
        assert_eq!(spine[0][3], 0x70);
        assert_ne!(frame[3], spine[0][3]);
        assert_eq!(
            refuse_s9se_frequency_program(),
            Err(S9SePllError::FrequencyProgramRefused)
        );
        assert_eq!(s9se_chip_addr_from_asic_index(1), Some(4));
        admit_s9se_chip_address(1, 4).unwrap();
        assert!(matches!(
            admit_s9se_chip_address(1, 2),
            Err(S9SePllError::ChipAddressMismatch {
                asic: 1,
                chip_addr: 2
            })
        ));
        admit_s9se_chip_address(0, 0).unwrap();
        admit_s9se_chip_address(59, 236).unwrap();
        assert!(admit_s9se_chip_address(60, 240).is_err());
    }
}
