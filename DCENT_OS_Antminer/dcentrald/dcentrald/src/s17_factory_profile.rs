// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only S17-family factory data recovered from the exact stock miners.
//! Raw loader 0x1462c copies EEPROM to 0x954bc, four bytes after the
//! loaded flag at 0x954b8. Keeping these bases distinct is essential.

use anyhow::{ensure, Result};

pub(super) const SOURCE_SHA256: &str =
    "1404e188d2f307d70e3f4d09b85f1a46ce42b2e0d79a1d8980413886f4f3d592";
/// Temperature init 0xe67c loads table 0x75950 and multiplies each index by 5.
pub(super) const SENSOR_ADDRESSES: [u8; 4] = [55, 40, 180, 195];

/// Every offset is relative to the raw 256-byte page, not its loaded flag.
/// T17 Apr-2020 loader/getters: 0x159d4, 0x16f4c, 0x170d0, 0x172d8.
#[derive(Clone, Copy)]
pub(super) struct FactoryLayout {
    pub source_sha256: &'static str,
    pub sensor_addresses: [u8; 4],
    chips: usize,
    production_crc: usize,
    mode_count: usize,
    mode_stride: usize,
    voltage_offset: usize,
    valid_offset: usize,
}

pub(super) fn layout(board: &str) -> Result<FactoryLayout> {
    Ok(match board {
        "am2-s17p" => FactoryLayout {
            source_sha256: SOURCE_SHA256,
            sensor_addresses: SENSOR_ADDRESSES,
            chips: 48,
            production_crc: 0xd1,
            mode_count: 3,
            mode_stride: 55,
            voltage_offset: 0x5a,
            valid_offset: 0x60,
        },
        "am2-t17" => FactoryLayout {
            source_sha256: "ad090e7abbf525a7a8a23c7153529e45af94b864e1170e677e1f85b4c4091367",
            sensor_addresses: [64, 48, 168, 184],
            chips: 30,
            production_crc: 0x51,
            mode_count: 1,
            mode_stride: 37,
            voltage_offset: 0x48,
            valid_offset: 0x4e,
        },
        "am2-s17plus" => FactoryLayout {
            source_sha256: "dcf2eccf2d57ac4960d1bd0e073517bf09e3d50f736c422edc7b110eb645f0d5",
            sensor_addresses: [42, 30, 162, 150],
            chips: 65,
            production_crc: 0x74,
            mode_count: 1,
            mode_stride: 72,
            voltage_offset: 0x6b,
            valid_offset: 0x71,
        },
        "am2-t17plus" => FactoryLayout {
            source_sha256: "4cda35acf684334a60e41e23cdf2a61fada2400b7d44eabbe195d3036819fad8",
            sensor_addresses: [55, 40, 175, 160],
            chips: 44,
            production_crc: 0x5f,
            mode_count: 1,
            mode_stride: 51,
            voltage_offset: 0x56,
            valid_offset: 0x5c,
        },
        _ => anyhow::bail!(
            "S17-family target {board} has no compiled factory/PSU/sensor profile yet"
        ),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FactoryRecord {
    pub fixture_version: u16,
    pub sensor_model: u8,
    pub product_id: u8,
    pub pcb: u16,
    pub bom: u16,
    /// Each mode contains the APW9 centivolts and minimum per-chip MHz.
    pub modes: [Option<(u16, u16)>; 3],
}

fn crc16(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for byte in bytes {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    crc
}

pub(super) fn decode(board: &str, page: &[u8]) -> Result<FactoryRecord> {
    let layout = layout(board)?;
    ensure!(page.len() == 256, "S17 factory page must contain 256 bytes");
    let word = |offset| u16::from_le_bytes([page[offset], page[offset + 1]]);
    ensure!(
        word(0) == 0x1397 && word(0x28) == 0x1397,
        "S17 factory/production BM1397 identity mismatch"
    );
    // Production loaders authenticate this header with CRC and BM1397 magic.
    // They do not require the factory jig's particular version value of 1.
    ensure!(
        crc16(&page[..0x1e]) == word(0x1e),
        "S17 fixture CRC mismatch"
    );
    // Raw instructions 0x149b0..0x149c0: buffer is SP+0x10;
    // CRC starts SP+0x38 for 0xa9 bytes; stored CRC is SP+0xe1.
    ensure!(
        crc16(&page[0x28..layout.production_crc]) == word(layout.production_crc),
        "S17-family production CRC mismatch"
    );
    let sensor_model = page[28];
    ensure!(
        (1..=8).contains(&sensor_model),
        "unknown S17 factory sensor model"
    );
    let mut modes = [None; 3];
    for (mode, entry) in modes.iter_mut().enumerate().take(layout.mode_count) {
        // get_voltage 0x15fc0 and frequency reader 0x15f64 use
        // mode stride 55; subtract the four-byte loaded-flag prefix.
        let offset = mode * layout.mode_stride;
        if page[layout.valid_offset + offset] == 0 {
            continue;
        }
        let voltage = word(layout.voltage_offset + offset);
        let minimum_frequency = page[0x2a + offset..0x2a + layout.chips + offset]
            .iter()
            .map(|byte| u16::from(*byte) * 5)
            .min()
            .unwrap();
        ensure!(
            (1450..=2100).contains(&voltage),
            "S17 factory APW9 target outside transfer-law envelope"
        );
        ensure!(
            (100..=1270).contains(&minimum_frequency),
            "S17 factory frequency table invalid"
        );
        *entry = Some((voltage, minimum_frequency));
    }
    ensure!(
        modes.iter().any(Option::is_some),
        "S17 factory page has no calibrated operating mode"
    );
    Ok(FactoryRecord {
        fixture_version: word(2),
        sensor_model,
        product_id: page[29],
        pcb: word(24),
        bom: word(26),
        modes,
    })
}

/// Choose a common calibrated mode at its recorded voltage. Initial beta
/// frequency is bounded below every chip's calibration by the runtime.
pub(super) fn common_mode(records: &[FactoryRecord]) -> Result<(usize, u16, u16)> {
    ensure!(
        records.len() == 3,
        "S17 needs all three physical board records"
    );
    let choice = (0..3)
        .filter_map(|mode| {
            let entries: Option<Vec<_>> = records.iter().map(|r| r.modes[mode]).collect();
            let entries = entries?;
            // A single APW9 drives all three boards. This profile intentionally
            // preserves a common factory voltage rather than inventing per-board
            // PIC DAC values. Different calibrated voltages need another recipe.
            let voltage = entries[0].0;
            if !entries.iter().all(|v| v.0 == voltage) {
                return None;
            }
            Some((mode, voltage, entries.iter().map(|v| v.1).min().unwrap()))
        })
        .min_by_key(|entry| entry.1);
    choice.ok_or_else(|| anyhow::anyhow!("S17 boards lack a common calibrated APW9 operating mode"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_page() -> [u8; 256] {
        // Synthetic layout fixture, not a capture and never installation evidence.
        let mut page = [0; 256];
        page[..4].copy_from_slice(&[0x97, 0x13, 1, 0]);
        page[28] = 1;
        page[29] = 7;
        page[0x28..0x2a].copy_from_slice(&[0x97, 0x13]);
        page[0x2a..0x5a].fill(100);
        page[0x5a..0x5c].copy_from_slice(&1850u16.to_le_bytes());
        page[0x60] = 1;
        let fixture = crc16(&page[..0x1e]);
        page[0x1e..0x20].copy_from_slice(&fixture.to_le_bytes());
        let production = crc16(&page[0x28..0xd1]);
        page[0xd1..0xd3].copy_from_slice(&production.to_le_bytes());
        page
    }

    #[test]
    fn s17_factory_crc_has_independent_standard_vector() {
        assert_eq!(crc16(b"123456789"), 0x4b37);
    }

    #[test]
    fn s17_factory_decode_uses_raw_loader_offsets_and_detects_corruption() {
        let page = synthetic_page();
        let record = decode("am2-s17p", &page).unwrap();
        assert_eq!(record.sensor_model, 1);
        assert_eq!(record.product_id, 7);
        assert_eq!(record.modes, [Some((1850, 500)), None, None]);
        for offset in [0, 2, 24, 28, 29, 0x1e, 0x28, 0x2a, 0x5a, 0x60, 0xd1] {
            let mut corrupt = page;
            corrupt[offset] ^= 1;
            assert!(
                decode("am2-s17p", &corrupt).is_err(),
                "byte {offset:#x} corruption must fail"
            );
        }
        assert!(decode("am2-s17p", &page[..255]).is_err());
    }

    #[test]
    fn s17_factory_common_mode_rejects_incompatible_board_calibration() {
        let record = decode("am2-s17p", &synthetic_page()).unwrap();
        let mut records = vec![record; 3];
        assert_eq!(common_mode(&records).unwrap(), (0, 1850, 500));
        records[2].modes[0] = Some((1800, 500));
        assert!(common_mode(&records).is_err());
    }

    #[test]
    fn t17_factory_layout_has_its_own_crc_and_thirty_chip_calibration() {
        let mut page = [0; 256];
        page[..4].copy_from_slice(&[0x97, 0x13, 1, 0]);
        page[28] = 2;
        page[0x28..0x2a].copy_from_slice(&[0x97, 0x13]);
        page[0x2a..0x48].fill(90);
        page[0x48..0x4a].copy_from_slice(&1800u16.to_le_bytes());
        page[0x4e] = 1;
        let fixture = crc16(&page[..0x1e]);
        page[0x1e..0x20].copy_from_slice(&fixture.to_le_bytes());
        let production = crc16(&page[0x28..0x51]);
        page[0x51..0x53].copy_from_slice(&production.to_le_bytes());
        assert_eq!(
            decode("am2-t17", &page).unwrap().modes,
            [Some((1800, 450)), None, None]
        );
        assert!(decode("am2-s17p", &page).is_err());
        page[0x48] ^= 1;
        assert!(decode("am2-t17", &page).is_err());
    }

    #[test]
    fn s17_plus_factory_pages_use_independent_chip_counts_and_production_spans() {
        // Offsets are fixture facts from the retained getters, not obtained
        // from layout(), so this catches wrong compiled production geometry.
        for (board, chips, voltage, valid, crc_at) in [
            ("am2-s17plus", 65, 0x6b, 0x71, 0x74),
            ("am2-t17plus", 44, 0x56, 0x5c, 0x5f),
        ] {
            let mut page = [0; 256];
            page[..4].copy_from_slice(&[0x97, 0x13, 1, 0]);
            page[28] = 1;
            page[0x28..0x2a].copy_from_slice(&[0x97, 0x13]);
            page[0x2a..0x2a + chips].fill(110);
            page[0x2a + chips - 1] = 80;
            page[voltage..voltage + 2].copy_from_slice(&1850u16.to_le_bytes());
            page[valid] = 1;
            let fixture = crc16(&page[..0x1e]);
            page[0x1e..0x20].copy_from_slice(&fixture.to_le_bytes());
            let production = crc16(&page[0x28..crc_at]);
            page[crc_at..crc_at + 2].copy_from_slice(&production.to_le_bytes());
            assert_eq!(
                decode(board, &page).unwrap().modes,
                [Some((1850, 400)), None, None]
            );
            let other = if board == "am2-s17plus" {
                "am2-t17plus"
            } else {
                "am2-s17plus"
            };
            assert!(decode(other, &page).is_err());
            // A valid CRC cannot turn an invalid production-mode flag into
            // an admitted profile, nor hide an absent last-chip calibration.
            page[valid] = 0;
            let production = crc16(&page[0x28..crc_at]);
            page[crc_at..crc_at + 2].copy_from_slice(&production.to_le_bytes());
            assert!(decode(board, &page).is_err());
        }
    }
}
