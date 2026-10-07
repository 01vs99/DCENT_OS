//! Exact held S15/T15 software settings, not measured electrical limits.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Profile {
    pub model: Model,
    pub configured_mhz: u16,
    pub working_volts: f64,
    pub pll: PllSetting,
    pub timeout_ticks: u32,
    pub cutoff_c: i16,
}

// S15 0x9e530/T15 0x9e450: (configured frequency, divider, raw PLL MHz).
// Both exact binaries contain these33 triples. 575 maps to2870/5 in stock;
// retain that distinction rather than reporting a measured575MHz clock.
const PROFILES: &[(u16, u8, u16)] = &[
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

impl Profile {
    pub fn from_config(config: &DcentraldConfig, model: Model) -> Result<Self> {
        ensure!(
            config.mining.enabled && !config.mining.passthrough,
            "BM1391 requires enabled native mining"
        );
        ensure!(
            config.watchdog.enabled,
            "BM1391 requires the independent hardware watchdog"
        );
        ensure!(
            config.mining.frequency_mhz != 575,
            "BM1391 stock575MHz profile names missing PLL2870; refusing its silent PLL200 fallback"
        );
        let &(configured_mhz, divider, pll_mhz) = PROFILES
            .iter()
            .find(|(frequency, _, _)| *frequency == config.mining.frequency_mhz)
            .context(
                "BM1391 requires an explicit stock frequency profile100..900MHz in25MHz steps",
            )?;
        ensure!((16030..=20280).contains(&config.mining.voltage_mv),
                "BM1391 requires explicit working voltage16030..20280mV within the retained APW8 software envelope");
        let cutoff_c = i16::from(config.thermal.dangerous_temp_c);
        ensure!(cutoff_c > 15, "BM1391 configured thermal cutoff is invalid");
        Ok(Self {
            model,
            configured_mhz,
            working_volts: f64::from(config.mining.voltage_mv) / 1000.0,
            pll: PllSetting::new(pll_mhz, divider).map_err(anyhow::Error::msg)?,
            // Complete original4c234/4c27c:256 source cores, address interval,
            // frequency, then90 percent; exact integer-division order retained.
            timeout_ticks: (65536 * u32::from(model.address_interval())
                / u32::from(configured_mhz))
                * 90
                / 100,
            cutoff_c,
        })
    }
}

fn dac(volts: f64) -> u8 {
    (1215.894_44 - volts * 59.931_506_85).clamp(0.0, 255.0) as u8
}
pub(super) fn dac_preimage(code: u8) -> f64 {
    // A checked input to the existing bounded setter produces the exact stock
    // raw DAC command. This value is a software preimage, never rail readback.
    let volts = ((1215.894_44 - (f64::from(code) + 0.5)) / 59.931_506_85).clamp(16.03, 20.28);
    assert_eq!(dac(volts), code);
    volts
}
pub(super) fn ramp_codes(start_volts: f64, target_volts: f64) -> Vec<u8> {
    // Complete original7aa38/7aa00: five coarse DAC steps, adaptive approach,
    // exact target. Default argument0 still waits500ms after every setter.
    let mut current = i16::from(dac(start_volts));
    let target = i16::from(dac(target_volts));
    let direction = if start_volts >= target_volts { 1 } else { -1 };
    let step = (current - target).abs() / 6;
    let mut codes = Vec::new();
    for _ in 0..5 {
        current += direction * step;
        codes.push(current as u8);
    }
    while (current - target).abs() >= 2 {
        let distance = (current - target).abs();
        let step = if distance > 32 {
            16
        } else if distance > 16 {
            8
        } else if distance > 2 {
            2
        } else {
            1
        };
        current += direction * step;
        codes.push(current as u8);
        assert!(codes.len() < 32);
    }
    codes.push(target as u8);
    codes
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_original_profile_and_timeout_tables_match_both_releases() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../"
        )).unwrap();
        for release in oracle["releases"].as_array().unwrap() {
            assert_eq!(
                release["profiles"].as_array().unwrap().len(),
                PROFILES.len()
            );
            for ((mhz, divider, pll), row) in
                PROFILES.iter().zip(release["profiles"].as_array().unwrap())
            {
                assert_eq!(
                    (*mhz, *divider, *pll),
                    (
                        row["configured_mhz"].as_u64().unwrap() as u16,
                        row["clock_divider"].as_u64().unwrap() as u8,
                        row["pll_table_mhz"].as_u64().unwrap() as u16
                    )
                );
                if *mhz == 575 {
                    assert!(PllSetting::new(*pll, *divider).is_err());
                    assert_eq!(row["writes"][5]["value"].as_u64().unwrap(), 0x40400241);
                } else {
                    assert!(PllSetting::new(*pll, *divider).is_ok());
                }
            }
            for row in release["timeouts"].as_array().unwrap() {
                assert_eq!(
                    (65536 * row["address_interval"].as_u64().unwrap()
                        / row["configured_mhz"].as_u64().unwrap())
                        * 90
                        / 100,
                    row["ticks"].as_u64().unwrap()
                );
            }
        }
    }
    #[test]
    fn all_target_dac_codes_match512_complete_original_ramps_and_bounded_setter_inputs() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../"
        )).unwrap();
        for release in oracle["releases"].as_array().unwrap() {
            for row in release["vectors"].as_array().unwrap() {
                let codes = ramp_codes(20.0, row["requested_volts"].as_f64().unwrap());
                let expected: Vec<u8> = row["codes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect();
                assert_eq!(codes, expected);
                for code in codes {
                    let volts = dac_preimage(code);
                    assert!((16.03..=20.28).contains(&volts));
                    assert_eq!(dac(volts), code);
                }
            }
        }
    }
}
