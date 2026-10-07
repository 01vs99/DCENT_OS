//! Pure BM1396 frequency/PCB-temperature auto-adapt voltage contract.
//!
//! This module encodes only facts recovered from the held 2019 T17e and
//! signed-2020 S17e/T17e `bmminer` binaries. It performs no I/O and grants no
//! carrier, rail, PLL, or mining authority.

use crate::bm1396_contract::{
    plan_bm1396_vendor_voltage_dac_ramp, Bm1396Model, Bm1396VoltageOutsideVendorEnvelope,
};
use crate::bm1396_lifecycle::Bm1396FirmwareRelease;

pub const BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C: [i16; 5] = [8, 18, 28, 38, 48];
pub const BM1396_T17E_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ: [u16; 9] =
    [200, 300, 350, 400, 450, 500, 550, 600, 650];
pub const BM1396_S17E_SIGNED_2020_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ: [u16; 5] =
    [200, 300, 350, 400, 450];

/// Lower T17e matrix stored at signed-2020 address `0xe3230 + 0x6c`.
///
/// The same 45 active little-endian `u32` cells occur at 2019 address
/// `0x8e684 + 0x68`. Rows are frequency buckets and columns are PCB-minimum
/// temperature buckets. The physical row stride is eight cells; the three
/// unused cells are zero.
pub const BM1396_T17E_AUTO_ADAPT_LOWER_MATRIX_CV: [[u16; 5]; 9] = [
    [2100, 2100, 2100, 2100, 2100],
    [1940, 1930, 1920, 1910, 1900],
    [1930, 1920, 1910, 1900, 1880],
    [1920, 1910, 1900, 1880, 1860],
    [1860, 1850, 1840, 1840, 1840],
    [1840, 1830, 1820, 1820, 1820],
    [1840, 1830, 1820, 1820, 1820],
    [1830, 1820, 1810, 1810, 1810],
    [1820, 1810, 1800, 1800, 1800],
];

/// Upper T17e matrix stored at signed-2020 address `0xe349c + 0x6c`.
///
/// The same 45 active cells occur at 2019 address `0x8ec04 + 0x68`.
pub const BM1396_T17E_AUTO_ADAPT_UPPER_MATRIX_CV: [[u16; 5]; 9] = [
    [2100, 2100, 2100, 2100, 2100],
    [2100, 2100, 2100, 2100, 2100],
    [2100, 2100, 2100, 2100, 2100],
    [2100, 2100, 2100, 2100, 2000],
    [2100, 2100, 2000, 2000, 2000],
    [2000, 2000, 2000, 2000, 1940],
    [2000, 2000, 1980, 1980, 1920],
    [1960, 1940, 1940, 1920, 1860],
    [1940, 1900, 1880, 1860, 1860],
];

/// Signed-2020 S17e fixed matrix at address `0xe2700 + 0x6c`.
pub const BM1396_S17E_SIGNED_2020_AUTO_ADAPT_MATRIX_CV: [[u16; 5]; 5] = [
    [2100, 2100, 2100, 2100, 2100],
    [2000, 1980, 1980, 1950, 1920],
    [1980, 1950, 1950, 1920, 1900],
    [1950, 1950, 1920, 1900, 1880],
    [1950, 1920, 1900, 1880, 1860],
];

pub const BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV: u16 = 1760;
pub const BM1396_T17E_SIGNED_2020_CALIBRATION_UPPER_CV: u16 = 1840;
pub const BM1396_AUTO_ADAPT_POST_PLL_ADC_THRESHOLD_MHZ: u16 = 300;

/// Explicit profile provenance required before a lookup can be planned.
///
/// The 2019 matrices were separate board-match results, not model aliases.
/// A caller must therefore already have proved which exact runtime profile was
/// selected; this API never guesses one from `T17e` alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396AutoAdaptProfile {
    Legacy2019T17eMatchedLowerMatrix,
    Legacy2019T17eMatchedUpperMatrix,
    Signed2020S17eFixed,
    Signed2020T17eCalibration { calibration_cv: u16 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396AutoAdaptVoltageError {
    UnsupportedReleaseModel {
        release: Bm1396FirmwareRelease,
        model: Bm1396Model,
    },
    ProfileDoesNotMatchReleaseModel {
        release: Bm1396FirmwareRelease,
        model: Bm1396Model,
        profile: Bm1396AutoAdaptProfile,
    },
    CalibrationOutsideRecoveredAnchors {
        observed_cv: u16,
    },
    CurrentVoltageOutsideVendorEnvelope {
        observed_cv: u16,
    },
}

impl std::fmt::Display for Bm1396AutoAdaptVoltageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedReleaseModel { release, model } => write!(
                f,
                "BM1396 auto-adapt voltage is not recovered for {release:?}/{model:?}"
            ),
            Self::ProfileDoesNotMatchReleaseModel {
                release,
                model,
                profile,
            } => write!(
                f,
                "BM1396 auto-adapt profile {profile:?} does not match {release:?}/{model:?}"
            ),
            Self::CalibrationOutsideRecoveredAnchors { observed_cv } => write!(
                f,
                "signed-2020 T17e calibration {observed_cv} cV is outside recovered anchors {}..={} cV",
                BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV,
                BM1396_T17E_SIGNED_2020_CALIBRATION_UPPER_CV
            ),
            Self::CurrentVoltageOutsideVendorEnvelope { observed_cv } => write!(
                f,
                "BM1396 auto-adapt current voltage {observed_cv} cV is outside the recovered vendor envelope"
            ),
        }
    }
}

impl std::error::Error for Bm1396AutoAdaptVoltageError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Bm1396VoltagePhase {
    PllAutoAdapt,
    S17eFactoryWorking,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bm1396AutoAdaptVoltagePlan {
    pub phase: Bm1396VoltagePhase,
    pub release: Bm1396FirmwareRelease,
    pub model: Bm1396Model,
    pub profile: Bm1396AutoAdaptProfile,
    pub frequency_mhz: u16,
    pub minimum_pcb_temperature_c: i16,
    pub frequency_band: u8,
    pub temperature_band: u8,
    pub current_voltage_cv: u16,
    pub target_voltage_cv: u16,
    /// Empty when current and target centivolts compare equal. Otherwise these
    /// are the exact DAC bytes the recovered stepped setter attempts in order.
    pub stepped_dac_codes: Vec<u8>,
    /// The stock wrapper is void and discards the stepped setter's verification
    /// result. True exactly when the setter is entered.
    pub stock_discards_setter_verification_result: bool,
    /// Signed-2020 helper behavior before the PLL write: only a changed target
    /// at a frequency strictly above 300 MHz invokes domain-ADC mode 1.
    pub helper_invokes_domain_adc_mode1_before_pll: bool,
    /// Signed-2020 T17e `FUN_0000f218` performs another mode-1 call after the
    /// PLL stage whenever frequency is strictly above 300 MHz, independent of
    /// whether the helper changed voltage. Its result is also discarded.
    pub t17e_ramp_invokes_domain_adc_mode1_after_pll: bool,
}

fn right_closed_bucket<T: Ord + Copy>(value: T, thresholds: &[T]) -> usize {
    thresholds
        .iter()
        .position(|&threshold| value <= threshold)
        .unwrap_or(thresholds.len() - 1)
}

fn t17e_interpolated_target_cv(
    calibration_cv: u16,
    frequency_band: usize,
    temperature_band: usize,
) -> Result<u16, Bm1396AutoAdaptVoltageError> {
    if !(BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV
        ..=BM1396_T17E_SIGNED_2020_CALIBRATION_UPPER_CV)
        .contains(&calibration_cv)
    {
        return Err(
            Bm1396AutoAdaptVoltageError::CalibrationOutsideRecoveredAnchors {
                observed_cv: calibration_cv,
            },
        );
    }

    let lower = i32::from(BM1396_T17E_AUTO_ADAPT_LOWER_MATRIX_CV[frequency_band][temperature_band]);
    let upper = i32::from(BM1396_T17E_AUTO_ADAPT_UPPER_MATRIX_CV[frequency_band][temperature_band]);
    let calibration_delta =
        i32::from(calibration_cv - BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV);
    let calibration_span = i32::from(
        BM1396_T17E_SIGNED_2020_CALIBRATION_UPPER_CV - BM1396_T17E_SIGNED_2020_CALIBRATION_LOWER_CV,
    );

    // Exact endpoint copies are semantically identical to this expression.
    // ARM signed division truncates toward zero, followed by a second signed
    // divide/multiply that rounds the positive result down to 10 cV.
    let interpolated = lower + calibration_delta * (upper - lower) / calibration_span;
    Ok(((interpolated / 10) * 10).min(2100) as u16)
}

/// Select the exact higher-voltage target without performing hardware I/O.
pub fn bm1396_auto_adapt_target_voltage_cv(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
    profile: Bm1396AutoAdaptProfile,
    frequency_mhz: u16,
    minimum_pcb_temperature_c: i16,
) -> Result<(u8, u8, u16), Bm1396AutoAdaptVoltageError> {
    if matches!(
        (release, model),
        (Bm1396FirmwareRelease::Legacy2019, Bm1396Model::S17e)
    ) {
        return Err(Bm1396AutoAdaptVoltageError::UnsupportedReleaseModel { release, model });
    }

    let temperature_band = right_closed_bucket(
        minimum_pcb_temperature_c,
        &BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C,
    );

    let (frequency_band, target_cv) = match (release, model, profile) {
        (
            Bm1396FirmwareRelease::Legacy2019,
            Bm1396Model::T17e,
            Bm1396AutoAdaptProfile::Legacy2019T17eMatchedLowerMatrix,
        ) => {
            let band = right_closed_bucket(
                frequency_mhz,
                &BM1396_T17E_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ,
            );
            (
                band,
                BM1396_T17E_AUTO_ADAPT_LOWER_MATRIX_CV[band][temperature_band],
            )
        }
        (
            Bm1396FirmwareRelease::Legacy2019,
            Bm1396Model::T17e,
            Bm1396AutoAdaptProfile::Legacy2019T17eMatchedUpperMatrix,
        ) => {
            let band = right_closed_bucket(
                frequency_mhz,
                &BM1396_T17E_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ,
            );
            (
                band,
                BM1396_T17E_AUTO_ADAPT_UPPER_MATRIX_CV[band][temperature_band],
            )
        }
        (
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::S17e,
            Bm1396AutoAdaptProfile::Signed2020S17eFixed,
        ) => {
            let band = right_closed_bucket(
                frequency_mhz,
                &BM1396_S17E_SIGNED_2020_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ,
            );
            (
                band,
                BM1396_S17E_SIGNED_2020_AUTO_ADAPT_MATRIX_CV[band][temperature_band],
            )
        }
        (
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            Bm1396AutoAdaptProfile::Signed2020T17eCalibration { calibration_cv },
        ) => {
            let band = right_closed_bucket(
                frequency_mhz,
                &BM1396_T17E_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ,
            );
            (
                band,
                t17e_interpolated_target_cv(calibration_cv, band, temperature_band)?,
            )
        }
        _ => {
            return Err(
                Bm1396AutoAdaptVoltageError::ProfileDoesNotMatchReleaseModel {
                    release,
                    model,
                    profile,
                },
            );
        }
    };

    Ok((frequency_band as u8, temperature_band as u8, target_cv))
}

/// Plan the exact lookup and stock write/check side effects without performing
/// I/O. The output is evidence only and cannot authorize a rail mutation.
pub fn plan_bm1396_auto_adapt_voltage(
    release: Bm1396FirmwareRelease,
    model: Bm1396Model,
    profile: Bm1396AutoAdaptProfile,
    frequency_mhz: u16,
    minimum_pcb_temperature_c: i16,
    current_voltage_cv: u16,
) -> Result<Bm1396AutoAdaptVoltagePlan, Bm1396AutoAdaptVoltageError> {
    let (frequency_band, temperature_band, target_voltage_cv) =
        bm1396_auto_adapt_target_voltage_cv(
            release,
            model,
            profile,
            frequency_mhz,
            minimum_pcb_temperature_c,
        )?;

    let changed = current_voltage_cv != target_voltage_cv;
    let stepped_dac_codes = if changed {
        plan_bm1396_vendor_voltage_dac_ramp(current_voltage_cv, target_voltage_cv).map_err(
            |Bm1396VoltageOutsideVendorEnvelope { requested_cv }| {
                Bm1396AutoAdaptVoltageError::CurrentVoltageOutsideVendorEnvelope {
                    observed_cv: requested_cv,
                }
            },
        )?
    } else {
        Vec::new()
    };
    let above_adc_threshold = frequency_mhz > BM1396_AUTO_ADAPT_POST_PLL_ADC_THRESHOLD_MHZ;

    Ok(Bm1396AutoAdaptVoltagePlan {
        phase: Bm1396VoltagePhase::PllAutoAdapt,
        release,
        model,
        profile,
        frequency_mhz,
        minimum_pcb_temperature_c,
        frequency_band,
        temperature_band,
        current_voltage_cv,
        target_voltage_cv,
        stepped_dac_codes,
        stock_discards_setter_verification_result: changed,
        helper_invokes_domain_adc_mode1_before_pll: matches!(
            release,
            Bm1396FirmwareRelease::Signed2020
        ) && changed
            && above_adc_threshold,
        t17e_ramp_invokes_domain_adc_mode1_after_pll: matches!(
            (release, model),
            (Bm1396FirmwareRelease::Signed2020, Bm1396Model::T17e)
        ) && above_adc_threshold,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_tables_and_right_closed_bucket_boundaries_are_pinned() {
        for (row, &frequency) in BM1396_T17E_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ
            .iter()
            .enumerate()
        {
            for (column, &temperature) in BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C
                .iter()
                .enumerate()
            {
                assert_eq!(
                    bm1396_auto_adapt_target_voltage_cv(
                        Bm1396FirmwareRelease::Signed2020,
                        Bm1396Model::T17e,
                        Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                            calibration_cv: 1760,
                        },
                        frequency,
                        temperature,
                    ),
                    Ok((
                        row as u8,
                        column as u8,
                        BM1396_T17E_AUTO_ADAPT_LOWER_MATRIX_CV[row][column],
                    ))
                );
            }
        }

        assert_eq!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::T17e,
                Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                    calibration_cv: 1840,
                },
                201,
                9,
            ),
            Ok((1, 1, 2100))
        );
        assert_eq!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::T17e,
                Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                    calibration_cv: 1760,
                },
                0,
                i16::MIN,
            ),
            Ok((0, 0, 2100))
        );
        assert_eq!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::T17e,
                Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                    calibration_cv: 1760,
                },
                u16::MAX,
                i16::MAX,
            ),
            Ok((8, 4, 1800))
        );
    }

    #[test]
    fn every_frequency_and_temperature_threshold_pins_minus_exact_and_plus_one() {
        for thresholds in [
            BM1396_T17E_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ.as_slice(),
            BM1396_S17E_SIGNED_2020_AUTO_ADAPT_FREQUENCY_THRESHOLDS_MHZ.as_slice(),
        ] {
            for (index, &threshold) in thresholds.iter().enumerate() {
                assert_eq!(right_closed_bucket(threshold - 1, thresholds), index);
                assert_eq!(right_closed_bucket(threshold, thresholds), index);
                assert_eq!(
                    right_closed_bucket(threshold + 1, thresholds),
                    (index + 1).min(thresholds.len() - 1)
                );
            }
        }

        for (index, &threshold) in BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C
            .iter()
            .enumerate()
        {
            assert_eq!(
                right_closed_bucket(threshold - 1, &BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C,),
                index
            );
            assert_eq!(
                right_closed_bucket(threshold, &BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C),
                index
            );
            assert_eq!(
                right_closed_bucket(threshold + 1, &BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C,),
                (index + 1).min(BM1396_AUTO_ADAPT_TEMPERATURE_THRESHOLDS_C.len() - 1)
            );
        }
    }

    #[test]
    fn signed_2020_t17e_interpolation_uses_integer_truncation_then_ten_cv_floor() {
        assert_eq!(t17e_interpolated_target_cv(1800, 1, 0), Ok(2020));
        assert_eq!(t17e_interpolated_target_cv(1800, 8, 4), Ok(1830));
        assert_eq!(t17e_interpolated_target_cv(1761, 1, 0), Ok(1940));
        assert_eq!(t17e_interpolated_target_cv(1764, 1, 0), Ok(1940));
        assert_eq!(t17e_interpolated_target_cv(1765, 1, 0), Ok(1950));
        assert_eq!(
            t17e_interpolated_target_cv(1759, 0, 0),
            Err(
                Bm1396AutoAdaptVoltageError::CalibrationOutsideRecoveredAnchors {
                    observed_cv: 1759
                }
            )
        );
        assert_eq!(
            t17e_interpolated_target_cv(1841, 0, 0),
            Err(
                Bm1396AutoAdaptVoltageError::CalibrationOutsideRecoveredAnchors {
                    observed_cv: 1841
                }
            )
        );
    }

    #[test]
    fn release_and_profile_selection_is_explicit_and_fail_closed() {
        assert_eq!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Legacy2019,
                Bm1396Model::T17e,
                Bm1396AutoAdaptProfile::Legacy2019T17eMatchedLowerMatrix,
                300,
                18,
            ),
            Ok((1, 1, 1930))
        );
        assert_eq!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Legacy2019,
                Bm1396Model::T17e,
                Bm1396AutoAdaptProfile::Legacy2019T17eMatchedUpperMatrix,
                300,
                18,
            ),
            Ok((1, 1, 2100))
        );
        assert!(matches!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Legacy2019,
                Bm1396Model::S17e,
                Bm1396AutoAdaptProfile::Signed2020S17eFixed,
                300,
                18,
            ),
            Err(Bm1396AutoAdaptVoltageError::UnsupportedReleaseModel { .. })
        ));
        assert!(matches!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::S17e,
                Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                    calibration_cv: 1800,
                },
                300,
                18,
            ),
            Err(Bm1396AutoAdaptVoltageError::ProfileDoesNotMatchReleaseModel { .. })
        ));
    }

    #[test]
    fn signed_2020_s17e_fixed_table_clamps_both_axes() {
        assert_eq!(
            bm1396_auto_adapt_target_voltage_cv(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::S17e,
                Bm1396AutoAdaptProfile::Signed2020S17eFixed,
                451,
                49,
            ),
            Ok((4, 4, 1860))
        );
    }

    #[test]
    fn planner_pins_setter_condition_write_order_and_strict_adc_comparisons() {
        let at_300 = plan_bm1396_auto_adapt_voltage(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                calibration_cv: 1760,
            },
            300,
            18,
            1800,
        )
        .unwrap();
        assert_eq!(at_300.target_voltage_cv, 1930);
        assert_eq!(at_300.stepped_dac_codes, vec![103, 86, 73]);
        assert!(at_300.stock_discards_setter_verification_result);
        assert!(!at_300.helper_invokes_domain_adc_mode1_before_pll);
        assert!(!at_300.t17e_ramp_invokes_domain_adc_mode1_after_pll);

        let above_300 = plan_bm1396_auto_adapt_voltage(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                calibration_cv: 1760,
            },
            301,
            18,
            1800,
        )
        .unwrap();
        assert_eq!(above_300.target_voltage_cv, 1920);
        assert_eq!(above_300.stepped_dac_codes, vec![103, 86, 77]);
        assert!(above_300.helper_invokes_domain_adc_mode1_before_pll);
        assert!(above_300.t17e_ramp_invokes_domain_adc_mode1_after_pll);

        let unchanged = plan_bm1396_auto_adapt_voltage(
            Bm1396FirmwareRelease::Signed2020,
            Bm1396Model::T17e,
            Bm1396AutoAdaptProfile::Signed2020T17eCalibration {
                calibration_cv: 1760,
            },
            301,
            18,
            1920,
        )
        .unwrap();
        assert!(unchanged.stepped_dac_codes.is_empty());
        assert!(!unchanged.stock_discards_setter_verification_result);
        assert!(!unchanged.helper_invokes_domain_adc_mode1_before_pll);
        assert!(unchanged.t17e_ramp_invokes_domain_adc_mode1_after_pll);
    }

    #[test]
    fn planner_rejects_current_shadow_outside_vendor_envelope() {
        assert_eq!(
            plan_bm1396_auto_adapt_voltage(
                Bm1396FirmwareRelease::Signed2020,
                Bm1396Model::S17e,
                Bm1396AutoAdaptProfile::Signed2020S17eFixed,
                300,
                18,
                1799,
            ),
            Err(
                Bm1396AutoAdaptVoltageError::CurrentVoltageOutsideVendorEnvelope {
                    observed_cv: 1799,
                }
            )
        );
    }
}
