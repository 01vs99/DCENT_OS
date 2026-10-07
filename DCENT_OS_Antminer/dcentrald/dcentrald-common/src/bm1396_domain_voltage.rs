//! Pure BM1396 ASIC-domain voltage policy recovered from exact signed S17e
//! and T17e production miners. This module evaluates already-acquired values;
//! it performs no register or carrier I/O.

use crate::bm1396_contract::Bm1396Model;

pub const BM1396_S17E_DOMAIN_COUNT: usize = 15;
pub const BM1396_T17E_DOMAIN_COUNT: usize = 13;
pub const BM1396_S17E_CHIPS_PER_DOMAIN: usize = 9;
pub const BM1396_T17E_CHIPS_PER_DOMAIN: usize = 6;
pub const BM1396_DOMAIN_ADC_LANE_COUNT: usize = 4;
pub const BM1396_DOMAIN_ADC_RAW_MASK: u16 = 0x0fff;
pub const BM1396_DOMAIN_ADC_SCALE_2_NEG_12_F64_BITS: u64 = 0x3f30_0000_0000_0000;
pub const BM1396_DOMAIN_ADC_MULTIPLIER: f64 = 1.5;
pub const BM1396_DOMAIN_ADC_LANE_SPREAD_F64_BITS: u64 = 0x3fb9_9999_9999_999a;
pub const BM1396_DOMAIN_VOLTAGE_ACQUISITION_ERROR_BASE: u32 = 0xe100_0000;

pub const BM1396_DOMAIN_MIN_0_8_F32_BITS: u32 = 0x3f4c_cccd;
pub const BM1396_DOMAIN_MIN_1_0_F32_BITS: u32 = 0x3f80_0000;
pub const BM1396_DOMAIN_MIN_1_1_F32_BITS: u32 = 0x3f8c_cccd;
pub const BM1396_DOMAIN_MIN_1_2_F32_BITS: u32 = 0x3f99_999a;
pub const BM1396_DOMAIN_MIN_1_3_F32_BITS: u32 = 0x3fa6_6666;
pub const BM1396_DOMAIN_SPREAD_0_05_F32_BITS: u32 = 0x3d4c_cccd;
pub const BM1396_DOMAIN_SPREAD_0_1_F32_BITS: u32 = 0x3dcc_cccd;
pub const BM1396_DOMAIN_SPREAD_0_2_F32_BITS: u32 = 0x3e4c_cccd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1396DomainAdcRawLanes {
    pub lanes: [u16; BM1396_DOMAIN_ADC_LANE_COUNT],
}

/// Decode the four12-bit lanes returned by ASIC registers B4/B8. Original
/// S17e7e508/7e53c and T17e7f370/7f3a0 extract the second lane at bit16.
/// Reserved bits12..15 and28..31 are ignored; see384 original callback replays.
pub const fn bm1396_decode_domain_adc_registers(
    register_b4: u32,
    register_b8: u32,
) -> Bm1396DomainAdcRawLanes {
    Bm1396DomainAdcRawLanes {
        lanes: [
            (register_b4 & BM1396_DOMAIN_ADC_RAW_MASK as u32) as u16,
            ((register_b4 >> 16) & BM1396_DOMAIN_ADC_RAW_MASK as u32) as u16,
            (register_b8 & BM1396_DOMAIN_ADC_RAW_MASK as u32) as u16,
            ((register_b8 >> 16) & BM1396_DOMAIN_ADC_RAW_MASK as u32) as u16,
        ],
    }
}

pub fn bm1396_domain_adc_raw_to_volts(raw: u16) -> Option<f64> {
    if raw > BM1396_DOMAIN_ADC_RAW_MASK {
        return None;
    }
    Some(
        f64::from(raw)
            * BM1396_DOMAIN_ADC_MULTIPLIER
            * f64::from_bits(BM1396_DOMAIN_ADC_SCALE_2_NEG_12_F64_BITS),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396DomainAdcIndexError {
    InvalidChainSlot { observed: u8 },
    MisalignedWireAddress { address: u8, interval: u8 },
    ChipOrdinalOutOfRange { observed: usize, maximum: usize },
}

/// Model-correct callback-array index. T17e divides interval-three wire
/// addresses; DCENT explicitly refuses a misaligned address before indexing.
pub fn bm1396_domain_adc_sample_index(
    model: Bm1396Model,
    chain_slot: u8,
    wire_chip_address: u8,
) -> Result<usize, Bm1396DomainAdcIndexError> {
    if chain_slot >= 16 {
        return Err(Bm1396DomainAdcIndexError::InvalidChainSlot {
            observed: chain_slot,
        });
    }
    let interval = model.address_interval();
    if wire_chip_address % interval != 0 {
        return Err(Bm1396DomainAdcIndexError::MisalignedWireAddress {
            address: wire_chip_address,
            interval,
        });
    }
    let chip_ordinal = usize::from(wire_chip_address / interval);
    let chip_count = usize::from(model.expected_chips_per_present_chain());
    if chip_ordinal >= chip_count {
        return Err(Bm1396DomainAdcIndexError::ChipOrdinalOutOfRange {
            observed: chip_ordinal,
            maximum: chip_count,
        });
    }
    Ok(usize::from(chain_slot) * chip_count + chip_ordinal)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1396DomainAdcSummary {
    pub lane_means_v: [f32; BM1396_DOMAIN_ADC_LANE_COUNT],
    /// The outer threshold policy consumes lane 3.
    pub domain_voltage_v: f32,
    /// Stock uses this for diagnostics, not as a fatal return at acquisition.
    pub lane_spread_diagnostic: [bool; BM1396_DOMAIN_ADC_LANE_COUNT],
    pub saw_zero_sample: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396DomainAdcSummaryError {
    WrongChipCount {
        expected: usize,
        observed: usize,
    },
    RawLaneOutOfRange {
        chip_ordinal: usize,
        lane: usize,
        observed: u16,
    },
}

/// Group one chain into exact model domains. Each nonzero raw sample is first
/// converted to f64 volts, then summed/divided in f64; the mean is stored f32.
/// Zero samples are skipped. A wholly-zero lane yields zero for the outer
/// minimum policy to reject.
pub fn bm1396_summarize_domain_adc(
    model: Bm1396Model,
    chip_lanes: &[[u16; BM1396_DOMAIN_ADC_LANE_COUNT]],
) -> Result<Vec<Bm1396DomainAdcSummary>, Bm1396DomainAdcSummaryError> {
    let (chip_count, chips_per_domain, domain_count) = match model {
        Bm1396Model::S17e => (
            usize::from(model.expected_chips_per_present_chain()),
            BM1396_S17E_CHIPS_PER_DOMAIN,
            BM1396_S17E_DOMAIN_COUNT,
        ),
        Bm1396Model::T17e => (
            usize::from(model.expected_chips_per_present_chain()),
            BM1396_T17E_CHIPS_PER_DOMAIN,
            BM1396_T17E_DOMAIN_COUNT,
        ),
    };
    if chip_lanes.len() != chip_count {
        return Err(Bm1396DomainAdcSummaryError::WrongChipCount {
            expected: chip_count,
            observed: chip_lanes.len(),
        });
    }
    for (chip_ordinal, lanes) in chip_lanes.iter().enumerate() {
        for (lane, raw) in lanes.iter().copied().enumerate() {
            if raw > BM1396_DOMAIN_ADC_RAW_MASK {
                return Err(Bm1396DomainAdcSummaryError::RawLaneOutOfRange {
                    chip_ordinal,
                    lane,
                    observed: raw,
                });
            }
        }
    }
    let spread_limit = f64::from_bits(BM1396_DOMAIN_ADC_LANE_SPREAD_F64_BITS);
    let mut summaries = Vec::with_capacity(domain_count);
    for group in chip_lanes.chunks_exact(chips_per_domain) {
        let mut lane_means_v = [0.0f32; BM1396_DOMAIN_ADC_LANE_COUNT];
        let mut lane_spread_diagnostic = [false; BM1396_DOMAIN_ADC_LANE_COUNT];
        let mut saw_zero_sample = false;
        for lane in 0..BM1396_DOMAIN_ADC_LANE_COUNT {
            let mut sum = 0.0f64;
            let mut count = 0u32;
            let mut minimum = f64::INFINITY;
            let mut maximum = f64::NEG_INFINITY;
            for lanes in group {
                let raw = lanes[lane];
                if raw == 0 {
                    saw_zero_sample = true;
                    continue;
                }
                let volts = bm1396_domain_adc_raw_to_volts(raw)
                    .expect("range validated before exact grouping");
                sum += volts;
                count += 1;
                minimum = minimum.min(volts);
                maximum = maximum.max(volts);
            }
            if count != 0 {
                lane_means_v[lane] = (sum / f64::from(count)) as f32;
                let extrema_delta = (maximum as f32) - (minimum as f32);
                lane_spread_diagnostic[lane] = f64::from(extrema_delta) > spread_limit;
            }
        }
        summaries.push(Bm1396DomainAdcSummary {
            domain_voltage_v: lane_means_v[3],
            lane_means_v,
            lane_spread_diagnostic,
            saw_zero_sample,
        });
    }
    debug_assert_eq!(summaries.len(), domain_count);
    Ok(summaries)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396DomainVoltageMode {
    /// Vendor params other than 1/2/3 acquire values without threshold checks.
    AcquireOnly,
    /// Vendor param 1: enforce a per-domain minimum.
    Minimum,
    /// Vendor param 2: enforce minimum, then update a capability flag from
    /// spread; spread failure itself does not propagate an error in stock.
    MinimumAndSpreadCapability,
    /// Vendor param 3: enforce spread and propagate failure.
    Spread,
}

pub const fn bm1396_domain_voltage_mode_from_vendor_param(
    parameter: u32,
) -> Bm1396DomainVoltageMode {
    match parameter {
        1 => Bm1396DomainVoltageMode::Minimum,
        2 => Bm1396DomainVoltageMode::MinimumAndSpreadCapability,
        3 => Bm1396DomainVoltageMode::Spread,
        _ => Bm1396DomainVoltageMode::AcquireOnly,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bm1396DomainVoltageAdaptiveLevel {
    Baseline,
    Adapted,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Bm1396DomainVoltagePolicy {
    domain_count: usize,
    minimum_v: Option<f32>,
    maximum_spread_v: Option<f32>,
    mode: Bm1396DomainVoltageMode,
}

impl Bm1396DomainVoltagePolicy {
    pub const fn domain_count(self) -> usize {
        self.domain_count
    }

    pub const fn minimum_v(self) -> Option<f32> {
        self.minimum_v
    }

    pub const fn maximum_spread_v(self) -> Option<f32> {
        self.maximum_spread_v
    }

    pub const fn mode(self) -> Bm1396DomainVoltageMode {
        self.mode
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bm1396DomainVoltagePolicyError {
    UnsupportedAdaptiveLevel {
        model: Bm1396Model,
        level: Bm1396DomainVoltageAdaptiveLevel,
    },
}

/// Resolve the exact model/profile thresholds. S17e has one fixed profile;
/// T17e has a two-level selector and advances only after its first successful
/// full-enumeration minimum check.
pub fn bm1396_domain_voltage_policy(
    model: Bm1396Model,
    level: Bm1396DomainVoltageAdaptiveLevel,
    mode: Bm1396DomainVoltageMode,
) -> Result<Bm1396DomainVoltagePolicy, Bm1396DomainVoltagePolicyError> {
    if model == Bm1396Model::S17e && level == Bm1396DomainVoltageAdaptiveLevel::Adapted {
        return Err(Bm1396DomainVoltagePolicyError::UnsupportedAdaptiveLevel { model, level });
    }
    let domain_count = match model {
        Bm1396Model::S17e => BM1396_S17E_DOMAIN_COUNT,
        Bm1396Model::T17e => BM1396_T17E_DOMAIN_COUNT,
    };
    let minimum_v = match (model, level, mode) {
        (_, _, Bm1396DomainVoltageMode::AcquireOnly | Bm1396DomainVoltageMode::Spread) => None,
        (Bm1396Model::S17e, _, Bm1396DomainVoltageMode::Minimum) => {
            Some(f32::from_bits(BM1396_DOMAIN_MIN_0_8_F32_BITS))
        }
        (Bm1396Model::S17e, _, Bm1396DomainVoltageMode::MinimumAndSpreadCapability) => {
            Some(f32::from_bits(BM1396_DOMAIN_MIN_1_0_F32_BITS))
        }
        (
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Baseline,
            Bm1396DomainVoltageMode::Minimum,
        ) => Some(f32::from_bits(BM1396_DOMAIN_MIN_0_8_F32_BITS)),
        (
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Baseline,
            Bm1396DomainVoltageMode::MinimumAndSpreadCapability,
        ) => Some(f32::from_bits(BM1396_DOMAIN_MIN_1_2_F32_BITS)),
        (
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Adapted,
            Bm1396DomainVoltageMode::Minimum,
        ) => Some(f32::from_bits(BM1396_DOMAIN_MIN_1_1_F32_BITS)),
        (
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Adapted,
            Bm1396DomainVoltageMode::MinimumAndSpreadCapability,
        ) => Some(f32::from_bits(BM1396_DOMAIN_MIN_1_3_F32_BITS)),
    };
    let maximum_spread_v = match (model, mode) {
        (_, Bm1396DomainVoltageMode::AcquireOnly | Bm1396DomainVoltageMode::Minimum) => None,
        (Bm1396Model::S17e, Bm1396DomainVoltageMode::MinimumAndSpreadCapability) => {
            Some(f32::from_bits(BM1396_DOMAIN_SPREAD_0_2_F32_BITS))
        }
        (Bm1396Model::T17e, Bm1396DomainVoltageMode::MinimumAndSpreadCapability) => {
            Some(f32::from_bits(BM1396_DOMAIN_SPREAD_0_05_F32_BITS))
        }
        (_, Bm1396DomainVoltageMode::Spread) => {
            Some(f32::from_bits(BM1396_DOMAIN_SPREAD_0_1_F32_BITS))
        }
    };
    Ok(Bm1396DomainVoltagePolicy {
        domain_count,
        minimum_v,
        maximum_spread_v,
        mode,
    })
}

/// Saturating profile-selector transition. S17e count=1 remains at baseline;
/// T17e count=2 advances once and then remains adapted.
pub const fn bm1396_next_domain_voltage_level(
    model: Bm1396Model,
    current: Bm1396DomainVoltageAdaptiveLevel,
) -> Bm1396DomainVoltageAdaptiveLevel {
    match (model, current) {
        (Bm1396Model::T17e, Bm1396DomainVoltageAdaptiveLevel::Baseline) => {
            Bm1396DomainVoltageAdaptiveLevel::Adapted
        }
        _ => current,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bm1396DomainVoltageDecision {
    Pass {
        capability_enabled: Option<bool>,
    },
    MinimumViolation {
        domain_index: usize,
        observed_v: f32,
        required_v: f32,
    },
    SpreadViolationClearsCapability {
        observed_v: f32,
        maximum_v: f32,
    },
    SpreadViolationPropagates {
        observed_v: f32,
        maximum_v: f32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Bm1396DomainVoltageInputError {
    WrongDomainCount { expected: usize, observed: usize },
    NonFiniteValue { domain_index: usize, observed: f32 },
}

/// Evaluate one already-acquired chain. Equality passes for both minimum and
/// spread comparisons. Non-finite values are a DCENT fail-closed hardening.
pub fn bm1396_evaluate_domain_voltages(
    policy: Bm1396DomainVoltagePolicy,
    voltages_v: &[f32],
) -> Result<Bm1396DomainVoltageDecision, Bm1396DomainVoltageInputError> {
    if voltages_v.len() != policy.domain_count {
        return Err(Bm1396DomainVoltageInputError::WrongDomainCount {
            expected: policy.domain_count,
            observed: voltages_v.len(),
        });
    }
    for (domain_index, observed) in voltages_v.iter().copied().enumerate() {
        if !observed.is_finite() {
            return Err(Bm1396DomainVoltageInputError::NonFiniteValue {
                domain_index,
                observed,
            });
        }
        if let Some(required) = policy.minimum_v {
            if observed < required {
                return Ok(Bm1396DomainVoltageDecision::MinimumViolation {
                    domain_index,
                    observed_v: observed,
                    required_v: required,
                });
            }
        }
    }
    if let Some(maximum_spread) = policy.maximum_spread_v {
        let mut minimum = voltages_v[0];
        let mut maximum = voltages_v[0];
        for value in voltages_v.iter().copied().skip(1) {
            minimum = minimum.min(value);
            maximum = maximum.max(value);
        }
        let observed_spread = maximum - minimum;
        if observed_spread > maximum_spread {
            return Ok(match policy.mode {
                Bm1396DomainVoltageMode::MinimumAndSpreadCapability => {
                    Bm1396DomainVoltageDecision::SpreadViolationClearsCapability {
                        observed_v: observed_spread,
                        maximum_v: maximum_spread,
                    }
                }
                Bm1396DomainVoltageMode::Spread => {
                    Bm1396DomainVoltageDecision::SpreadViolationPropagates {
                        observed_v: observed_spread,
                        maximum_v: maximum_spread,
                    }
                }
                _ => unreachable!("policy/mode spread invariant"),
            });
        }
    }
    Ok(Bm1396DomainVoltageDecision::Pass {
        capability_enabled: (policy.mode == Bm1396DomainVoltageMode::MinimumAndSpreadCapability)
            .then_some(true),
    })
}

pub const fn bm1396_domain_voltage_acquisition_error(failed_chain_bits: u16) -> u32 {
    BM1396_DOMAIN_VOLTAGE_ACQUISITION_ERROR_BASE | failed_chain_bits as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn complete_original_adc_callback_vectors_preserve_reserved_gap_and_index() {
        let mut count = 0;
        for line in include_str!("bm1396_domain_adc_callback_vectors.csv")
            .lines()
            .filter(|line| !line.starts_with('#'))
        {
            let fields: Vec<u32> = line
                .split(',')
                .map(|field| field.parse().unwrap())
                .collect();
            assert_eq!(fields.len(), 10);
            let model = if fields[0] == 0 {
                Bm1396Model::S17e
            } else {
                Bm1396Model::T17e
            };
            assert_eq!(
                bm1396_domain_adc_sample_index(model, fields[1] as u8, fields[2] as u8).unwrap(),
                fields[5] as usize
            );
            let b4 = fields[3] == 0xb4;
            let actual = bm1396_decode_domain_adc_registers(
                if b4 { fields[4] } else { 0 },
                if b4 { 0 } else { fields[4] },
            );
            let offset = if b4 { 0 } else { 2 };
            assert_eq!(actual.lanes[offset], fields[6 + offset] as u16);
            assert_eq!(actual.lanes[offset + 1], fields[7 + offset] as u16);
            count += 1;
        }
        assert_eq!(count, 384);
    }

    #[test]
    fn adc_register_decode_scale_and_model_index_are_exact() {
        assert_eq!(
            bm1396_decode_domain_adc_registers(0xfabc_f123, 0x5def_a456),
            Bm1396DomainAdcRawLanes {
                lanes: [0x123, 0xabc, 0x456, 0xdef],
            }
        );
        assert_eq!(
            bm1396_domain_adc_raw_to_volts(4095),
            Some(1.499_633_789_062_5)
        );
        assert_eq!(bm1396_domain_adc_raw_to_volts(4096), None);

        assert_eq!(
            bm1396_domain_adc_sample_index(Bm1396Model::S17e, 1, 134),
            Ok(269)
        );
        assert_eq!(
            bm1396_domain_adc_sample_index(Bm1396Model::T17e, 2, 231),
            Ok(233)
        );
        assert!(matches!(
            bm1396_domain_adc_sample_index(Bm1396Model::T17e, 0, 230),
            Err(Bm1396DomainAdcIndexError::MisalignedWireAddress { .. })
        ));
    }

    #[test]
    fn adc_grouping_skips_zero_and_preserves_f64_then_f32_vendor_arithmetic() {
        let mut samples = vec![[0u16; BM1396_DOMAIN_ADC_LANE_COUNT]; 135];
        samples[0][3] = 1000;
        samples[1][3] = 2000;
        let summaries = bm1396_summarize_domain_adc(Bm1396Model::S17e, &samples).unwrap();
        assert_eq!(summaries.len(), BM1396_S17E_DOMAIN_COUNT);
        assert_eq!(summaries[0].domain_voltage_v, 0.549_316_4);
        assert!(summaries[0].lane_spread_diagnostic[3]);
        assert!(summaries[0].saw_zero_sample);
        assert_eq!(summaries[1].domain_voltage_v, 0.0);

        assert!(matches!(
            bm1396_summarize_domain_adc(Bm1396Model::T17e, &samples[..77]),
            Err(Bm1396DomainAdcSummaryError::WrongChipCount { .. })
        ));
        let mut malformed = vec![[0u16; BM1396_DOMAIN_ADC_LANE_COUNT]; 78];
        malformed[7][2] = 4096;
        assert_eq!(
            bm1396_summarize_domain_adc(Bm1396Model::T17e, &malformed),
            Err(Bm1396DomainAdcSummaryError::RawLaneOutOfRange {
                chip_ordinal: 7,
                lane: 2,
                observed: 4096,
            })
        );
    }

    #[test]
    fn s17e_and_t17e_domain_geometry_and_profiles_remain_distinct() {
        let s_mode2 = bm1396_domain_voltage_policy(
            Bm1396Model::S17e,
            Bm1396DomainVoltageAdaptiveLevel::Baseline,
            Bm1396DomainVoltageMode::MinimumAndSpreadCapability,
        )
        .unwrap();
        assert_eq!(s_mode2.domain_count(), 15);
        assert_eq!(s_mode2.minimum_v().unwrap().to_bits(), 0x3f80_0000);
        assert_eq!(s_mode2.maximum_spread_v().unwrap().to_bits(), 0x3e4c_cccd);

        let t_before = bm1396_domain_voltage_policy(
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Baseline,
            Bm1396DomainVoltageMode::MinimumAndSpreadCapability,
        )
        .unwrap();
        let t_after = bm1396_domain_voltage_policy(
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Adapted,
            Bm1396DomainVoltageMode::MinimumAndSpreadCapability,
        )
        .unwrap();
        assert_eq!(t_before.domain_count(), 13);
        assert_eq!(t_before.minimum_v().unwrap().to_bits(), 0x3f99_999a);
        assert_eq!(t_after.minimum_v().unwrap().to_bits(), 0x3fa6_6666);
        assert_eq!(t_after.maximum_spread_v().unwrap().to_bits(), 0x3d4c_cccd);
        assert_eq!(
            bm1396_domain_voltage_policy(
                Bm1396Model::S17e,
                Bm1396DomainVoltageAdaptiveLevel::Adapted,
                Bm1396DomainVoltageMode::Minimum,
            ),
            Err(Bm1396DomainVoltagePolicyError::UnsupportedAdaptiveLevel {
                model: Bm1396Model::S17e,
                level: Bm1396DomainVoltageAdaptiveLevel::Adapted,
            })
        );
    }

    #[test]
    fn adaptive_transition_is_model_specific_and_saturating() {
        assert_eq!(
            bm1396_next_domain_voltage_level(
                Bm1396Model::S17e,
                Bm1396DomainVoltageAdaptiveLevel::Baseline,
            ),
            Bm1396DomainVoltageAdaptiveLevel::Baseline
        );
        assert_eq!(
            bm1396_next_domain_voltage_level(
                Bm1396Model::T17e,
                Bm1396DomainVoltageAdaptiveLevel::Baseline,
            ),
            Bm1396DomainVoltageAdaptiveLevel::Adapted
        );
        assert_eq!(
            bm1396_next_domain_voltage_level(
                Bm1396Model::T17e,
                Bm1396DomainVoltageAdaptiveLevel::Adapted,
            ),
            Bm1396DomainVoltageAdaptiveLevel::Adapted
        );
    }

    #[test]
    fn minimum_and_spread_boundaries_are_inclusive_and_reactions_differ() {
        let s_policy = bm1396_domain_voltage_policy(
            Bm1396Model::S17e,
            Bm1396DomainVoltageAdaptiveLevel::Baseline,
            Bm1396DomainVoltageMode::MinimumAndSpreadCapability,
        )
        .unwrap();
        let mut values = vec![1.0; 15];
        assert_eq!(
            bm1396_evaluate_domain_voltages(s_policy, &values),
            Ok(Bm1396DomainVoltageDecision::Pass {
                capability_enabled: Some(true),
            })
        );
        values[14] = 1.21;
        assert!(matches!(
            bm1396_evaluate_domain_voltages(s_policy, &values),
            Ok(Bm1396DomainVoltageDecision::SpreadViolationClearsCapability { .. })
        ));

        let spread_policy = bm1396_domain_voltage_policy(
            Bm1396Model::S17e,
            Bm1396DomainVoltageAdaptiveLevel::Baseline,
            Bm1396DomainVoltageMode::Spread,
        )
        .unwrap();
        let exact_spread = f32::from_bits(BM1396_DOMAIN_SPREAD_0_1_F32_BITS);
        let mut equality_values = vec![0.0; 15];
        equality_values[14] = exact_spread;
        assert_eq!(
            bm1396_evaluate_domain_voltages(spread_policy, &equality_values),
            Ok(Bm1396DomainVoltageDecision::Pass {
                capability_enabled: None,
            })
        );
        assert!(matches!(
            bm1396_evaluate_domain_voltages(spread_policy, &values),
            Ok(Bm1396DomainVoltageDecision::SpreadViolationPropagates { .. })
        ));

        let min_policy = bm1396_domain_voltage_policy(
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Adapted,
            Bm1396DomainVoltageMode::Minimum,
        )
        .unwrap();
        let mut values = vec![1.1; 13];
        assert!(matches!(
            bm1396_evaluate_domain_voltages(min_policy, &values),
            Ok(Bm1396DomainVoltageDecision::Pass { .. })
        ));
        values[4] = 1.09;
        assert!(matches!(
            bm1396_evaluate_domain_voltages(min_policy, &values),
            Ok(Bm1396DomainVoltageDecision::MinimumViolation {
                domain_index: 4,
                ..
            })
        ));
    }

    #[test]
    fn acquisition_and_malformed_inputs_fail_closed() {
        assert_eq!(bm1396_domain_voltage_acquisition_error(0x0005), 0xe100_0005);
        let policy = bm1396_domain_voltage_policy(
            Bm1396Model::T17e,
            Bm1396DomainVoltageAdaptiveLevel::Baseline,
            Bm1396DomainVoltageMode::Minimum,
        )
        .unwrap();
        assert!(matches!(
            bm1396_evaluate_domain_voltages(policy, &[1.0; 12]),
            Err(Bm1396DomainVoltageInputError::WrongDomainCount { .. })
        ));
        let mut malformed = [1.0; 13];
        malformed[3] = f32::NAN;
        assert!(matches!(
            bm1396_evaluate_domain_voltages(policy, &malformed),
            Err(Bm1396DomainVoltageInputError::NonFiniteValue {
                domain_index: 3,
                ..
            })
        ));
    }
}
