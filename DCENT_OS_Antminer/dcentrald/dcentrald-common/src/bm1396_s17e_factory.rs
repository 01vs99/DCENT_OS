//! Exact signed-2020 S17e factory frequencies and addressed startup plan.
//!
//! Clean-room facts from bmminer SHA256
//! 819bd5ee790f3ce74f61a45546856e0cd7b37a62e7ec2263ebb83e35220c8243:
//! 573c0/59224/599a8 read and decode the factory record; e764 checks the
//! frequency ceiling. 35b60 -> 35028 -> 3524c binds the fixed e26c0 profile;
//! 24064 reads e2af8[1]+e2af8[3] = 480+50 MHz. fd84 ramps in five-MHz
//! steps (12574/e269c), sorting each nine-chip domain by target difference
//! (dd40), then visiting fifteen domains per rank with 100ms between ranks.
//! This module has no I/O and grants no physical ownership or work authority.

pub const CHIPS: usize = 135;
pub const FACTORY_MAX_MHZ: u16 = 530;
pub const FACTORY_STEP_MHZ: u16 = 5;
pub const DOMAIN_RANK_WAIT_MS: u32 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S17eFactoryRecord {
    frequencies: [u16; CHIPS],
    working_voltage_cv: u16,
}

impl S17eFactoryRecord {
    pub fn frequencies_mhz(&self) -> &[u16; CHIPS] {
        &self.frequencies
    }
    pub fn working_voltage_cv(&self) -> u16 {
        self.working_voltage_cv
    }
    pub fn minimum_mhz(&self) -> u16 {
        *self.frequencies.iter().min().expect("135 chips")
    }
    pub fn maximum_mhz(&self) -> u16 {
        *self.frequencies.iter().max().expect("135 chips")
    }
}

/// AEB58 uses the two reflected Modbus tables, initial FFFF, little-endian
/// stored result. Factory bytes are never repaired or written by this API.
pub fn factory_crc(bytes: &[u8]) -> u16 {
    let mut crc = 0xffffu16;
    for &byte in bytes {
        crc ^= u16::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    crc
}

pub fn decode_factory_record(bytes: &[u8]) -> Result<S17eFactoryRecord, String> {
    if bytes.len() != 256 {
        return Err("S17e factory record requires 256 completed bytes".into());
    }
    let word = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    if word(0) != 0x1396 || factory_crc(&bytes[..0x26]) != word(0x26) {
        return Err("S17e fixture header/CRC rejected".into());
    }
    if word(0x28) != 0x1396 || factory_crc(&bytes[0x28..0xfe]) != word(0xfe) {
        return Err("S17e miner header/CRC rejected".into());
    }
    if bytes[0xb9] == 0 {
        return Err("S17e mode-zero factory profile is absent".into());
    }
    let mut frequencies = [0; CHIPS];
    for (frequency, &encoded) in frequencies.iter_mut().zip(&bytes[0x2a..0xb1]) {
        *frequency = u16::from(encoded) * 5;
        // EB68 skips initial divider settings at or below its 50 MHz floor.
        // Refuse a factory target that cannot produce a complete cold ramp.
        if *frequency <= 50 || *frequency > FACTORY_MAX_MHZ {
            return Err("S17e factory frequency cannot produce the bounded stock ramp".into());
        }
    }
    let working_voltage_cv = word(0xb1);
    if !(1800..=2100).contains(&working_voltage_cv) {
        return Err("S17e factory voltage exceeds the source working envelope".into());
    }
    Ok(S17eFactoryRecord {
        frequencies,
        working_voltage_cv,
    })
}

/// The native population must be nonempty and exact. The source selects the
/// maximum stored rail (11084); require its documented 50cV spread without
/// preserving the stock integer-average branch that could miss disagreement.
pub fn population_working_voltage(records: &[S17eFactoryRecord]) -> Result<u16, String> {
    let maximum = records
        .iter()
        .map(S17eFactoryRecord::working_voltage_cv)
        .max()
        .ok_or("S17e factory population is empty")?;
    let minimum = records
        .iter()
        .map(S17eFactoryRecord::working_voltage_cv)
        .min()
        .unwrap();
    if maximum - minimum > 50 {
        return Err("S17e factory voltage population disagrees".into());
    }
    Ok(maximum)
}

/// Integer register composition from the exact 8131c single-precision search.
/// No fallback PLL is returned when the requested target is unrepresentable.
pub fn pll_register(frequency: u16) -> Result<u32, String> {
    if frequency == 0 || frequency > FACTORY_MAX_MHZ {
        return Err("S17e PLL target outside factory bounds".into());
    }
    let target = f32::from(frequency);
    let mut error = 10.0f32;
    let mut best = None;
    for reference in [2u16, 1] {
        for post1 in 1u16..=7 {
            for post2 in post1..=7 {
                let feedback =
                    ((f32::from(post1) * target * f32::from(post2) * f32::from(reference)) / 25.0
                        + 0.5) as u16;
                if !(16..=250).contains(&feedback) {
                    continue;
                }
                let vco = (25.0 / f32::from(reference)) * f32::from(feedback);
                if (reference == 1 && vco > 3125.0) || !(2000.0..=3200.0).contains(&vco) {
                    continue;
                }
                let difference = (target - vco / f32::from(post1 * post2)).abs();
                if difference < error {
                    error = difference;
                    best = Some(
                        0x4000_0000
                            | u32::from(feedback) << 16
                            | u32::from(reference) << 8
                            | u32::from(post2) << 4
                            | u32::from(post1),
                    );
                }
            }
        }
    }
    best.ok_or_else(|| "S17e factory PLL is not representable".into())
}

pub fn register_frequency_mhz(word: u32) -> Result<u16, String> {
    let feedback = (word >> 16) & 0xfff;
    let reference = (word >> 8) & 0x3f;
    let post2 = (word >> 4) & 7;
    let post1 = word & 7;
    if reference == 0 || post1 == 0 || post2 == 0 {
        return Err("S17e PLL divider is zero".into());
    }
    Ok((25 * feedback / (reference * post1 * post2)) as u16)
}

/// Source 12640: interval byte(+5337, initialized to one by 80e8c..80ea0)
/// times 2^24, divided by next-power-of-two cores(+5333, 96 at14c0c..14c1c),
/// multiplied by90/100, then divided by the completed maximum frequency.
/// The job planner separately applies its effective version-count scaling.
pub fn timeout_base(maximum_frequency_mhz: u16) -> Result<u32, String> {
    if !(55..=FACTORY_MAX_MHZ).contains(&maximum_frequency_mhz) {
        return Err("S17e timeout requires completed bounded factory frequency".into());
    }
    Ok((((1u32 << 24) / 128) * 90 / 100) / u32::from(maximum_frequency_mhz))
}

/// 1999c completes the PLL, then10c94 chooses its working rail: above20C use
/// the factory population maximum; at/below20C use min(factory+100cV, the
/// selected frequency/temperature matrix cell). 5dd14/5e084 ->5bbfc applies it.
/// The caller must still observe real rails and the final domain ADC afterward.
pub fn working_voltage_plan(
    records: &[S17eFactoryRecord],
    frequency: u16,
    minimum_pcb_c: i16,
    current_voltage_cv: u16,
) -> Result<crate::bm1396_auto_adapt_voltage::Bm1396AutoAdaptVoltagePlan, String> {
    use crate::bm1396_auto_adapt_voltage::*;
    let working = population_working_voltage(records)?;
    let mut plan = plan_bm1396_auto_adapt_voltage(
        crate::bm1396_lifecycle::Bm1396FirmwareRelease::Signed2020,
        crate::Bm1396Model::S17e,
        Bm1396AutoAdaptProfile::Signed2020S17eFixed,
        frequency,
        minimum_pcb_c,
        current_voltage_cv,
    )
    .map_err(|error| error.to_string())?;
    plan.phase = Bm1396VoltagePhase::S17eFactoryWorking;
    plan.target_voltage_cv = if minimum_pcb_c <= 20 {
        (working + 100).min(plan.target_voltage_cv)
    } else {
        working
    };
    plan.stepped_dac_codes = if current_voltage_cv == plan.target_voltage_cv {
        Vec::new()
    } else {
        crate::bm1396_contract::plan_bm1396_vendor_voltage_dac_ramp(
            current_voltage_cv,
            plan.target_voltage_cv,
        )
        .map_err(|error| error.to_string())?
    };
    plan.stock_discards_setter_verification_result = !plan.stepped_dac_codes.is_empty();
    plan.helper_invokes_domain_adc_mode1_before_pll = false;
    plan.t17e_ramp_invokes_domain_adc_mode1_after_pll = false;
    Ok(plan)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryPllCommand {
    pub chain: u8,
    pub chip: Option<u8>,
    pub register: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FactoryPllStage {
    /// Voltage planning uses the highest target that this stage can apply.
    pub frequency_mhz: u16,
    pub commands: Vec<FactoryPllCommand>,
    pub wait_ms: u32,
    /// EB68 performs mode-one domain ADC after bootstrap stages above 300.
    pub domain_adc_after: bool,
    pub factory_working_voltage: bool,
}

/// Selected chain IDs are supplied by the physical owner, never synthesized as
/// three chains. The plan itself is pure data; HAL must rejoin it to that owner.
pub fn startup_plan(records: &[(u8, S17eFactoryRecord)]) -> Result<Vec<FactoryPllStage>, String> {
    if records.is_empty()
        || records.len() > 8
        || records.iter().any(|(chain, _)| *chain >= 16)
        || !records.windows(2).all(|pair| pair[0].0 < pair[1].0)
    {
        return Err("S17e exact ordered factory population required".into());
    }
    let mut selectors = 0u8;
    for (chain, _) in records {
        let bit = 1 << (chain & 7);
        if selectors & bit != 0 {
            return Err("S17e factory PIC selector alias".into());
        }
        selectors |= bit;
    }
    population_working_voltage(&records.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>())?;
    let lowest = records.iter().map(|(_, r)| r.minimum_mhz()).min().unwrap();
    let seed = pll_register(lowest)?;
    let mut dividers = Vec::new();
    for post2 in (seed >> 4) & 7..=7 {
        for post1 in seed & 7..=post2 {
            dividers.push((post1 * post2, (seed & !0x77) | post2 << 4 | post1));
        }
    }
    // DD50 compares descending product. Native ties retain traversal order;
    // the source comparator does not prove an independent equal-product order.
    dividers.sort_by_key(|&(product, _)| std::cmp::Reverse(product));
    let mut result = Vec::new();
    for (_, register) in dividers {
        let frequency = register_frequency_mhz(register)?;
        if frequency > 50 {
            result.push(FactoryPllStage {
                frequency_mhz: frequency,
                commands: records
                    .iter()
                    .map(|(chain, _)| FactoryPllCommand {
                        chain: *chain,
                        chip: None,
                        register,
                    })
                    .collect(),
                wait_ms: 2000,
                domain_adc_after: frequency > 300,
                factory_working_voltage: false,
            });
        }
    }
    let mut minima: Vec<_> = records.iter().map(|(_, r)| r.minimum_mhz()).collect();
    minima.sort_unstable();
    for pair in minima.windows(2) {
        let mut frequency = pair[0];
        while frequency < pair[1] {
            frequency = (frequency + FACTORY_STEP_MHZ).min(pair[1]);
            result.push(FactoryPllStage {
                frequency_mhz: frequency,
                commands: records
                    .iter()
                    .filter(|(_, r)| r.minimum_mhz() >= pair[1])
                    .map(|(chain, _)| {
                        Ok(FactoryPllCommand {
                            chain: *chain,
                            chip: None,
                            register: pll_register(frequency)?,
                        })
                    })
                    .collect::<Result<_, String>>()?,
                wait_ms: 2000,
                domain_adc_after: false,
                factory_working_voltage: false,
            });
        }
    }
    let maximum = records.iter().map(|(_, r)| r.maximum_mhz()).max().unwrap();
    for (chain, record) in records {
        let minimum = record.minimum_mhz();
        let mut domains: Vec<Vec<(u8, u16)>> = record
            .frequencies
            .chunks_exact(9)
            .enumerate()
            .map(|(domain, frequencies)| {
                let mut chips: Vec<_> = frequencies
                    .iter()
                    .enumerate()
                    .map(|(index, &frequency)| ((domain * 9 + index) as u8, frequency - minimum))
                    .collect();
                chips.sort_by_key(|&(_, difference)| difference);
                chips
            })
            .collect();
        let difference = record.maximum_mhz() - minimum;
        for increment in (FACTORY_STEP_MHZ..=difference).step_by(usize::from(FACTORY_STEP_MHZ)) {
            for rank in 0..9 {
                let mut commands = Vec::new();
                for domain in &mut domains {
                    let (chip, delta) = domain[rank];
                    if increment <= delta || increment - delta < FACTORY_STEP_MHZ {
                        commands.push(FactoryPllCommand {
                            chain: *chain,
                            chip: Some(chip),
                            register: pll_register(minimum + increment.min(delta))?,
                        });
                    }
                }
                result.push(FactoryPllStage {
                    frequency_mhz: maximum,
                    commands,
                    wait_ms: DOMAIN_RANK_WAIT_MS,
                    domain_adc_after: false,
                    factory_working_voltage: false,
                });
            }
        }
    }
    if result.is_empty() {
        return Err("S17e factory ramp is empty".into());
    }
    result.push(FactoryPllStage {
        frequency_mhz: maximum,
        commands: Vec::new(),
        wait_ms: 0,
        domain_adc_after: false,
        factory_working_voltage: true,
    });
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(frequencies: [u8; CHIPS], voltage: u16) -> Vec<u8> {
        let mut bytes = vec![0; 256];
        bytes[..2].copy_from_slice(&0x1396u16.to_le_bytes());
        bytes[0x28..0x2a].copy_from_slice(&0x1396u16.to_le_bytes());
        bytes[0x2a..0xb1].copy_from_slice(&frequencies);
        bytes[0xb1..0xb3].copy_from_slice(&voltage.to_le_bytes());
        bytes[0xb9] = 1;
        crc(&mut bytes);
        bytes
    }
    fn crc(bytes: &mut [u8]) {
        let first = factory_crc(&bytes[..0x26]);
        let second = factory_crc(&bytes[0x28..0xfe]);
        bytes[0x26..0x28].copy_from_slice(&first.to_le_bytes());
        bytes[0xfe..].copy_from_slice(&second.to_le_bytes());
    }
    #[test]
    fn exact_factory_regions_mode_voltage_and_frequency_fail_closed() {
        let bytes = record([78; CHIPS], 1900);
        let decoded = decode_factory_record(&bytes).unwrap();
        assert_eq!(decoded.frequencies_mhz(), &[390; CHIPS]);
        assert_eq!(decoded.working_voltage_cv(), 1900);
        for offset in [0, 0x26, 0x28, 0x2a, 0xb1, 0xfe] {
            let mut bad = bytes.clone();
            bad[offset] ^= 1;
            assert!(decode_factory_record(&bad).is_err());
        }
        for (offset, value) in [(0xb9, 0), (0x2a, 0), (0x2a, 107)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            crc(&mut bad);
            assert!(decode_factory_record(&bad).is_err());
        }
        assert!(decode_factory_record(&bytes[..255]).is_err());
        assert!(decode_factory_record(&record([78; CHIPS], 2101)).is_err());
        assert!(population_working_voltage(&[
            decoded,
            decode_factory_record(&record([78; CHIPS], 1960)).unwrap()
        ])
        .is_err());
    }
    #[test]
    fn addressed_ramp_reaches_each_factory_target_without_sibling_geometry() {
        let frequencies = std::array::from_fn(|index| 78 + (index % 9) as u8);
        let record = decode_factory_record(&record(frequencies, 1900)).unwrap();
        let plan = startup_plan(&[(0, record.clone()), (2, record)]).unwrap();
        let addressed: Vec<_> = plan.iter().filter(|stage| stage.wait_ms == 100).collect();
        assert!(!addressed.is_empty());
        let first = addressed
            .iter()
            .find(|stage| !stage.commands.is_empty())
            .unwrap();
        assert_eq!(
            first
                .commands
                .iter()
                .map(|command| command.chip.unwrap())
                .collect::<Vec<_>>(),
            (0..15).map(|domain| domain * 9 + 1).collect::<Vec<_>>()
        );
        for chain in [0, 2] {
            let mut final_frequency = [0; CHIPS];
            for stage in &plan {
                for command in &stage.commands {
                    if command.chain == chain {
                        let frequency = register_frequency_mhz(command.register).unwrap();
                        if let Some(chip) = command.chip {
                            final_frequency[usize::from(chip)] = frequency;
                        } else {
                            final_frequency.fill(frequency);
                        }
                    }
                }
            }
            for (index, frequency) in final_frequency.into_iter().enumerate() {
                assert!(frequency.abs_diff(u16::from(frequencies[index]) * 5) <= 1);
            }
        }
        assert!(startup_plan(&[]).is_err());
    }
    #[test]
    fn pll_words_pin_actual_source_search_and_initial_floor() {
        assert_eq!(pll_register(300).unwrap(), 0x40a8_0271);
        assert_eq!(register_frequency_mhz(0x40a8_0275).unwrap(), 60);
        assert!(pll_register(0).is_err());
        assert!(pll_register(531).is_err());
        assert_eq!(timeout_base(300).unwrap(), 393);
        assert_eq!(timeout_base(430).unwrap(), 274);
        assert!(timeout_base(0).is_err());
        let record = decode_factory_record(&record([60; CHIPS], 1900)).unwrap();
        let plan = startup_plan(&[(0, record)]).unwrap();
        assert_eq!(
            plan.iter()
                .filter(|s| !s.factory_working_voltage)
                .map(|s| s.frequency_mhz)
                .collect::<Vec<_>>(),
            [60, 75, 100, 150, 300]
        );
        assert!(plan.last().unwrap().factory_working_voltage);
    }

    #[test]
    fn final_factory_rail_uses_actual_population_and_exact_twenty_degree_boundary() {
        let record = decode_factory_record(&record([86; CHIPS], 1850)).unwrap();
        let warm = working_voltage_plan(&[record.clone()], 430, 21, 2000).unwrap();
        assert_eq!(warm.target_voltage_cv, 1850);
        let cold = working_voltage_plan(&[record.clone()], 430, 20, 2000).unwrap();
        assert_eq!(cold.target_voltage_cv, 1900);
        assert_eq!(
            cold.phase,
            crate::bm1396_auto_adapt_voltage::Bm1396VoltagePhase::S17eFactoryWorking
        );
        assert!(!cold.helper_invokes_domain_adc_mode1_before_pll);
        assert!(working_voltage_plan(&[], 430, 21, 2000).is_err());
        let invalid_current = working_voltage_plan(&[record], 430, 21, 999);
        assert!(invalid_current.is_err());
    }
}
