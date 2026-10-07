//! Original table-mode BM1391 startup PLL and auxiliary clock programming.
use super::*;

include!("stock_bm1391_pll_table.rs");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PllSetting {
    nominal_mhz: u16,
    clock_divider: u8,
    raw_word: u32,
}
impl PllSetting {
    /// Select an exact stock table entry and nonzero stock divider byte.
    /// Voltage, temperature and board-specific operating limits belong to the
    /// runtime; table membership alone does not qualify an operating point.
    pub fn new(nominal_mhz: u16, clock_divider: u8) -> Result<Self, String> {
        if clock_divider == 0 {
            return Err(
                "BM1391 clock divider would underflow the stock divider-minus-one encoding".into(),
            );
        }
        let &(_, raw_word) = STOCK_PLL
            .iter()
            .find(|(mhz, _)| *mhz == nominal_mhz)
            .ok_or("BM1391 frequency is absent from the exact stock PLL table")?;
        Ok(Self {
            nominal_mhz,
            clock_divider,
            raw_word,
        })
    }
    pub fn nominal_mhz(self) -> u16 {
        self.nominal_mhz
    }
    /// Frequency represented by the stock PLL divisors, excluding the
    /// separately programmed clock-divider field. No lock/readback is implied.
    pub fn pll_hz(self) -> u64 {
        let feedback = (self.raw_word >> 16) & 0xff;
        let reference = (self.raw_word >> 8) & 0x3f;
        let post1 = (self.raw_word >> 4) & 0xf;
        let post2 = self.raw_word & 0xf;
        25_000_000 * u64::from(feedback) / u64::from(reference * post1 * post2)
    }
}

impl<R: Registers> Transport<R> {
    /// Complete one chain's startup clock sequence under the same retained
    /// lane: repeated70/08 followed by repeated74/60,78/64,7c/68. Original
    /// S15 470d4 +46d4c and T15 47108 +46d80 are replayed through real stores.
    /// Completion means FPGA command completion, not observed PLL lock.
    pub fn program_pll(
        &self,
        chain: u8,
        setting: PllSetting,
        deadline: Instant,
    ) -> Result<(), String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 PLL is outside the retained population".into());
        }
        self.with_asic_lane(deadline, || {
            let divider = 0x0f0f_0f00 | u32::from(setting.clock_divider - 1);
            let pll = setting.raw_word | 0x4000_0000;
            for _ in 0..2 {
                for (register, value) in [(0x70, divider), (8, pll)] {
                    self.publish_command_locked(
                        chain,
                        &Self::register_frame(0, true, register, value),
                        deadline,
                    )?;
                }
            }
            for (select, clock) in [(0x74, 0x60), (0x78, 0x64), (0x7c, 0x68)] {
                for _ in 0..2 {
                    for (register, value) in [(select, 0x0f0f_0f0f), (clock, 0x8010_3f77)] {
                        self.publish_command_locked(
                            chain,
                            &Self::register_frame(0, true, register, value),
                            deadline,
                        )?;
                    }
                }
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{deadline, sample_work, RecordingRegisters};
    use super::*;

    #[test]
    fn all_table_entries_match_both_original_releases_without_fallback_frequency() {
        let tables: [serde_json::Value; 2] = [
            serde_json::from_str(include_str!("../../../../../../")).unwrap(),
            serde_json::from_str(include_str!("../../../../../../")).unwrap(),
        ];
        for table in tables {
            assert_eq!(table["rows"].as_array().unwrap().len(), STOCK_PLL.len());
            for (index, row) in table["rows"].as_array().unwrap().iter().enumerate() {
                let nominal = row[0].as_u64().unwrap() as u16;
                let raw = row[3].as_u64().unwrap() as u32;
                let selected = PllSetting::new(nominal, 1).unwrap();
                assert_eq!(STOCK_PLL[index], (nominal, raw));
                assert_eq!(selected.raw_word, raw);
                assert_eq!(selected.nominal_mhz(), nominal);
            }
        }
        assert_eq!(PllSetting::new(100, 1).unwrap().pll_hz(), 100_000_000);
        assert_eq!(PllSetting::new(303, 1).unwrap().pll_hz(), 303_125_000);
        for (mhz, divisor) in [(0, 1), (299, 1), (3301, 1), (100, 0)] {
            assert!(PllSetting::new(mhz, divisor).is_err());
        }
    }

    #[test]
    fn complete_pll_and_auxiliary_clocks_match_72_original_machine_code_sequences() {
        let oracle: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../../../"
        )).unwrap();
        let mut sequences = 0;
        let mut stores = 0;
        for release in oracle["releases"].as_array().unwrap() {
            for vector in release["vectors"].as_array().unwrap() {
                let registers = Arc::new(RecordingRegisters::default());
                let owner = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
                let setting = PllSetting::new(
                    vector["frequency_mhz"].as_u64().unwrap() as u16,
                    vector["divider"].as_u64().unwrap() as u8,
                )
                .unwrap();
                owner
                    .program_pll(vector["chain"].as_u64().unwrap() as u8, setting, deadline())
                    .unwrap();
                let expected: Vec<_> = vector["writes"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| {
                        (
                            v["offset"].as_u64().unwrap() as u32,
                            v["value"].as_u64().unwrap() as u32,
                        )
                    })
                    .collect();
                assert_eq!(registers.state.lock().unwrap().writes, expected);
                assert_eq!(expected.len(), 64);
                sequences += 1;
                stores += expected.len();
            }
        }
        assert_eq!((sequences, stores), (72, 4608));
    }

    #[test]
    fn partial_pll_publication_stops_remaining_clock_commands_and_work() {
        for failure in 0..64 {
            let registers = Arc::new(RecordingRegisters::default());
            registers.state.lock().unwrap().fail_at = Some(failure);
            let owner = Transport::new(registers.clone(), vec![0]).unwrap();
            assert!(owner
                .program_pll(0, PllSetting::new(100, 1).unwrap(), deadline())
                .is_err());
            assert!(owner.terminal());
            assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
            assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
        }
    }
}
