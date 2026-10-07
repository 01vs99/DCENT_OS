//! Modern bm13xx FIFO ABI recovered from held bosminer.bin, not from labels
//! attached to a register dump. See campaign evidence/r07/modern-fpga-abi.md.
//! Function names there are investigator-assigned; addresses are original.

use crate::fpga_chain::FpgaChain;
use dcentrald_common::s19_bm1398_runtime::Bm1398FpgaMidstateMode;
use std::time::Duration;

pub const BM13XX_VERSION: u32 = 0x0090_1002;
// The stock opener 0x376fdc requires this format/version and a build at least
// this timestamp. Build is retained separately; it is never called CTRL.
pub const MINIMUM_BUILD: u32 = 0x5c2a_ad81;
pub const STARTUP_BAUD_DIVISOR: u32 = 108;
pub const MAX_WORK_TIME_TICKS: u32 = 5_000_000;
pub const WORK_FIFO_WORDS: usize = 2048;
pub const WORK_FIFO_THRESHOLD: u32 = 1848;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398FpgaFabric {
    pub version: u32,
    pub build_timestamp: u32,
}

pub fn validate_fabric(fpga: &FpgaChain) -> Result<Bm1398FpgaFabric, String> {
    let fabric = Bm1398FpgaFabric {
        version: fpga.read_raw(0),
        build_timestamp: fpga.read_raw(4),
    };
    if fpga.uses_am2_register_layout()
        || fabric.version != BM13XX_VERSION
        || (fabric.build_timestamp as i32) < MINIMUM_BUILD as i32
    {
        return Err(format!(
            "BM1398 requires stock bm13xx version 00901002, supported build and CTRL+8 handle; observed {fabric:?}"
        ));
    }
    Ok(fabric)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bm1398FpgaWorkConfig {
    mode: Bm1398FpgaMidstateMode,
    work_time_ticks: u32,
}

impl Bm1398FpgaWorkConfig {
    /// Exact register conversion recovered at 0x387458: truncate duration at
    /// 100 MHz and cap at 50 ms. Choosing the interval is scheduler policy.
    pub fn new(mode: Bm1398FpgaMidstateMode, interval: Duration) -> Result<Self, String> {
        let ticks = (interval.as_nanos() / 10).min(u128::from(MAX_WORK_TIME_TICKS)) as u32;
        if ticks == 0 {
            return Err("BM1398 work interval must contain at least one 100 MHz tick".into());
        }
        Ok(Self {
            mode,
            work_time_ticks: ticks,
        })
    }

    pub fn word_count(self) -> usize {
        4 + 8 * (1_usize << self.midstate_log2())
    }

    pub fn midstate_log2(self) -> u8 {
        match self.mode {
            Bm1398FpgaMidstateMode::Four => 2,
            Bm1398FpgaMidstateMode::Eight => 3,
        }
    }

    pub fn work_time_ticks(self) -> u32 {
        self.work_time_ticks
    }

    pub fn host_work_id_slots(self) -> u32 {
        1_u32 << (16 - self.midstate_log2())
    }

    /// Mirrors 0x36b10c..0x36b130: preserve other bits, log2 in bits2:1,
    /// enable bit3 and BM139X command/work encoding bit4.
    pub fn control_word(self, current: u32) -> u32 {
        (current & !6) | (u32::from(self.midstate_log2()) << 1) | 0x18
    }

    /// Operates only the already-owned handle. No factory, PIC or rail I/O.
    /// No zero-CTRL transition and no invented inline work-time word.
    pub fn apply(self, fpga: &FpgaChain) -> Result<Bm1398FpgaFabric, String> {
        let fabric = validate_fabric(fpga)?;
        let ctrl = self.control_word(fpga.read_ctrl());
        fpga.set_baud(STARTUP_BAUD_DIVISOR);
        fpga.write_ctrl(ctrl);
        fpga.set_work_time(self.work_time_ticks);
        fpga.write_work_tx_threshold(WORK_FIFO_THRESHOLD);
        if fpga.read_ctrl() != ctrl
            || fpga.read_baud() != STARTUP_BAUD_DIVISOR
            || fpga.read_work_time() != self.work_time_ticks
            || fpga.read_work_tx_threshold() != WORK_FIFO_THRESHOLD
        {
            return Err("BM1398 FPGA configuration readback mismatch".into());
        }
        Ok(fabric)
    }

    pub fn can_enqueue(self, fpga: &FpgaChain) -> Result<bool, String> {
        whole_frame_capacity(fpga, self.word_count())
    }

    /// The recorded modern sender at 0x323114 writes four header words,
    /// followed by each SHA midstate reversed across its full 32 bytes.
    /// Input midstates are canonical SHA digest bytes, not host-native words.
    /// RTL inserts the ASIC preamble/CRC and zero starting nonce itself.
    pub fn encode_work(
        self,
        work_id: u16,
        nbits: u32,
        ntime: u32,
        merkle_tail: [u8; 4],
        midstates: &[[u8; 32]],
    ) -> Result<Vec<u32>, String> {
        if u32::from(work_id) >= self.host_work_id_slots()
            || midstates.len() != 1_usize << self.midstate_log2()
        {
            return Err("BM1398 work ID or midstate count exceeds configured FPGA format".into());
        }
        let mut words = Vec::with_capacity(self.word_count());
        words.extend_from_slice(&[
            u32::from(work_id) << self.midstate_log2(),
            nbits,
            ntime,
            u32::from_le_bytes(merkle_tail),
        ]);
        for midstate in midstates {
            for chunk in midstate.chunks_exact(4).rev() {
                words.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
            }
        }
        Ok(words)
    }
}

/// Sole-writer admission for a complete packet. A non-full FIFO could have
/// only one free word. The held FIFO RTL reports its *current* below-threshold
/// condition in status bit4; it is not a latched interrupt acknowledgement.
/// At threshold1848 the 2048-word FIFO reserves more than either packet width.
pub fn whole_frame_capacity(fpga: &FpgaChain, words: usize) -> Result<bool, String> {
    whole_frame_capacity_from_status(
        fpga.read_work_tx_status(),
        fpga.read_work_tx_threshold(),
        words,
    )
}

fn whole_frame_capacity_from_status(
    status: u32,
    threshold: u32,
    words: usize,
) -> Result<bool, String> {
    if !matches!(words, 36 | 68) || threshold == 0 || threshold as usize > WORK_FIFO_WORDS - words {
        return Err("BM1398 FIFO threshold cannot reserve a complete work packet".into());
    }
    use crate::fpga_chain::{STAT_IRQ, STAT_TX_EMPTY, STAT_TX_FULL};
    Ok(status & STAT_TX_FULL == 0 && status & (STAT_IRQ | STAT_TX_EMPTY) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fifo_capacity_requires_space_for_the_whole_packet() {
        use crate::fpga_chain::{STAT_IRQ, STAT_TX_EMPTY, STAT_TX_FULL};
        assert!(!whole_frame_capacity_from_status(0, 1848, 36).unwrap());
        assert!(whole_frame_capacity_from_status(STAT_IRQ, 1848, 68).unwrap());
        assert!(whole_frame_capacity_from_status(STAT_TX_EMPTY, 1848, 36).unwrap());
        assert!(!whole_frame_capacity_from_status(STAT_IRQ | STAT_TX_FULL, 1848, 36).unwrap());
        assert!(whole_frame_capacity_from_status(STAT_IRQ, 2040, 36).is_err());
        assert!(whole_frame_capacity_from_status(STAT_TX_EMPTY, 0, 36).is_err());
    }

    #[test]
    fn stock_timing_conversion_and_control_preserve_distinct_registers() {
        let four =
            Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Four, Duration::from_nanos(1009))
                .unwrap();
        assert_eq!(four.work_time_ticks(), 100);
        assert_eq!(four.control_word(0), 0x1c);
        assert_eq!(four.control_word(0x206), 0x21c);
        let eight =
            Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Eight, Duration::from_secs(1))
                .unwrap();
        assert_eq!(eight.work_time_ticks(), 5_000_000);
        assert_eq!(eight.control_word(0), 0x1e);
        assert!(Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Four, Duration::ZERO).is_err());
    }

    #[test]
    fn stock_fifo_encoder_uses_extended_id_and_full_reversed_midstate() {
        let config =
            Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Four, Duration::from_millis(4))
                .unwrap();
        let midstate = std::array::from_fn(|i| i as u8);
        let words = config
            .encode_work(
                0x3fff,
                0x1d00ffff,
                0x495fab29,
                [0x4b, 0x1e, 0x5e, 0x4a],
                &[midstate; 4],
            )
            .unwrap();
        assert_eq!(words.len(), 36);
        assert_eq!(&words[..4], &[0xfffc, 0x1d00ffff, 0x495fab29, 0x4a5e1e4b]);
        assert_eq!(words[4], 0x1c1d1e1f);
        assert_eq!(words[11], 0x00010203);
        assert!(config
            .encode_work(0x4000, 0, 0, [0; 4], &[midstate; 4])
            .is_err());
        let eight =
            Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Eight, Duration::from_millis(8))
                .unwrap();
        assert_eq!(
            eight
                .encode_work(0x1fff, 0, 0, [0; 4], &[midstate; 8])
                .unwrap()
                .len(),
            68
        );
        assert!(eight
            .encode_work(0x2000, 0, 0, [0; 4], &[midstate; 8])
            .is_err());
    }
}
