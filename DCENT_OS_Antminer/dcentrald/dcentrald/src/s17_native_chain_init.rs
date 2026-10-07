// SPDX-License-Identifier: GPL-3.0-or-later
//! The native S17 ASIC initializer shared by hardware and host protocol tests.
//! The retained caller still owns EEPROM/PIC/PSU/fan/fabric admission and closeout.
use super::*;

pub(super) trait ColdChainIo: ChainIo {
    fn reset_fifos(&mut self);
    fn read_work_tx_threshold(&self) -> u32;
    fn write_ctrl(&mut self, value: u32);
    fn set_work_time(&mut self, value: u32);
}

impl ColdChainIo for UioChain {
    fn reset_fifos(&mut self) {
        self.0.reset_fifos();
    }
    fn read_work_tx_threshold(&self) -> u32 {
        self.0.read_work_tx_threshold()
    }
    fn write_ctrl(&mut self, value: u32) {
        self.0.write_ctrl(value);
    }
    fn set_work_time(&mut self, value: u32) {
        self.0.set_work_time(value);
    }
}

pub(super) async fn initialize_cold_chain(
    io: &mut impl ColdChainIo,
    reset: &impl ChainResetIo,
    profile: &S17RuntimeProfile,
    chain: &mut ChainProfile,
    work_time: u32,
    shutdown: &CancellationToken,
) -> Result<()> {
    let chips = s17_chips_per_chain(&profile.board_target).context("S17 chip count")?;
    let stride = s17_addr_interval(&profile.board_target).context("S17 address stride")?;
    let driver = Bm1397Driver::new();
    io.reset_fifos();
    ensure!(
        io.read_work_tx_threshold() == 1848,
        "S17 whole-frame FIFO reserve did not read back"
    );
    io.write_ctrl(driver.ctrl_reg_value()); // 0x1c; never CTRL=0.
    release_chain_reset(reset, chain.slot)?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let divisor = discover_divisor(io, chips).await?;
    tracing::info!(
        slot = chain.slot,
        divisor,
        chips,
        "S17 native exact BM1397 enumeration"
    );
    io.command(&[0x53, 5, 0, 0]);
    for chip in 0..chips {
        io.command(&[0x40, 5, chip * stride, 0]);
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    for chip in 0..chips {
        let id = register_read(io, chip * stride, 0).await?;
        ensure!(id >> 16 == 0x1397, "S17 address verification failed");
    }
    // Keep the positively observed ASIC/host baud. Clock and core
    // initialization do not rely on the unresolved fast-UART divider.
    register_write(io, None, 0x80, 0);
    register_write(io, None, 0x84, 0);
    register_write(io, None, 0x20, 1);
    register_write(io, None, 0x3c, 0x8000_8074);
    register_write(io, None, 0x14, driver.ticket_mask(256));
    for mhz in
        dcentrald_common::bm1397_s17_bhb07601::pll_slow_ramp_mhz(u32::from(profile.frequency_mhz))
    {
        let pll = driver.pll_params(mhz as u16).reg_value;
        for _ in 0..2 {
            register_write(io, None, 0x70, 0x0304_0607);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for _ in 0..2 {
            register_write(io, None, 0x08, pll);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    // Use this boot's observed kernel FCLK0 rate. Neither a shared
    // VERSION nor an old capture fixes the current fabric clock.
    io.set_work_time(work_time);
    let pll = driver.pll_params(profile.frequency_mhz).reg_value;
    let observed = register_read(io, 0, 0x08).await?;
    ensure!(
        dcentrald_common::bm1397_pll0_readback_matches(pll, observed),
        "S17 PLL readback mismatch"
    );
    // Jig BHB07601_open_core: 84 outer steps, four core clocks at
    // +{0,84,168,252}, then zero dummy work. Only the ASIC operations
    // are ported; stock register64/36/TW offsets are not s17io MMIO.
    for base in 0..84 {
        for core in dcentrald_common::bm1397_s17_bhb07601::opencore_enable_ids(base) {
            register_write(
                io,
                None,
                0x3c,
                dcentrald_common::bm1397_s17_bhb07601::enable_core_data(core),
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let deadline = Instant::now() + REGISTER_WAIT;
        while io.work_full() {
            ensure!(Instant::now() < deadline, "S17 open-core FIFO stalled");
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        io.write_work(&[0; 36])?;
        tokio::time::sleep(Duration::from_millis(u64::from(profile.open_core_gap_ms))).await;
    }
    io.flush_work();
    initialize_sensors(
        io,
        &mut chain.sensors,
        matches!(profile.board_target.as_str(), "am2-s17plus" | "am2-t17plus"),
    )
    .await?;
    ensure!(!shutdown.is_cancelled(), "S17 bringup cancelled");
    Ok(())
}
