//! Exact110-chip S19 XP/S19j XP serial initialization.
//!
//! Wire constants: held ESP-Miner/components/asic/bm1366.c:166..252,
//! explicitly annotated S19XP stock dump. Runtime model geometry and PSU/LM75
//! selection: campaign evidence/r12, production constructors8242fc/82483c.
//! This does not import S19k's77-chip Braiins fill or its 3Mbaud transition.
use super::*;

pub(super) fn industrial_pll(target: u16, policy: IndustrialSerialPllPolicy) -> Result<(u32, u16)> {
    anyhow::ensure!(
        policy.is_bm1366_xp() && policy.admits_target(target),
        "BM1366 XP frequency {target} is outside its exact model policy"
    );
    let (register, actual) = dcentrald_common::bm1366_pll_reg_and_actual(target);
    anyhow::ensure!(
        actual.abs_diff(target) <= INDUSTRIAL_PLL_MAX_ERROR_MHZ as u16,
        "BM1366 XP PLL error exceeds local policy"
    );
    Ok((register, actual))
}

impl SerialMiner {
    pub(super) fn init_bm1366_xp_chain(
        serial: ValidatedSerialBackend,
        serial_device: &str,
        configured_baud: u32,
        chip_count: u8,
        target_freq_mhz: u16,
        pll_policy: IndustrialSerialPllPolicy,
    ) -> Result<(ValidatedSerialBackend, ValidatedSerialAssignedGeometry)> {
        use dcentrald_common::AsicProtocolIdentity;
        anyhow::ensure!(
            chip_count == 110 && configured_baud == 115_200,
            "BM1366 XP requires110 chips and its cold115200 UART profile"
        );
        let (target_pll, actual) = industrial_pll(target_freq_mhz, pll_policy)?;
        serial.flush_io()?;
        serial.set_response_len(BM13XX_CMD_RESP_BODY_LEN);
        for _ in 0..3 {
            serial.send_write_reg_broadcast_bm1397plus(0xa4, 0x9000_ffff)?;
            std::thread::sleep(Duration::from_millis(5));
        }
        let cold = serial.query_chip_address_window(
            AsicProtocolIdentity::Bm1366,
            "BM1366 XP complete cold identity",
        )?;
        anyhow::ensure!(
            cold.observed_frames().get() == chip_count
                && cold.shape() == SerialAddressWindowShape::RepeatedUnassignedZero,
            "BM1366 XP cold response is not the full unassigned110-chip population"
        );
        serial.send_write_reg_broadcast_bm1397plus(0xa8, 0x0007_0000)?;
        serial.send_write_reg_broadcast_bm1397plus(0x18, 0xff0f_c100)?;
        serial.send_chain_inactive_bm1397plus()?;
        std::thread::sleep(Duration::from_millis(10));
        let interval = Self::serial_address_interval(chip_count)?;
        for address in dcentrald_common::linear_chip_addresses(chip_count, interval) {
            serial.send_set_address_bm1397plus(address)?;
        }
        for (reg, value) in [
            (0x3c, 0x8000_8540),
            (0x3c, 0x8000_8020),
            (0x14, TICKET_MASK_256),
            (0x54, 3),
            (0x58, 0x0211_1111),
        ] {
            serial.send_write_reg_broadcast_bm1397plus(reg, value)?;
            std::thread::sleep(Duration::from_millis(10));
        }
        serial.send_write_reg_bm1397plus(0, 0x2c, 0x007c_0003)?;
        // Held initializer explicitly defers FastUART until a separate call.
        // Retain115200 for command/work/RX; no guessed S19k3M baud pair.
        for address in dcentrald_common::linear_chip_addresses(chip_count, interval) {
            for (reg, value) in [
                (0xa8, 0x0007_01f0),
                (0x18, 0xf000_c100),
                (0x3c, 0x8000_8540),
                (0x3c, 0x8000_8020),
                (0x3c, 0x8000_82aa),
            ] {
                serial.send_write_reg_bm1397plus(address, reg, value)?;
            }
        }
        // Local startup policy: begin at100MHz, then <=6MHz per100ms. This
        // bounds the held ESP transition's6.25MHz/100ms ramp using the common
        // integer-MHz PLL solver.100MHz is a conservative DCENT starting point,
        // not a claim about the unknown power-on PLL. No work is sent yet.
        for frequency in (100..target_freq_mhz).step_by(6) {
            let (register, _) = dcentrald_common::bm1366_pll_reg_and_actual(frequency);
            serial.send_write_reg_broadcast_bm1397plus(0x08, register)?;
            std::thread::sleep(Duration::from_millis(100));
        }
        serial.send_write_reg_broadcast_bm1397plus(0x08, target_pll)?;
        std::thread::sleep(Duration::from_millis(100));
        serial.send_write_reg_broadcast_bm1397plus(0x10, 0x0000_151c)?;
        serial.send_write_reg_broadcast_bm1397plus(0xa4, 0x9000_ffff)?;
        let assigned = serial.query_chip_address_window(
            AsicProtocolIdentity::Bm1366,
            "BM1366 XP complete assigned population",
        )?;
        let geometry = ValidatedSerialAssignedGeometry::from_window(
            assigned,
            AsicProtocolIdentity::Bm1366,
            chip_count,
            interval,
        )?
        .with_applied_frequency(actual);
        tracing::info!(
            serial_device,
            chip_count,
            actual,
            configured_baud,
            "BM1366 XP native init completed with full assigned response coverage"
        );
        Ok((serial, geometry))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn industrial_frequency_is_exact_model_bound_and_preserves_bm1366_solution() {
        for policy in [
            IndustrialSerialPllPolicy::S19XpBm1366Native,
            IndustrialSerialPllPolicy::S19jXpBm1366Native,
        ] {
            let (_, actual) = industrial_pll(400, policy).unwrap();
            assert_eq!(actual, 400);
            assert!(industrial_pll(600, policy).is_err());
        }
        assert!(industrial_pll(400, IndustrialSerialPllPolicy::S21Bm1368ShippedConfig).is_err());
        assert!(industrial_pll(515, IndustrialSerialPllPolicy::S19XpBm1366Native).is_err());
        assert!(industrial_pll(515, IndustrialSerialPllPolicy::S19jXpBm1366Native).is_ok());
    }
}
