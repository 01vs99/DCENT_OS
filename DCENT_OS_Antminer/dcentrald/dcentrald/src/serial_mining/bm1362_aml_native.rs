//! Exact classic126/A126/Plus120 BM1362 initialization on retained AML UARTs.
//!
//! The pinned held AArch64 production serializer is executed in campaign R10:
//! 8b7e44 cold preamble, 8b78c8 analog/IO and 8b84b8 per-chip/nonce/HCN.
//! PLL encoding uses the common BM1362 table, independently accepted-share
//! qualified on that silicon. Timing and400..500MHz steps are DCENT policy;
//! neither the replay nor a PTY test is physical hashing qualification.
use super::*;

pub(super) fn industrial_pll(target: u16, policy: IndustrialSerialPllPolicy) -> Result<(u32, u16)> {
    anyhow::ensure!(
        policy.is_bm1362_aml() && policy.admits_target(target),
        "BM1362 AML frequency {target} is outside the exact native model policy"
    );
    let (register, actual) = dcentrald_common::bm1362_pll_reg_and_actual(target);
    anyhow::ensure!(
        actual == target,
        "BM1362 AML requires an exact common PLL step"
    );
    Ok((register, actual))
}

pub(super) fn hash_counting_number(chips: u8, actual_mhz: u16) -> Result<u32> {
    anyhow::ensure!(
        matches!(chips, 120 | 126) && actual_mhz > 0,
        "BM1362 AML HCN needs an exact populated chain and nonzero actual frequency"
    );
    // Original8b84b8, independently replayed120/126 at300/350/400/500/550MHz:
    // floor(2^32 * 12.5MHz *0.8 / (128 cores *chips *actual Hz)).
    let hcn =
        ((1u64 << 32) * 10_000_000) / (128 * u64::from(chips) * u64::from(actual_mhz) * 1_000_000);
    Ok(u32::try_from(hcn)?)
}

pub(super) fn runtime_hcn(
    descriptor: &SerialSessionDescriptor,
    register: u8,
    value: u32,
) -> Result<Option<u32>> {
    let Some(policy) = descriptor
        .industrial_pll_policy
        .filter(|policy| policy.is_bm1362_aml())
    else {
        return Ok(None);
    };
    if register != 0x08 {
        return Ok(None);
    }
    anyhow::ensure!(
        IndustrialSerialPllPolicy::for_route(descriptor.board_target, descriptor.identity)?
            == policy,
        "BM1362 AML runtime PLL lost its exact model identity"
    );
    let count = match policy {
        IndustrialSerialPllPolicy::S19jProABm1362Native
        | IndustrialSerialPllPolicy::S19jProClassicAmlBm1362Native => 126,
        IndustrialSerialPllPolicy::S19jProPlusBm1362Native => 120,
        _ => unreachable!(),
    };
    anyhow::ensure!(
        descriptor.configured_chip_count == count,
        "BM1362 AML runtime PLL geometry drift"
    );
    let actual = (400..=500)
        .step_by(25)
        .find(|mhz| industrial_pll(*mhz, policy).is_ok_and(|(candidate, _)| candidate == value))
        .context("BM1362 AML runtime PLL is not an admitted exact model step")?;
    Ok(Some(hash_counting_number(count, actual)?))
}

impl SerialMiner {
    pub(super) fn init_bm1362_aml_chain(
        serial: ValidatedSerialBackend,
        serial_device: &str,
        configured_baud: u32,
        chip_count: u8,
        target_freq_mhz: u16,
        pll_policy: IndustrialSerialPllPolicy,
    ) -> Result<(ValidatedSerialBackend, ValidatedSerialAssignedGeometry)> {
        let geometry = Self::init_bm1362_aml_chain_retained(
            &serial,
            serial_device,
            configured_baud,
            chip_count,
            target_freq_mhz,
            pll_policy,
        )?;
        Ok((serial, geometry))
    }

    /// Borrow an already retained UART so an initialization error cannot drop
    /// its exclusive descriptor before the route performs independent cutoff.
    pub(super) fn init_bm1362_aml_chain_retained(
        serial: &ValidatedSerialBackend,
        serial_device: &str,
        configured_baud: u32,
        chip_count: u8,
        target_freq_mhz: u16,
        pll_policy: IndustrialSerialPllPolicy,
    ) -> Result<ValidatedSerialAssignedGeometry> {
        use dcentrald_common::AsicProtocolIdentity;
        let expected = match pll_policy {
            IndustrialSerialPllPolicy::S19jProABm1362Native
            | IndustrialSerialPllPolicy::S19jProClassicAmlBm1362Native => 126,
            IndustrialSerialPllPolicy::S19jProPlusBm1362Native => 120,
            _ => anyhow::bail!("BM1362 AML init requires exact classic, A or Plus model policy"),
        };
        anyhow::ensure!(
            chip_count == expected && configured_baud == 115_200,
            "BM1362 AML init requires its complete factory geometry and115200 UART"
        );
        let (pll, actual) = industrial_pll(target_freq_mhz, pll_policy)?;
        let hcn = hash_counting_number(chip_count, actual)?;
        serial.flush_io()?;
        serial.set_response_len(BM13XX_CMD_RESP_BODY_LEN);
        // Exact held preamble;100ms between writes comes from the same method.
        for (reg, value) in [(0xa8, 0), (0x18, 0xb000_c100), (0xa4, 0x9000_ffff)] {
            serial.send_write_reg_broadcast_bm1397plus(reg, value)?;
            std::thread::sleep(Duration::from_millis(100));
        }
        let cold = serial.query_cold_chip_address_window(
            AsicProtocolIdentity::Bm1362,
            "BM1362 AML complete cold identity",
        )?;
        anyhow::ensure!(
            cold.observed_frames().get() == chip_count
                && cold.shape() == SerialAddressWindowShape::RepeatedUnassignedZero,
            "BM1362 AML cold response lacks complete unassigned factory population"
        );
        serial.send_chain_inactive_bm1397plus()?;
        std::thread::sleep(Duration::from_millis(100));
        let interval = Self::serial_address_interval(chip_count)?;
        for address in dcentrald_common::linear_chip_addresses(chip_count, interval) {
            serial.send_set_address_bm1397plus(address)?;
        }
        for (reg, value) in [(0x54, 3), (0x58, 0x0001_1111)] {
            serial.send_write_reg_broadcast_bm1397plus(reg, value)?;
        }
        // Exact original targeted serializers, including byte order. In
        // particular A8=2 and Misc=b000c100 are not the older AM2 trace literals.
        for address in dcentrald_common::linear_chip_addresses(chip_count, interval) {
            for (reg, value) in [
                (0xa8, 2),
                (0x18, 0xb000_c100),
                (0x3c, 0x8000_8540),
                (0x3c, 0x8000_8008),
                (0x3c, 0x8000_82aa),
            ] {
                serial.send_write_reg_bm1397plus(address, reg, value)?;
            }
        }
        let offset_step = 65535 / u32::from(chip_count);
        for (index, address) in dcentrald_common::linear_chip_addresses(chip_count, interval)
            .into_iter()
            .enumerate()
        {
            serial.send_write_reg_bm1397plus(
                address,
                0x0c,
                0x8000_0000 | offset_step * index as u32,
            )?;
        }
        // Same-silicon PLL0 divider and table encoding; no work before settle.
        serial.send_write_reg_broadcast_bm1397plus(0x70, 0)?;
        serial.send_write_reg_broadcast_bm1397plus(0x08, pll)?;
        std::thread::sleep(Duration::from_millis(100));
        serial.send_write_reg_broadcast_bm1397plus(0x14, TICKET_MASK_256)?;
        serial.send_write_reg_broadcast_bm1397plus(0x10, hcn)?;
        serial.send_write_reg_broadcast_bm1397plus(0xa4, 0x9000_ffff)?;
        // Retain the cold UART rate: no inferred fast-baud register transition.
        let assigned = serial.query_chip_address_window(
            AsicProtocolIdentity::Bm1362,
            "BM1362 AML complete assigned population",
        )?;
        let geometry = ValidatedSerialAssignedGeometry::from_window(
            assigned,
            AsicProtocolIdentity::Bm1362,
            chip_count,
            interval,
        )?
        .with_applied_frequency(actual);
        tracing::info!(
            serial_device,
            chip_count,
            actual,
            configured_baud,
            hcn,
            "BM1362 AML native initialization completed with full assigned coverage"
        );
        Ok(geometry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_model_pll_and_original_machine_code_hcn_vectors() {
        for policy in [
            IndustrialSerialPllPolicy::S19jProClassicAmlBm1362Native,
            IndustrialSerialPllPolicy::S19jProABm1362Native,
            IndustrialSerialPllPolicy::S19jProPlusBm1362Native,
        ] {
            assert_eq!(industrial_pll(400, policy).unwrap(), (0x50a0_0141, 400));
            for mhz in [300, 399, 412, 501, 550] {
                assert!(industrial_pll(mhz, policy).is_err());
            }
        }
        assert!(industrial_pll(400, IndustrialSerialPllPolicy::S21Bm1368ShippedConfig).is_err());
        for (count, values) in [
            (120, [9320, 7989, 6990, 5592, 5084]),
            (126, [8876, 7608, 6657, 5326, 4841]),
        ] {
            for (mhz, expected) in [300, 350, 400, 500, 550].into_iter().zip(values) {
                assert_eq!(hash_counting_number(count, mhz).unwrap(), expected);
            }
        }
        assert!(hash_counting_number(0, 400).is_err());
        assert!(hash_counting_number(126, 0).is_err());
        assert!(hash_counting_number(110, 400).is_err());
    }
}
