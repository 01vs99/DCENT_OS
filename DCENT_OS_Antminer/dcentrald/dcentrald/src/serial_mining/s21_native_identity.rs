//! Exact deployed S21 identity, read only through retained management custody.
use anyhow::{Context, Result};
use dcentrald_api_types::deployed_eeprom::{decode_deployed_eeprom, DeployedIdentityProvenance};
use dcentrald_api_types::hashboard_eeprom::observed_protocol_from_deployed_page;
use dcentrald_api_types::zhiju_eeprom::Crc5Check;
use dcentrald_common::AsicProtocolIdentity;
use dcentrald_hal::platform::amlogic::{
    AmlogicNoPicAdmission, AmlogicNoPicProfile, AmlogicPowerThermalService,
};
use std::time::{Duration, Instant};

pub(super) fn capture(
    admission: &AmlogicNoPicAdmission,
    service: &AmlogicPowerThermalService,
) -> Result<()> {
    let pages = admission.read_identity_pages(service, Instant::now() + Duration::from_secs(5))?;
    match admission.profile() {
        AmlogicNoPicProfile::S21 => validate_pages(admission.populated_slots(), &pages),
        AmlogicNoPicProfile::S21Pro | AmlogicNoPicProfile::S21Xp => {
            validate_bm1370_pages(admission.profile(), admission.populated_slots(), &pages)
        }
        AmlogicNoPicProfile::S19Xp | AmlogicNoPicProfile::S19jXp => {
            validate_bm1366_xp_pages(admission.profile(), admission.populated_slots(), &pages)
        }
        AmlogicNoPicProfile::S19jProA | AmlogicNoPicProfile::S19jProPlus => {
            validate_bm1362_aml_pages(admission.profile(), admission.populated_slots(), &pages)
        }
        _ => anyhow::bail!("modern S21 identity requested for another controller profile"),
    }?;
    let mut names: [Option<String>; 3] = [None, None, None];
    for (slot, page) in pages.iter().enumerate() {
        if let Some(page) = page {
            names[slot] = Some(decode_deployed_eeprom(page)?.board_name);
        }
    }
    admission.bind_population_polarity(service, names.each_ref().map(|name| name.as_deref()))?;
    Ok(())
}

pub(super) fn validate_pages(population: [bool; 3], pages: &[Option<Vec<u8>>; 3]) -> Result<()> {
    anyhow::ensure!(
        population.iter().any(|present| *present),
        "empty S21 population"
    );
    for (slot, page) in pages.iter().enumerate() {
        anyhow::ensure!(
            page.is_some() == population[slot],
            "S21 plug/EEPROM disagreement at slot{slot}"
        );
        let Some(page) = page else {
            continue;
        };
        let identity = decode_deployed_eeprom(page)
            .with_context(|| format!("S21 slot{slot} deployed identity"))?;
        anyhow::ensure!(
            identity.board_class == 5 && identity.region_1_crc5 == Crc5Check::Match,
            "S21 slot{slot} class/identity checksum rejected"
        );
        // Exact identity rows have separate held evidence; broad BHB68 names
        // include BM1370 and never authorize this 108-chip BM1368 runtime.
        anyhow::ensure!(
            matches!(identity.board_name.as_str(), "BHB68603" | "BHB68606")
                && observed_protocol_from_deployed_page(page) == Some(AsicProtocolIdentity::Bm1368),
            "S21 slot{slot} unsupported deployed board {} / {}",
            identity.board_name,
            identity.chip_marking
        );
        anyhow::ensure!(
            !identity.board_serial.trim().is_empty(),
            "S21 slot{slot} missing factory serial"
        );
        tracing::info!(slot, board = %identity.board_name, serial = %identity.board_serial, "S21 fresh factory identity admitted; factory page remains protected");
    }
    Ok(())
}

/// Format1 proves its plaintext SKU only. It does not manufacture serial,
/// tuning or CRC evidence from the still-encrypted body. The native caller
/// must subsequently prove full BM1370 GetAddress coverage on every route.
pub(super) fn validate_bm1370_pages(
    profile: AmlogicNoPicProfile,
    population: [bool; 3],
    pages: &[Option<Vec<u8>>; 3],
) -> Result<()> {
    let names: &[&str] = match profile {
        AmlogicNoPicProfile::S21Pro => &["A3HB70601", "A3HB70602"],
        AmlogicNoPicProfile::S21Xp => &["A3HB70501", "A3HB70502", "A3HB70503"],
        _ => anyhow::bail!("BM1370 identity requires its exact Pro/XP profile"),
    };
    anyhow::ensure!(
        population.iter().any(|present| *present),
        "empty BM1370 population"
    );
    for (slot, page) in pages.iter().enumerate() {
        anyhow::ensure!(
            page.is_some() == population[slot],
            "BM1370 plug/EEPROM disagreement at slot{slot}"
        );
        let Some(page) = page else {
            continue;
        };
        anyhow::ensure!(
            page.len() == 256,
            "BM1370 slot{slot} requires a complete factory page"
        );
        let identity = decode_deployed_eeprom(page)
            .with_context(|| format!("BM1370 slot{slot} factory identity"))?;
        anyhow::ensure!(
            identity.board_class == 1
                && identity.provenance == DeployedIdentityProvenance::Format1PlaintextName
                && names.contains(&identity.board_name.as_str()),
            "BM1370 slot{slot} factory SKU {} does not select {profile:?}",
            identity.board_name
        );
        tracing::info!(slot, board = %identity.board_name, ?profile,
            "BM1370 plaintext factory SKU selected; independent ASIC count remains required");
    }
    Ok(())
}

/// Exact decrypted SKU selects the production model. The lot-code family
/// letter is corroboration only; full fresh110-chip BM1366 UART confirmation
/// remains mandatory after power/reset. Optional physical PICs are not used
/// by these models' production PSU voltage-controller factory.
pub(super) fn validate_bm1366_xp_pages(
    profile: AmlogicNoPicProfile,
    population: [bool; 3],
    pages: &[Option<Vec<u8>>; 3],
) -> Result<()> {
    let names: &[&str] = match profile {
        AmlogicNoPicProfile::S19Xp => &["BHB56801", "BHB56802"],
        AmlogicNoPicProfile::S19jXp => &["BHB56804"],
        _ => anyhow::bail!("BM1366 XP identity requires an exact XP model profile"),
    };
    anyhow::ensure!(
        population.iter().any(|present| *present),
        "empty BM1366 XP population"
    );
    for (slot, page) in pages.iter().enumerate() {
        anyhow::ensure!(
            page.is_some() == population[slot],
            "BM1366 XP plug/EEPROM disagreement at slot{slot}"
        );
        let Some(page) = page else {
            continue;
        };
        anyhow::ensure!(
            page.len() == 256,
            "BM1366 XP slot{slot} requires a complete factory page"
        );
        let identity = decode_deployed_eeprom(page)
            .with_context(|| format!("BM1366 XP slot{slot} deployed identity"))?;
        anyhow::ensure!(
            matches!(identity.board_class, 4 | 5)
                && identity.region_1_crc5 == Crc5Check::Match
                && names.contains(&identity.board_name.as_str())
                && identity.chip_marking_family_letter() == Some('G')
                && !identity.board_serial.trim().is_empty(),
            "BM1366 XP slot{slot} factory identity {} / {} does not select {profile:?}",
            identity.board_name,
            identity.chip_marking
        );
        tracing::info!(slot, board = %identity.board_name, ?profile,
            "Exact XP factory identity admitted; full110-chip serial confirmation remains required");
    }
    Ok(())
}

/// Exact factory names distinguish PSU-controlled A126/Plus120 from classic
/// PIC boards. This protects the whole EEPROM and reads no calibration into
/// voltage authority; fresh complete serial enumeration remains mandatory.
pub(super) fn validate_bm1362_aml_pages(
    profile: AmlogicNoPicProfile,
    population: [bool; 3],
    pages: &[Option<Vec<u8>>; 3],
) -> Result<()> {
    let names: &[&str] = match profile {
        AmlogicNoPicProfile::S19jProA => &["BHB42603", "BHB42631", "BHB42651"],
        AmlogicNoPicProfile::S19jProPlus => &["BHB42612"],
        _ => anyhow::bail!("BM1362 AML identity requires exact A or Plus profile"),
    };
    anyhow::ensure!(
        population.iter().any(|present| *present),
        "empty BM1362 AML population"
    );
    for (slot, page) in pages.iter().enumerate() {
        anyhow::ensure!(
            page.is_some() == population[slot],
            "BM1362 plug/EEPROM disagreement at slot{slot}"
        );
        let Some(page) = page else {
            continue;
        };
        anyhow::ensure!(
            page.len() == 256,
            "BM1362 AML complete factory page required"
        );
        let identity = decode_deployed_eeprom(page).context("BM1362 AML deployed identity")?;
        anyhow::ensure!(
            identity.board_class == 4
                && identity.region_1_crc5 == Crc5Check::Match
                && names.contains(&identity.board_name.as_str())
                && observed_protocol_from_deployed_page(page) == Some(AsicProtocolIdentity::Bm1362)
                && !identity.board_serial.trim().is_empty(),
            "BM1362 slot{slot} factory identity {} does not select {profile:?}",
            identity.board_name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recorded_bm1362_a_and_plus_pages_select_only_the_exact_psu_factory() {
        for (profile, page) in [
            (
                AmlogicNoPicProfile::S19jProA,
                include_bytes!("fixtures/bm1362-bhb42603.bin"),
            ),
            (
                AmlogicNoPicProfile::S19jProA,
                include_bytes!("fixtures/bm1362-bhb42631.bin"),
            ),
            (
                AmlogicNoPicProfile::S19jProA,
                include_bytes!("fixtures/bm1362-bhb42651.bin"),
            ),
            (
                AmlogicNoPicProfile::S19jProPlus,
                include_bytes!("fixtures/bm1362-bhb42612.bin"),
            ),
        ] {
            for mask in 1..8 {
                let population = std::array::from_fn(|slot| mask & (1 << slot) != 0);
                let pages = population.map(|present| present.then(|| page.to_vec()));
                validate_bm1362_aml_pages(profile, population, &pages).unwrap();
                let wrong = if profile == AmlogicNoPicProfile::S19jProA {
                    AmlogicNoPicProfile::S19jProPlus
                } else {
                    AmlogicNoPicProfile::S19jProA
                };
                assert!(validate_bm1362_aml_pages(wrong, population, &pages).is_err());
            }
            let mut changed = page.to_vec();
            changed[12] ^= 1;
            assert!(validate_bm1362_aml_pages(
                profile,
                [true, false, false],
                &[Some(changed), None, None]
            )
            .is_err());
        }
        let classic = include_bytes!("fixtures/bm1362-bhb42601.bin").to_vec();
        for profile in [
            AmlogicNoPicProfile::S19jProA,
            AmlogicNoPicProfile::S19jProPlus,
        ] {
            assert!(validate_bm1362_aml_pages(
                profile,
                [true, false, false],
                &[Some(classic.clone()), None, None]
            )
            .is_err());
            assert!(
                validate_bm1362_aml_pages(profile, [true, false, false], &[None, None, None])
                    .is_err()
            );
        }
    }

    #[test]
    fn exact_recorded_s21_page_admits_every_nonempty_physical_population() {
        let page = include_bytes!("fixtures/s21-bhb68606.bin");
        let decoded = decode_deployed_eeprom(page).unwrap();
        assert_eq!(decoded.board_name, "BHB68606");
        assert_eq!(decoded.board_serial, "DGAHYS3BDJEAF0087");
        for mask in 1..8 {
            let population = std::array::from_fn(|slot| mask & (1 << slot) != 0);
            let pages = population.map(|present| present.then(|| page.to_vec()));
            validate_pages(population, &pages).unwrap();
        }
    }
    #[test]
    fn changed_ciphertext_or_foreign_family_cannot_select_s21_profile() {
        let mut changed = include_bytes!("fixtures/s21-bhb68606.bin").to_vec();
        changed[12] ^= 1;
        assert!(validate_pages([true, false, false], &[Some(changed), None, None]).is_err());
        let foreign = include_bytes!("fixtures/s19k-bhb56903.bin").to_vec();
        assert!(validate_pages([true, false, false], &[Some(foreign), None, None]).is_err());
        assert!(validate_pages([false, true, false], &[None, None, None]).is_err());
    }
    #[test]
    fn recorded_format1_pro_and_xp_pages_select_every_nonempty_population() {
        // Exact held ePIC-matched EEPROM pages copied from api-types fixtures;
        // these are recorded bytes, not a claimed live DCENT BM1370 capture.
        for (profile, page) in [
            (
                AmlogicNoPicProfile::S21Pro,
                include_bytes!("fixtures/bm1370-a3hb70601.bin"),
            ),
            (
                AmlogicNoPicProfile::S21Xp,
                include_bytes!("fixtures/bm1370-a3hb70501.bin"),
            ),
        ] {
            let decoded = decode_deployed_eeprom(page).unwrap();
            assert!(decoded.board_serial.is_empty());
            assert_eq!(decoded.region_1_crc5, Crc5Check::Unknown);
            for mask in 1..8 {
                let population = std::array::from_fn(|slot| mask & (1 << slot) != 0);
                validate_bm1370_pages(
                    profile,
                    population,
                    &population.map(|present| present.then(|| page.to_vec())),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn bm1370_plaintext_selection_rejects_cross_model_plus_and_missing_pages() {
        let pro = include_bytes!("fixtures/bm1370-a3hb70601.bin").to_vec();
        let xp = include_bytes!("fixtures/bm1370-a3hb70501.bin").to_vec();
        let plus = include_bytes!("fixtures/bm1370-a3hb70701.bin").to_vec();
        assert!(validate_bm1370_pages(
            AmlogicNoPicProfile::S21Xp,
            [true, false, false],
            &[Some(pro), None, None]
        )
        .is_err());
        for page in [xp, plus] {
            assert!(validate_bm1370_pages(
                AmlogicNoPicProfile::S21Pro,
                [true, false, false],
                &[Some(page), None, None]
            )
            .is_err());
        }
        assert!(validate_bm1370_pages(
            AmlogicNoPicProfile::S21Pro,
            [false, true, false],
            &[None, None, None]
        )
        .is_err());
    }
    #[test]
    fn recorded_bm1366_xp_pages_select_exact_model_and_every_population() {
        for (profile, page) in [
            (
                AmlogicNoPicProfile::S19Xp,
                include_bytes!("fixtures/bm1366-bhb56801-class4.bin"),
            ),
            (
                AmlogicNoPicProfile::S19Xp,
                include_bytes!("fixtures/bm1366-bhb56801-class5.bin"),
            ),
            (
                AmlogicNoPicProfile::S19jXp,
                include_bytes!("fixtures/bm1366-bhb56804.bin"),
            ),
        ] {
            for mask in 1..8 {
                let population = std::array::from_fn(|slot| mask & (1 << slot) != 0);
                validate_bm1366_xp_pages(
                    profile,
                    population,
                    &population.map(|present| present.then(|| page.to_vec())),
                )
                .unwrap();
            }
            let other = if profile == AmlogicNoPicProfile::S19Xp {
                AmlogicNoPicProfile::S19jXp
            } else {
                AmlogicNoPicProfile::S19Xp
            };
            assert!(validate_bm1366_xp_pages(
                other,
                [true, false, false],
                &[Some(page.to_vec()), None, None]
            )
            .is_err());
            let mut changed = page.to_vec();
            changed[12] ^= 1;
            assert!(validate_bm1366_xp_pages(
                profile,
                [true, false, false],
                &[Some(changed), None, None]
            )
            .is_err());
        }
        assert!(validate_bm1366_xp_pages(
            AmlogicNoPicProfile::S19Xp,
            [true, false, false],
            &[
                Some(include_bytes!("fixtures/s19k-bhb56903.bin").to_vec()),
                None,
                None
            ]
        )
        .is_err());
    }
}
