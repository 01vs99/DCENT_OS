//! Clean-image S19k identity from the retained, generation-bound EEPROM owner.
//! This does not consume Braiins configuration or a runner-supplied digest.

use super::{S19kLiveHardwareProfile, S19kNativeBoardModel};
use anyhow::{Context, Result};
use dcentrald_api_types::deployed_eeprom::decode_deployed_eeprom;
use dcentrald_api_types::hashboard_eeprom::observed_protocol_from_deployed_page;
use dcentrald_api_types::zhiju_eeprom::Crc5Check;
use dcentrald_common::AsicProtocolIdentity;
use dcentrald_hal::platform::amlogic::{AmlogicPowerThermalService, S19kNativePopulationAdmission};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, Instant};

const SCHEMA: &str = "dcentos.s19k-native-eeprom-identity/v1";

/// Constructed only after complete, CRC-checked deployed identity decoding.
/// The page digest binds raw observations; the model digest binds the decoded
/// slot-to-SKU map. Neither is a claim of a measured ASIC chain population.
#[derive(Debug)]
pub(super) struct S19kNativeIdentityReceipt {
    pub(super) sha256: String,
    pub(super) model_sha256: String,
    pub(super) profile: S19kLiveHardwareProfile,
    pub(super) board_count: usize,
    pub(super) physical_addresses: String,
    pub(super) board_names: String,
    pub(super) eeprom_slots: String,
}

pub(super) fn capture(
    platform: &S19kNativePopulationAdmission,
    service: &AmlogicPowerThermalService,
) -> Result<S19kNativeIdentityReceipt> {
    anyhow::ensure!(
        super::s19k_linux_machine()? == "aarch64",
        "native S19k requires aarch64"
    );
    let cpuinfo = super::s19k_read_regular_nonsymlink(Path::new("/proc/cpuinfo"), "/proc/cpuinfo")?;
    super::s19k_validate_cpuinfo(
        std::str::from_utf8(&cpuinfo).context("native CPU identity UTF-8")?,
    )?;
    let pages = platform.read_identity_pages(service, Instant::now() + Duration::from_secs(3))?;
    let identity = decode_pages(platform.board_target(), platform.populated_slots(), &pages)?;
    let mut names: [Option<String>; 3] = [None, None, None];
    for (slot, page) in pages.iter().enumerate() {
        if let Some(page) = page {
            names[slot] = Some(decode_deployed_eeprom(page)?.board_name);
        }
    }
    platform.bind_population_polarity(service, names.each_ref().map(|name| name.as_deref()))?;
    Ok(identity)
}

fn decode_pages(
    board_target: &str,
    populated: [bool; 3],
    pages: &[Option<Vec<u8>>; 3],
) -> Result<S19kNativeIdentityReceipt> {
    anyhow::ensure!(
        board_target == "am3-s19k",
        "native identity is for the S19k controller"
    );
    anyhow::ensure!(
        populated.iter().any(|present| *present),
        "empty S19k population"
    );
    let mut boards = [None; 3];
    let mut transcript = format!(
        "schema={SCHEMA}\nboard_target={board_target}\ncpu={}\n",
        super::S19K_LIVE_CPU_TUPLE
    );
    for (slot, page) in pages.iter().enumerate() {
        anyhow::ensure!(
            page.is_some() == populated[slot],
            "S19k EEPROM/plug population mismatch at slot {}",
            slot + 1
        );
        let Some(page) = page else {
            transcript.push_str(&format!("slot{}=absent\n", slot + 1));
            continue;
        };
        let identity = decode_deployed_eeprom(page)
            .with_context(|| format!("S19k slot {} deployed EEPROM decode", slot + 1))?;
        anyhow::ensure!(
            identity.board_class == 0x05,
            "S19k slot {} has wrong board class",
            slot + 1
        );
        // CRC5 is a transport/format check, not authentication. Region 2 is
        // intentionally not used here: identity does not authorize factory V/F.
        anyhow::ensure!(
            identity.region_1_crc5 == Crc5Check::Match,
            "S19k slot {} identity CRC mismatch",
            slot + 1
        );
        let board = S19kNativeBoardModel::parse(&identity.board_name).with_context(|| {
            format!(
                "S19k slot {} unsupported SKU {}",
                slot + 1,
                identity.board_name
            )
        })?;
        anyhow::ensure!(
            observed_protocol_from_deployed_page(page) == Some(AsicProtocolIdentity::Bm1366),
            "S19k slot {} SKU/ASIC marking disagrees",
            slot + 1
        );
        boards[slot] = Some(board);
        transcript.push_str(&format!(
            "slot{}={}:{:x}\n",
            slot + 1,
            board.as_str(),
            Sha256::digest(page)
        ));
    }
    let profile = S19kLiveHardwareProfile { boards };
    let model = format!(
        "board_target={board_target}\nphysical_addresses={}\nboard_names={}\n",
        profile.physical_addresses(),
        profile.board_names()
    );
    Ok(S19kNativeIdentityReceipt {
        sha256: format!("{:x}", Sha256::digest(transcript.as_bytes())),
        model_sha256: format!("{:x}", Sha256::digest(model.as_bytes())),
        profile,
        board_count: profile.board_count(),
        physical_addresses: profile.physical_addresses(),
        board_names: profile.board_names(),
        eeprom_slots: profile.eeprom_slots(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held_page() -> Vec<u8> {
        include_bytes!("fixtures/s19k-bhb56903.bin").to_vec()
    }

    #[test]
    fn native_identity_decodes_held_page_for_every_nonempty_population() {
        for mask in 1u8..8 {
            let populated = std::array::from_fn(|slot| mask & (1 << slot) != 0);
            let pages = std::array::from_fn(|slot| populated[slot].then(held_page));
            let receipt = decode_pages("am3-s19k", populated, &pages).unwrap();
            assert_eq!(receipt.profile.eeprom_presence(), populated);
            assert_eq!(receipt.board_count, mask.count_ones() as usize);
            assert_eq!(receipt.sha256.len(), 64);
            assert_eq!(receipt.model_sha256.len(), 64);
        }
    }

    #[test]
    fn native_identity_decodes_every_mixed_and_homogeneous_supported_slot_map() {
        let page902 = include_bytes!("fixtures/epic-bhb56902.bin").to_vec();
        for mut code in 1..27 {
            let mut expected = [None; 3];
            let pages = std::array::from_fn(|slot| {
                let choice = code % 3;
                code /= 3;
                match choice {
                    0 => None,
                    1 => {
                        expected[slot] = Some(S19kNativeBoardModel::Bhb56902);
                        Some(page902.clone())
                    }
                    _ => {
                        expected[slot] = Some(S19kNativeBoardModel::Bhb56903);
                        Some(held_page())
                    }
                }
            });
            let receipt =
                decode_pages("am3-s19k", expected.map(|board| board.is_some()), &pages).unwrap();
            assert_eq!(receipt.profile.boards, expected);
        }
    }

    #[test]
    fn same_header_bm1366_xp_is_not_an_s19k_board() {
        let page = include_bytes!("fixtures/epic-bhb56801.bin").to_vec();
        assert_eq!(&page[..2], &[0x05, 0x11]);
        assert_eq!(
            decode_deployed_eeprom(&page).unwrap().board_name,
            "BHB56801"
        );
        assert!(decode_pages("am3-s19k", [true, false, false], &[Some(page), None, None]).is_err());
    }

    #[test]
    fn native_identity_refuses_wrong_controller_population_and_corrupt_pages() {
        let good = [Some(held_page()), None, None];
        assert!(decode_pages("am3-s21", [true, false, false], &good).is_err());
        assert!(decode_pages("am3-s19k", [false; 3], &[None, None, None]).is_err());
        assert!(decode_pages("am3-s19k", [true, true, false], &good).is_err());
        assert!(decode_pages("am3-s19k", [false, true, false], &good).is_err());
        let mut bad = held_page();
        bad[3] ^= 1;
        assert!(decode_pages("am3-s19k", [true, false, false], &[Some(bad), None, None]).is_err());
        assert!(decode_pages(
            "am3-s19k",
            [true, false, false],
            &[Some(vec![5, 17]), None, None]
        )
        .is_err());
    }
}
