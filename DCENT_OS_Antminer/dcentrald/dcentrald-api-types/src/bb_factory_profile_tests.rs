use super::*;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("bb_factory_profile_vectors.json")).unwrap()
}

fn page(name: &str) -> Vec<u8> {
    let vectors = vectors();
    let hex = vectors["fixtures"][name]["raw"].as_str().unwrap();
    assert_eq!(hex.len(), RAW_PAGE_LEN * 2);
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn held_pages_join_source_profiles_factory_units_and_immutable_raw_custody() {
    let vectors = vectors();
    for (name, sku, frequency) in [
        ("held_42601", BbFactorySku::Bhb42601, 545),
        ("held_42641", BbFactorySku::Bhb42641, 505),
    ] {
        let mut raw = page(name);
        let before = raw.clone();
        let profile = BbFactoryPage::decode(0x50, &raw).unwrap();
        assert_eq!(profile.raw_page().as_slice(), before);
        assert_eq!(profile.sku(), sku);
        assert_eq!(profile.sku().board_name(), profile.identity().board_name);
        assert_eq!(profile.sku().expected_chip_count(), 126);
        assert_eq!(
            profile.sku().pic_profile(),
            BbFactoryPicProfile::ClassicBhb426
        );
        assert_eq!(profile.factory_voltage_cv(), 1340);
        assert_eq!(profile.factory_frequency_mhz(), frequency);
        let expected = &vectors["fixtures"][name]["expected"];
        assert_eq!(
            u64::from(profile.factory_voltage_cv()) * 10,
            expected["default_volt"].as_u64().unwrap()
        );
        assert_eq!(
            profile.identity().board_serial,
            expected["board_serial_no"].as_str().unwrap()
        );
        assert_eq!(
            profile.identity().chip_marking,
            expected["chip_marking"].as_str().unwrap()
        );
        assert_eq!(profile.identity().region_1_crc5, Crc5Check::Match);
        assert_eq!(profile.identity().region_2_crc5, Crc5Check::Match);
        raw.fill(0);
        let mut detached_identity = profile.identity().clone();
        detached_identity.board_name = "untrusted replacement".into();
        detached_identity.voltage_cv = u16::MAX;
        assert_eq!(profile.raw_page().as_slice(), before);
        assert_eq!(profile.identity().board_name, sku.board_name());
        assert_eq!(profile.factory_voltage_cv(), 1340);
        assert_eq!(profile.clone(), profile);
    }
}

#[test]
fn complete_decoder_endpoint_range_is_explicit_and_not_a_physical_population() {
    let raw = page("held_42601");
    for address in 0..=u8::MAX {
        match BbFactoryPage::decode(address, &raw) {
            Ok(profile) => {
                assert!((0x50..=0x53).contains(&address));
                assert_eq!(profile.address(), address);
                assert_eq!(profile.source_chain_index(), address - 0x50);
            }
            Err(error) => {
                assert!(!(0x50..=0x53).contains(&address));
                assert_eq!(error, BbFactoryPageError::InvalidAddress { address });
            }
        }
    }
}

#[test]
fn every_partial_length_and_overlong_record_refuses_without_padding() {
    let raw = page("held_42601");
    for length in 0..RAW_PAGE_LEN {
        assert_eq!(
            BbFactoryPage::decode(0x50, &raw[..length]).unwrap_err(),
            BbFactoryPageError::Decode(DeployedEepromError::WrongLength { got: length })
        );
    }
    for length in [257, 258, 512] {
        let mut overlong = raw.clone();
        overlong.resize(length, 0);
        assert_eq!(
            BbFactoryPage::decode(0x50, &overlong).unwrap_err(),
            BbFactoryPageError::Decode(DeployedEepromError::WrongLength { got: length })
        );
    }
}

#[test]
fn exact_sku_and_decrypted_class_refuse_neighbor_profiles_and_name_only_data() {
    for (name, board_name) in [
        ("unsupported_42621", "BHB42621"),
        ("unsupported_42699", "BHB42699"),
        ("held_a126", "BHB42603"),
        ("held_plus120", "BHB42612"),
    ] {
        let raw = page(name);
        let decoded = decode_deployed_eeprom(&raw).unwrap();
        assert_eq!(decoded.board_name, board_name);
        assert_eq!(decoded.region_1_crc5, Crc5Check::Match);
        assert_eq!(decoded.region_2_crc5, Crc5Check::Match);
        assert_eq!(
            BbFactoryPage::decode(0x50, &raw).unwrap_err(),
            BbFactoryPageError::UnsupportedSku {
                board_name: board_name.into()
            }
        );
    }
    for (name, class) in [("held_format1", 1), ("class5", 5)] {
        assert_eq!(
            BbFactoryPage::decode(0x50, &page(name)).unwrap_err(),
            BbFactoryPageError::IncompleteFactoryIdentity { board_class: class }
        );
    }
}

#[test]
fn unsupported_algorithm_key_and_uncorroborated_identity_cannot_mint_profile() {
    let original = page("held_42601");
    for algorithm in 0..=15 {
        if algorithm == 1 {
            continue;
        }
        let mut raw = original.clone();
        raw[1] = (algorithm << 4) | 1;
        assert_eq!(
            BbFactoryPage::decode(0x50, &raw).unwrap_err(),
            BbFactoryPageError::Decode(DeployedEepromError::UnsupportedAlgorithm {
                algo_nibble: algorithm
            })
        );
    }
    for key_index in 4..=15 {
        let mut raw = original.clone();
        raw[1] = 0x10 | key_index;
        assert_eq!(
            BbFactoryPage::decode(0x50, &raw).unwrap_err(),
            BbFactoryPageError::Decode(DeployedEepromError::UnsupportedKeyIndex { key_index })
        );
    }
    for name in ["foreign_marking", "unknown_marking", "short_marking"] {
        let raw = page(name);
        let identity = decode_deployed_eeprom(&raw).unwrap();
        assert_eq!(identity.region_1_crc5, Crc5Check::Match);
        assert_eq!(identity.region_2_crc5, Crc5Check::Match);
        assert_eq!(
            BbFactoryPage::decode(0x50, &raw).unwrap_err(),
            BbFactoryPageError::SiliconDisagreement
        );
    }
    assert_eq!(
        BbFactoryPage::decode(0x50, &page("empty_serial")).unwrap_err(),
        BbFactoryPageError::EmptySerial
    );
}

#[test]
fn both_crc_checks_are_required_here_while_shared_decoder_stays_advisory() {
    for (name, first_region) in [
        ("identity_crc_mismatch", true),
        ("parameters_crc_mismatch", false),
    ] {
        let raw = page(name);
        let shared = decode_deployed_eeprom(&raw).expect("shared decoder must remain advisory");
        assert_eq!(shared.board_name, "BHB42601");
        assert_eq!(shared.voltage_cv, 1340);
        assert_eq!(shared.frequency_mhz, 545);
        let error = BbFactoryPage::decode(0x50, &raw).unwrap_err();
        if first_region {
            assert!(matches!(shared.region_1_crc5, Crc5Check::Mismatch { .. }));
            assert_eq!(shared.region_2_crc5, Crc5Check::Match);
            assert_eq!(
                error,
                BbFactoryPageError::IdentityCrc {
                    observed: shared.region_1_crc5
                }
            );
        } else {
            assert_eq!(shared.region_1_crc5, Crc5Check::Match);
            assert!(matches!(shared.region_2_crc5, Crc5Check::Mismatch { .. }));
            assert_eq!(
                error,
                BbFactoryPageError::ParametersCrc {
                    observed: shared.region_2_crc5
                }
            );
        }
    }
    let mut raw = page("held_42601");
    raw[255] = 0;
    let profile = BbFactoryPage::decode(0x50, &raw).unwrap();
    assert!(!profile.identity().end_sentinel_present);
    assert_eq!(profile.raw_page().as_slice(), raw);
    // The advisory sentinel does not authenticate identity or add a live gate.
}

#[test]
fn selected_collection_retains_every_record_in_selected_order() {
    let raw = page("held_42601");
    for selected in [vec![0x52], vec![0x52, 0x50], vec![0x53, 0x51, 0x50, 0x52]] {
        // Reuse of a test page at caller labels tests ordering only; it does not
        // fabricate different physical boards or a measured population.
        let records: Vec<_> = selected
            .iter()
            .rev()
            .map(|&address| (address, raw.as_slice()))
            .collect();
        let result = BbFactoryCollection::decode(&selected, &records).unwrap();
        assert_eq!(result.pages().len(), selected.len());
        for (record, &address) in result.pages().iter().zip(&selected) {
            assert_eq!(record.address(), address);
            assert_eq!(record.raw_page().as_slice(), raw);
        }
    }
}

#[test]
fn invalid_selected_sets_missing_extra_duplicate_and_foreign_records_refuse() {
    let raw = page("held_42601");
    let record = [(0x50, raw.as_slice())];
    assert_eq!(
        BbFactoryCollection::decode(&[], &[]).unwrap_err(),
        BbFactoryCollectionError::SelectedCount { got: 0 }
    );
    assert_eq!(
        BbFactoryCollection::decode(&[0x50; 5], &[]).unwrap_err(),
        BbFactoryCollectionError::SelectedCount { got: 5 }
    );
    for address in [0, 0x4f, 0x54, 0xff] {
        assert_eq!(
            BbFactoryCollection::decode(&[address], &record).unwrap_err(),
            BbFactoryCollectionError::InvalidSelectedAddress { address }
        );
    }
    assert_eq!(
        BbFactoryCollection::decode(&[0x50, 0x50], &[]).unwrap_err(),
        BbFactoryCollectionError::DuplicateSelectedAddress { address: 0x50 }
    );
    assert_eq!(
        BbFactoryCollection::decode(&[0x50, 0x51], &record).unwrap_err(),
        BbFactoryCollectionError::RecordCount {
            expected: 2,
            got: 1
        }
    );
    assert_eq!(
        BbFactoryCollection::decode(&[0x50], &[(0x50, raw.as_slice()); 2]).unwrap_err(),
        BbFactoryCollectionError::RecordCount {
            expected: 1,
            got: 2
        }
    );
    assert_eq!(
        BbFactoryCollection::decode(&[0x50, 0x51], &[(0x50, raw.as_slice()); 2]).unwrap_err(),
        BbFactoryCollectionError::DuplicateRecord { address: 0x50 }
    );
    for address in [0x4f, 0x52, 0x54] {
        assert_eq!(
            BbFactoryCollection::decode(
                &[0x50, 0x51],
                &[(0x50, raw.as_slice()), (address, raw.as_slice())]
            )
            .unwrap_err(),
            BbFactoryCollectionError::UnexpectedAddress { address }
        );
    }
}

#[test]
fn selected_collection_never_skips_bad_pages_or_accepts_mixed_exact_skus() {
    let good = page("held_42601");
    let other = page("held_42641");
    assert_eq!(
        BbFactoryCollection::decode(
            &[0x50, 0x51],
            &[(0x51, other.as_slice()), (0x50, good.as_slice())]
        )
        .unwrap_err(),
        BbFactoryCollectionError::MixedSku {
            first: BbFactorySku::Bhb42601,
            other: BbFactorySku::Bhb42641
        }
    );
    for selected in [[0x50, 0x51], [0x51, 0x50]] {
        for name in [
            "identity_crc_mismatch",
            "parameters_crc_mismatch",
            "held_plus120",
            "unsupported_42621",
        ] {
            let bad = page(name);
            let source = BbFactoryPage::decode(0x51, &bad).unwrap_err();
            assert_eq!(
                BbFactoryCollection::decode(
                    &selected,
                    &[(0x50, good.as_slice()), (0x51, bad.as_slice())]
                )
                .unwrap_err(),
                BbFactoryCollectionError::Page {
                    address: 0x51,
                    source
                }
            );
        }
        for length in [0, 32, 128, 255] {
            assert_eq!(
                BbFactoryCollection::decode(
                    &selected,
                    &[(0x50, good.as_slice()), (0x51, &good[..length])]
                )
                .unwrap_err(),
                BbFactoryCollectionError::Page {
                    address: 0x51,
                    source: BbFactoryPageError::Decode(DeployedEepromError::WrongLength {
                        got: length
                    })
                }
            );
        }
    }
}
