//! Pure source-data refusal checks only; these never construct an owner policy.
use super::*;

fn page(name: &str) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald-api-types/src/bb_factory_profile_vectors.json"
    )))
    .unwrap();
    let hex = value["fixtures"][name]["raw"].as_str().unwrap();
    (0..256)
        .map(|index| u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap())
        .collect()
}

#[test]
fn exact_native_data_uses_decoded_source_mapping_not_raw96_or_pic94() {
    for name in ["held_42601", "held_42641"] {
        let raw = page(name);
        assert_eq!(raw[0x96], 0xff, "independent held encrypted/raw-page fact");
        let collection = BbFactoryCollection::decode(&[0x52], &[(0x52, &raw)]).unwrap();
        let result = source_records(&collection, &[0x52]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].original_model_96, 1);
        assert_eq!(
            result[0].required,
            RequiredExchange::RequiredFourBridgeSweep
        );
        assert_eq!(result[0].factory_address, 0x52);
        assert_eq!(collection.pages()[0].raw_page().as_slice(), raw);
    }
}

#[test]
fn real_decoded_collection_rejects_different_order_count_membership_and_fourth_endpoint() {
    let raw = page("held_42601");
    let collection =
        BbFactoryCollection::decode(&[0x52, 0x50], &[(0x50, &raw), (0x52, &raw)]).unwrap();
    assert!(source_records(&collection, &[0x52, 0x50]).is_ok());
    for selected in [
        vec![],
        vec![0x52],
        vec![0x50, 0x52],
        vec![0x52, 0x51],
        vec![0x52, 0x52],
        vec![0x52, 0x50, 0x51],
        vec![0x53, 0x50],
    ] {
        assert!(source_records(&collection, &selected).is_err());
    }
    let diagnostic_fourth = BbFactoryCollection::decode(&[0x53], &[(0x53, &raw)]).unwrap();
    assert!(source_records(&diagnostic_fourth, &[0x53]).is_err());
    // The pure decoder accepts an explicitly labelled diagnostic fourth slot;
    // no such data can obtain the native selected-source requirement here.
}
