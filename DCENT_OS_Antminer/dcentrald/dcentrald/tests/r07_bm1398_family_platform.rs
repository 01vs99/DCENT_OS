// SPDX-License-Identifier: GPL-3.0-or-later
//! R07 BM1398 native family platform-profile replay (desk-only, no hardware).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R07 (owner
//! runtime_bm1398). Extends the wired NBP1901 (S19 Pro) lane with the
//! NBS1902 (S19 classic) and NBT1903 (T19) platform profiles:
//!
//! - exact identity join accept/refuse matrices (board target x dispatch
//!   identity x stock board name);
//! - per-platform geometry admission (right population passes, off-by-one
//!   refuses, cross-bin windows refuse);
//! - per-platform stock ladder bounds (only each bin's own held levels.json
//!   rows admit; the wired NBP1901 resolution is behavior-preserved);
//! - cross-platform leak refusals (an am2-s19pro admission never resolves an
//!   NBS/T19 profile and vice versa; the NBP-only EEPROM wrapper refuses the
//!   76-chip bins' names; the captured NBP1901 EEPROM generation alone never
//!   selects a bin).
//!
//! Every constant is cited in
//!
//! to the held first-party stock images (`s19-pro-20211116`,
//! `s19-20211116`, `t19-20230320` topol.conf + levels.json) and the
//! bench-20260902-nbp1901 EEPROM capture. The F04 Bitcoin oracle is NOT
//! needed here; the work/nonce replay lives in
//! `r07_bm1398_family_runtime_replay.rs`.
//!
//! This test grants no hardware, energization, dispatch, install, or
//! registration authority: the Lane-F energize intercept, the exact-admission
//! handoff and the EEPROM 0x50-0x57 write denylist are untouched.

#![forbid(unsafe_code)]

#[path = "../src/s19_bm1398_platform.rs"]
mod platform;

use dcentrald_api_types::bm1398_get_address::{
    locked_bm1398_unassigned_get_address_body, parse_bm1398_get_address_body,
};
use dcentrald_api_types::bm1398_protocol::{
    S19_NBS1902_BOARD_GEOMETRY, S19_PRO_NBP1901_BOARD_GEOMETRY, T19_NBT1903_BOARD_GEOMETRY,
};
use dcentrald_api_types::hashboard_eeprom::{
    decode_nbp1901_factory_page, observed_protocol_from_bm1398_factory_page,
    observed_protocol_from_nbp1901_factory_page, BM1398_NATIVE_STOCK_BOARD_NAMES,
};
use dcentrald_common::AsicProtocolIdentity;
use platform::Bm1398Platform;

/// Actual Sep 2 captured ciphertext (bench-20260902-nbp1901, sha256-pinned),
/// already independently pinned in `zhiju_eeprom.rs` / `hashboard_eeprom.rs`.
const NBP_PAGE_BOARDS_1_2_HEX: &str = "11422213c85248cf1657052522c82540d466dda751d68d4d5cfe15d56138b98f8cd7565a7b393d3894ec7f42e1beeef92aeb6b75955ed63d80be85f6a8131757ade4";
const NBP_PAGE_BOARD_3_HEX: &str = "1142fe6b91b8ec624ae7e16b905fa3281759f33497fec9efd0c14460646f9c88b2a0fafeeb1ec7fa7b470e52b5636dbe928f3bab3eb86b048dd0e4aa985e62215d91";

fn nbp_page(page_hex: &str) -> Vec<u8> {
    let mut raw = vec![0xff; 256];
    for (i, pair) in page_hex.as_bytes().chunks_exact(2).enumerate() {
        raw[i] = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    raw[255] = 0x5a;
    raw
}

fn chip_observation() -> dcentrald_api_types::bm1398_get_address::Bm1398GetAddressObservation {
    parse_bm1398_get_address_body(&locked_bm1398_unassigned_get_address_body()).unwrap()
}

/// Identity join accept matrix: exactly the three registered board targets
/// with exactly the BM1398 dispatch identity resolve to distinct profiles.
#[test]
fn identity_join_admits_exactly_the_three_family_targets() {
    assert_eq!(
        Bm1398Platform::from_admission("am2-s19pro", AsicProtocolIdentity::Bm1398),
        Ok(Bm1398Platform::S19Pro)
    );
    assert_eq!(
        Bm1398Platform::from_admission("am2-s19", AsicProtocolIdentity::Bm1398),
        Ok(Bm1398Platform::S19Classic)
    );
    assert_eq!(
        Bm1398Platform::from_admission("am2-t19", AsicProtocolIdentity::Bm1398),
        Ok(Bm1398Platform::T19)
    );
    // Targets are distinct: no aliasing, no prefix matching.
    assert_ne!(
        Bm1398Platform::from_admission("am2-s19", AsicProtocolIdentity::Bm1398),
        Bm1398Platform::from_admission("am2-s19pro", AsicProtocolIdentity::Bm1398)
    );
    assert_ne!(
        Bm1398Platform::from_admission("am2-t19", AsicProtocolIdentity::Bm1398),
        Bm1398Platform::from_admission("am2-s19", AsicProtocolIdentity::Bm1398)
    );
}

/// Identity join refuse matrix: every sibling carrier target, every wrong
/// dispatch identity, and non-target strings refuse.
#[test]
fn identity_join_refuses_wrong_targets_and_identities() {
    for wrong_target in [
        // BM1362 carriers, other families, malformations.
        "am2-s19j",
        "am2-s19jpro",
        "am2-s19jpro-zynq",
        "am3-s19k",
        "am3-s19xp",
        "am2-t17e",
        "am2-s19pro-x",
        "am2-s1",
        "AM2-S19",
        "am2-t19 ",
        "",
    ] {
        assert!(
            Bm1398Platform::from_admission(wrong_target, AsicProtocolIdentity::Bm1398).is_err(),
            "{wrong_target:?} must never resolve a family profile"
        );
    }
    for wrong_identity in [
        AsicProtocolIdentity::Bm1362,
        AsicProtocolIdentity::Bm1366,
        AsicProtocolIdentity::Bm1368,
        AsicProtocolIdentity::Bm1370,
        AsicProtocolIdentity::Bm1393,
        AsicProtocolIdentity::Bm1397,
        AsicProtocolIdentity::RuntimeDiscovered,
    ] {
        for target in ["am2-s19pro", "am2-s19", "am2-t19"] {
            assert!(
                Bm1398Platform::from_admission(target, wrong_identity).is_err(),
                "{target} with identity {wrong_identity:?} must refuse"
            );
        }
    }
}

/// Geometry admission: each bin's plan certifies EXACTLY its own stock
/// population at its own address interval; off-by-one and cross-bin windows
/// refuse. Counts are the stock topol.conf `chain_asic_num` rows.
#[test]
fn geometry_admission_is_exact_per_bin_and_refuses_off_by_one_and_cross_bin() {
    for (platform, chips, interval, geometry) in [
        (
            Bm1398Platform::S19Pro,
            114_u16,
            2_u8,
            S19_PRO_NBP1901_BOARD_GEOMETRY,
        ),
        (
            Bm1398Platform::S19Classic,
            76,
            3,
            S19_NBS1902_BOARD_GEOMETRY,
        ),
        (Bm1398Platform::T19, 76, 3, T19_NBT1903_BOARD_GEOMETRY),
    ] {
        assert_eq!(platform.geometry(), geometry, "{platform} geometry row");
        assert_eq!(platform.chips_per_chain(), chips);
        assert_eq!(platform.address_interval(), interval);
        let plan = platform.desk_plan(
            dcentrald_common::serial_chain_proof::PacedEnumerationPolicy::new(
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(1),
                std::time::Duration::from_millis(10),
                2,
            )
            .unwrap(),
            dcentrald_common::s19_bm1398_runtime::Bm1398FpgaMidstateMode::Four,
        );
        let expected = plan.expected_addresses();
        assert_eq!(expected.len(), usize::from(chips));
        assert_eq!(
            expected,
            (0..chips as u8)
                .map(|i| i.wrapping_mul(interval))
                .collect::<Vec<_>>()
        );
        // Right count passes.
        assert!(plan.certify_chain(&expected).is_ok());
        // Off-by-one (short) refuses.
        assert!(plan.certify_chain(&expected[..expected.len() - 1]).is_err());
        // Off-by-one (long: duplicate last address) refuses.
        let mut long = expected.clone();
        long.push(*expected.last().unwrap());
        assert!(plan.certify_chain(&long).is_err());
        // Cross-bin windows refuse ONLY where the address layouts actually
        // differ: 114/2 (NBP1901) vs 76/3. NBS1902 and NBT1903 share ONE
        // address plan by held stock evidence (first-party topol.conf rows:
        // both 76 chips, interval 3 — typed as the shared
        // `BM1398_76CHIP_INTERVAL3_ADDRESS_PLAN` in
        // `dcentrald-api-types/src/bm1398_protocol.rs`, "One const so both
        // bins provably use the same plan"), so the sibling 76/3 window MUST
        // certify on both — those bins are separated by the declared image
        // identity + stock board name join, never by the population window.
        // Round-1 repair: the former blanket "every sibling window refuses"
        // assertion mislabeled this shared-plan agreement as a leak.
        for (other_platform, other_chips, other_interval) in [
            (Bm1398Platform::S19Pro, 114_u16, 2_u8),
            (Bm1398Platform::S19Classic, 76, 3),
            (Bm1398Platform::T19, 76, 3),
        ] {
            let other: Vec<u8> = (0..other_chips as u8)
                .map(|i| i.wrapping_mul(other_interval))
                .collect();
            if other_chips == chips {
                assert!(
                    plan.certify_chain(&other).is_ok(),
                    "{platform} must certify the shared {other_chips}/{other_interval} layout"
                );
            } else {
                assert!(
                    plan.certify_chain(&other).is_err(),
                    "{platform} must not certify a {other_chips}/{other_interval} window"
                );
            }
        }
    }
}

/// Ladder bounds: NBP1901 keeps the WIRED clamp semantics byte-exact
/// (behavior-preserving); the 76-chip bins are exact-rung only (round-1
/// repair — no clamp band is invented for them, so a wrong-bin frequency
/// such as 675 on T19 is a refusal, never a silent substitution), and
/// cross-bin rows refuse everywhere.
#[test]
fn ladder_bounds_are_per_bin_and_nbp1901_resolution_is_preserved() {
    let pro = Bm1398Platform::S19Pro;
    // Exact historical behavior of the wired NBP1901 run().
    assert_eq!(pro.resolve_operating_point(0, 0).unwrap(), (500, 1280));
    assert_eq!(pro.resolve_operating_point(500, 0).unwrap(), (500, 1280));
    assert_eq!(pro.resolve_operating_point(524, 0).unwrap(), (500, 1280));
    assert_eq!(pro.resolve_operating_point(525, 0).unwrap(), (525, 1280));
    assert_eq!(
        pro.resolve_operating_point(525, 12600).unwrap(),
        (525, 1260)
    );
    assert_eq!(
        pro.resolve_operating_point(525, 12800).unwrap(),
        (525, 1280)
    );
    assert_eq!(
        pro.resolve_operating_point(525, 13000).unwrap(),
        (525, 1300)
    );
    for (f, mv) in [(499, 0), (0, 12601), (0, 13700), (525, 13800)] {
        assert!(pro.resolve_operating_point(f, mv).is_err(), "({f},{mv})");
    }
    let s19 = Bm1398Platform::S19Classic;
    assert_eq!(s19.resolve_operating_point(0, 0).unwrap(), (650, 1380));
    assert_eq!(
        s19.resolve_operating_point(675, 13800).unwrap(),
        (675, 1380)
    );
    assert_eq!(
        s19.resolve_operating_point(650, 14200).unwrap(),
        (650, 1420)
    );
    // Exact-rung only: between-rung and wrong-bin frequencies refuse.
    for (f, mv) in [
        (649, 0),
        (674, 0),
        (525, 0),
        (0, 12800),
        (650, 14400),
        (650, 14001),
        (625, 14400),
    ] {
        assert!(s19.resolve_operating_point(f, mv).is_err(), "({f},{mv})");
    }
    let t19 = Bm1398Platform::T19;
    assert_eq!(t19.resolve_operating_point(0, 0).unwrap(), (550, 1420));
    assert_eq!(
        t19.resolve_operating_point(625, 14400).unwrap(),
        (625, 1440)
    );
    assert_eq!(
        t19.resolve_operating_point(550, 14200).unwrap(),
        (550, 1420)
    );
    // (550, 1400) is not a held T19 row: the T19 ladder is not a cross product.
    assert!(t19.resolve_operating_point(550, 14000).is_err());
    // Exact-rung only: 675 is NBS1902's rung and MUST refuse on T19
    // (round-1 failure 1); 574/626 sit between rungs and refuse too.
    assert!(t19.resolve_operating_point(675, 0).is_err());
    assert!(t19.resolve_operating_point(675, 13800).is_err());
    assert!(t19.resolve_operating_point(650, 13800).is_err());
    assert!(t19.resolve_operating_point(549, 0).is_err());
    assert!(t19.resolve_operating_point(574, 0).is_err());
    assert!(t19.resolve_operating_point(626, 0).is_err());
    assert!(t19.resolve_operating_point(525, 12800).is_err());
}

/// Held legacy pages retain their decoded serials, but carry no exact SKU.
/// A caller-supplied family name and BM1398 chip reply cannot invent one.
/// Named-page positives are covered by the five-profile production-owner tests.
#[test]
fn eeprom_join_leak_matrix_matches_the_held_generation() {
    let pages = [
        nbp_page(NBP_PAGE_BOARDS_1_2_HEX),
        nbp_page(NBP_PAGE_BOARD_3_HEX),
    ];
    let observation = chip_observation();
    for raw in &pages {
        // Decoded identity is the Braiins boot-table oracle serials.
        let decoded = decode_nbp1901_factory_page(raw).unwrap();
        assert!(decoded.hashboard_sn.len() == 17);
        // Every exact profile refuses this unnamed generation, including NBP.
        for name in BM1398_NATIVE_STOCK_BOARD_NAMES {
            assert_eq!(
                observed_protocol_from_bm1398_factory_page(raw, name, Some(observation)),
                None,
                "{name} must not acquire an identity absent from the held page"
            );
        }
        // Platform stock names agree with the family table.
        for platform in Bm1398Platform::ALL {
            for name in platform.stock_board_names() {
                assert!(BM1398_NATIVE_STOCK_BOARD_NAMES.contains(name));
            }
        }
        // Non-family names refuse.
        for name in ["BHB42601", "BHB42xxx", "NBS1903", "NBT1902", "", "nbp1901"] {
            assert_eq!(
                observed_protocol_from_bm1398_factory_page(raw, name, Some(observation)),
                None,
                "{name:?} must never join"
            );
        }
        // Without the sealed 0x1398 chip observation nothing joins.
        assert_eq!(
            observed_protocol_from_bm1398_factory_page(raw, "NBP1901", None),
            None
        );
        assert_eq!(
            observed_protocol_from_bm1398_factory_page(raw, "NBS1902", None),
            None
        );
        // The NBP-only wrapper refuses the 76-chip bins' names (and vice
        // versa the family join alone never implies the NBP wrapper).
        assert_eq!(
            observed_protocol_from_nbp1901_factory_page(raw, "NBS1902", Some(observation)),
            None
        );
        assert_eq!(
            observed_protocol_from_nbp1901_factory_page(raw, "NBT1903", Some(observation)),
            None
        );
        assert_eq!(
            observed_protocol_from_nbp1901_factory_page(raw, "NBP1901", Some(observation)),
            None
        );
    }
    // A page of the deployed BHB42 generation (header byte 0x04) fails the
    // captured-generation decode and therefore joins nothing.
    let mut bhb42 = vec![0xff; 256];
    bhb42[0] = 0x04;
    bhb42[1] = 0x11;
    bhb42[255] = 0x5a;
    assert!(decode_nbp1901_factory_page(&bhb42).is_err());
    for name in BM1398_NATIVE_STOCK_BOARD_NAMES {
        assert_eq!(
            observed_protocol_from_bm1398_factory_page(&bhb42, name, Some(observation)),
            None
        );
    }
}
