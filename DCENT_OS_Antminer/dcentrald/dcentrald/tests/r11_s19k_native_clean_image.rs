// SPDX-License-Identifier: GPL-3.0-or-later
//! R11 S19k native clean-image acceptance replay (desk-only, no hardware).
//!
//! Campaign `2026-09-07-antminer-beta-execution`, lane R11 (`agent_tasks.json`
//! R11, P0, "Finish S19k native clean-image operation"). Acceptance clause:
//! "a clean DCENT rootfs reaches the native executor without bos_* or raw I2C
//! tools; all selected routes credited; failed identity/cooling/reset/baud
//! retains cutoff behavior."
//!
//! This file desk-represents every acceptance clause against the EXISTING
//! executor surfaces without rewriting any of them:
//!
//! - discovery: the native path derives identity from DCENT-owned evidence
//!   only (`s19k_native_discovery::detect_dcent_owned_profile` in the HAL +
//!   the retained, generation-bound bus-1 EEPROM service identity capture);
//!   the Braiins-file/`i2cget`/runner-receipt discovery stays separately
//!   preserved on the inherited Track-1 path and is asserted untouched;
//! - the one-to-three-route native executor is exercised through its real
//!   public policy SSOTs in `dcentrald-common` (`s19k_bm1366_init_seq`,
//!   `s19k_bm1366_uart_rx`, `s19k_bm1366_wire_b`) — the same functions the
//!   daemon executor calls — for every non-empty route population, using
//!   synthesized CRC-valid BM1366 GetAddress responses (clearly desk
//!   fixtures, NOT recorded wire captures and NOT physical hashing);
//! - cutoff behavior is pinned by source-contract anchors (same
//!   `include_str!` tradition as the in-module tests) plus the public
//!   post-baud/rollback and cut-hash-before-noise policy functions.
//!
//! Every constant is cited in
//! .
//! Passing grants no hardware, energization, install, dispatch, or
//! registration authority; native S19k work TX remains EXPERIMENTAL and the
//! live-bench remainder (physical identity/cooling/reset/baud evidence on a
//! unit) is explicitly out of scope for this desk lane.

#![forbid(unsafe_code)]

use dcentrald_api_types::deployed_eeprom::decode_deployed_eeprom;
use dcentrald_api_types::hashboard_eeprom::observed_protocol_from_deployed_page;
use dcentrald_api_types::zhiju_eeprom::Crc5Check;
use dcentrald_common::bm1366_serial_platform::bm1366_dispatch_admitted_serial_platform;
use dcentrald_common::s19k_am3_gpio437::{
    s19k_nopic_panic_fan_action, S19kNoPicPanicFanAction,
};
use dcentrald_common::s19k_bm1366_init_seq::{
    admit_s19k_bosminer_stock_fastuart_with_host_baud,
    admit_s19k_native_work_tx_after_post_baud, admit_s19k_production_native_transport_requires_joined_owner,
    classify_s19k_post_baud_observation, refuse_chip_heard_at_115200_as_3m_work_proof,
    refuse_native_post_baud_pass_as_production, s19k_bm1366_native_execution_program,
    s19k_post_baud_failure_is_rollback_not_work_tx, S19kBm1366NativeCommandOp, S19kInitDialect,
    S19kPostBaudObservation, S19kPostBaudWorkTxDisposition, BOSMINER_BM1366_AML_HOST_BAUD,
    S19K_78_DMESG_HOLD_BAUD,
};
use dcentrald_common::s19k_bm1366_uart_rx::{
    admit_bm1366_enum_response_bodies, command_response_crc5, S19kRxDiag,
};
use dcentrald_common::s19k_bm1366_wire_b::{s19k_aml_linear_addresses, S19K_AML_ADDR_INTERVAL};
use dcentrald_common::s19k_bosminer_enum::S19K_BHB56902_CHIP_COUNT;
use dcentrald_common::AsicProtocolIdentity;
use dcentrald_hal::platform::amlogic::{
    S19K_NATIVE_LOGICAL_CHAIN_ROUTES, S19kNativeLogicalChainRoute,
};

const DAEMON_SOURCE: &str = include_str!("../src/serial_mining.rs");
const HAL_AMLOGIC_SOURCE: &str = include_str!("../../dcentrald-hal/src/platform/amlogic/mod.rs");

fn repo_file(relative_from_repo_root: &str) -> std::path::PathBuf {
    // The test crate root is DCENT_OS_Antminer/dcentrald/dcentrald.
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(relative_from_repo_root)
}

fn daemon_region(start_anchor: &str, end_anchor: &str) -> String {
    let start = DAEMON_SOURCE
        .find(start_anchor)
        .unwrap_or_else(|| panic!("serial_mining.rs lost anchor {start_anchor:?}"));
    let end = DAEMON_SOURCE[start..]
        .find(end_anchor)
        .map(|offset| start + offset)
        .unwrap_or_else(|| panic!("serial_mining.rs lost end anchor {end_anchor:?}"));
    DAEMON_SOURCE[start..end].to_string()
}

fn hal_aggregate_admission_region() -> String {
    let start = HAL_AMLOGIC_SOURCE
        .find("impl S19kNativeAggregateAdmission")
        .expect("HAL lost the aggregate S19k admission implementation");
    let end = HAL_AMLOGIC_SOURCE[start..]
        .find("impl S19kNativePopulationAdmission")
        .map(|offset| start + offset)
        .expect("HAL lost the population S19k admission implementation");
    HAL_AMLOGIC_SOURCE[start..end].to_string()
}

/// One synthesized desk fixture: a CRC-valid BM1366 GetAddress ChipAddress
/// response for `address` (stride `S19K_AML_ADDR_INTERVAL`), in the exact
/// 11-byte `AA 55 …` response-frame shape with the 9-byte body that
/// [`admit_bm1366_enum_response_bodies`] consumes. This is a construction,
/// not a captured frame and not ASIC evidence.
fn chip_address_body(address: u8) -> Vec<u8> {
    let mut frame = [0u8; 11];
    frame[0] = 0xAA;
    frame[1] = 0x55;
    frame[2] = 0x13; // chip_id 0x1366 high byte
    frame[3] = 0x66; // chip_id 0x1366 low byte
    frame[5] = address; // value_address
    frame[6] = address; // responder_address
    frame[7] = 0x00; // register_address 0 → GetAddress-shaped
    frame[10] = command_response_crc5(&frame[2..10]);
    frame[2..].to_vec()
}

fn full_77_chip_route_bodies() -> Vec<Vec<u8>> {
    s19k_aml_linear_addresses()
        .into_iter()
        .map(chip_address_body)
        .collect()
}

// ---------------------------------------------------------------------------
// Clause 1: clean DCENT rootfs reaches the native executor without bos_* or
// raw I2C tools.
// ---------------------------------------------------------------------------

#[test]
fn native_s19k_discovery_is_dcent_owned_without_bos_files_i2c_tools_or_runner_hashes() {
    // The daemon's native admission block, from the aggregate identity/UART/
    // plug admission through the service-owned EEPROM identity capture.
    let native = daemon_region(
        "S19kNativeAggregateAdmission::detect()",
        "native S19k service-owned EEPROM identity refused",
    );
    assert!(
        native.contains("s19k_native_identity::capture(&mapped, &service)"),
        "native identity must be captured through the retained EEPROM service"
    );
    for forbidden in [
        "i2cget",
        "i2cdetect",
        "bos_platform",
        "bos_mode",
        "bosminer_model",
        "bosminer.toml",
        "DCENT_S19K_LIVE_IDENTITY_SHA256",
        "runner_sha256",
        "s19k_capture_and_require_bound_live_identity",
    ] {
        assert!(
            !native.contains(forbidden),
            "native S19k discovery/identity region must not reference {forbidden}"
        );
    }

    // The HAL aggregate admission discovers through the DCENT-owned marker
    // module, never through the shared multi-source detector whose fallback
    // chain contains the Braiins overlay file.
    let aggregate = hal_aggregate_admission_region();
    assert!(aggregate.contains("s19k_native_discovery::detect_dcent_owned_profile()"));
    assert!(!aggregate.contains("detect_amlogic_nopic_profile"));
    assert!(!aggregate.contains("bosminer"));
    assert!(!aggregate.contains("i2cget"));
    assert!(!aggregate.contains("i2cdetect"));

    // The dispatch-admitted BM1366 platform join the native cold-start owner
    // consumes still binds exactly am3-s19k + BM1366.
    let profile = bm1366_dispatch_admitted_serial_platform("am3-s19k")
        .expect("am3-s19k must remain the dispatch-admitted native BM1366 platform");
    assert_eq!(profile.board_target, "am3-s19k");
    assert!(bm1366_dispatch_admitted_serial_platform("am3-s21").is_err());
}

#[test]
fn track1_inherited_braiins_i2cget_runner_discovery_is_preserved_separately_untouched() {
    // The inherited discovery keeps its Braiins file + i2cget + runner-bound
    // receipt evidence on the Track-1 path only. This is the "preserve the
    // inherited Track-1 path separately and untouched" clause: the helper
    // must still exist, byte-for-byte in shape, and native mode must not
    // call it (checked in the native-region test above).
    let capture = daemon_region(
        "fn s19k_i2cget_byte(",
        "fn s19k_capture_and_require_bound_live_identity",
    );
    for required in [
        "/usr/sbin/i2cget",
        "/etc/bos_platform",
        "/etc/bos_mode",
        "/etc/bosminer_model.json",
    ] {
        assert!(
            capture.contains(required),
            "Track-1 inherited discovery lost {required}"
        );
    }
    let bound = daemon_region(
        "fn s19k_capture_and_require_bound_live_identity",
        "fn s19k_ephemeral_trial_parent",
    );
    assert!(
        bound.contains("S19K_LIVE_IDENTITY_ENV"),
        "Track-1 runner-bound live identity digest requirement disappeared"
    );
    // Track-1 remains gated behind the Braiins handoff, not native ownership.
    let track1_gate = daemon_region(
        "if braiins_bm1366_passthrough_handoff {",
        "let admitted_live_identity = match s19k_capture_and_require_bound_live_identity()",
    );
    assert!(track1_gate.contains("S19k Track-1 lost its exact supervisor+bosminer handoff identity"));
}

#[test]
fn clean_rootfs_ships_no_raw_i2c_tools_and_writes_no_bos_identity_files() {
    // Buildroot policy: i2c-tools stay disabled repo-wide (the shared
    // fragment refuses re-enabling), and the am3-s19k defconfigs inherit
    // that policy.
    let fragment = std::fs::read_to_string(repo_file("br2_external_dcentos/configs/dcentos-common.fragment"))
        .expect("shared buildroot fragment");
    assert!(fragment.contains("# BR2_PACKAGE_I2C_TOOLS is not set"));
    assert!(!fragment.contains("BR2_PACKAGE_I2C_TOOLS=y"));
    for defconfig in [
        "br2_external_dcentos/configs/dcentos_am3_s19kpro_defconfig",
        "br2_external_dcentos/configs/dcentos_am3_s19kpro_nopic_defconfig",
        "br2_external_dcentos/configs/dcentos_am3_aml_common.fragment",
    ] {
        let text = std::fs::read_to_string(repo_file(defconfig))
            .unwrap_or_else(|error| panic!("{defconfig}: {error}"));
        assert!(
            !text.contains("BR2_PACKAGE_I2C_TOOLS=y"),
            "{defconfig} must not re-enable i2c-tools"
        );
    }
    // The S19k Pro board overlay writes DCENT-owned identity/marker state,
    // never Braiins bos_* identity files or raw I2C tool calls.
    for overlay in [
        "br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/init.d/S38s19k-data",
        "br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/init.d/S49s19k-postinstall-witness",
        "br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/usr/sbin/dcent-s19k-data-mount",
        "br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/usr/sbin/dcent-s19k-postinstall-witness.py",
    ] {
        let text = std::fs::read_to_string(repo_file(overlay))
            .unwrap_or_else(|error| panic!("{overlay}: {error}"));
        for forbidden in ["i2cget", "i2cdetect", "bos_platform", "bos_mode", "bosminer_model"] {
            assert!(
                !text.contains(forbidden),
                "{overlay} must not reference {forbidden}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Clause 2: all selected routes credited — the existing one-to-three-route
// executor exercised for every non-empty population.
// ---------------------------------------------------------------------------

#[test]
fn every_nonempty_population_selects_exactly_its_routes_in_logical_chain_order() {
    // Immutable controller-facing route table (held stock/VNish recovered).
    assert_eq!(
        S19K_NATIVE_LOGICAL_CHAIN_ROUTES.map(|route| (
            route.logical_chain,
            route.logical_board_address,
            route.uart,
            route.plug_gpio,
            route.reset_gpio
        )),
        [
            (0, 1, "/dev/ttyS3", 439, 454),
            (1, 2, "/dev/ttyS2", 440, 455),
            (2, 3, "/dev/ttyS1", 441, 456),
        ]
    );
    // The executor admits only ordered subsets of this exact table with
    // matching backend cardinality. Replay that law for every population.
    for mask in 1u8..8u8 {
        let populated = [mask & 1 != 0, mask & 2 != 0, mask & 4 != 0];
        let selected: Vec<S19kNativeLogicalChainRoute> = S19K_NATIVE_LOGICAL_CHAIN_ROUTES
            .iter()
            .copied()
            .filter(|route| populated[route.logical_chain as usize])
            .collect();
        assert_eq!(selected.len(), mask.count_ones() as usize);
        assert!(selected.windows(2).all(|pair| pair[0].logical_chain < pair[1].logical_chain));
        assert!(selected.iter().all(|route| {
            S19K_NATIVE_LOGICAL_CHAIN_ROUTES.get(route.logical_chain as usize) == Some(route)
        }));
        // One UART backend per selected route, in the same order.
        let uarts: Vec<&str> = selected.iter().map(|route| route.uart).collect();
        assert_eq!(uarts.len(), selected.len());
        assert!(uarts.iter().all(|uart| S19K_NATIVE_LOGICAL_CHAIN_ROUTES
            .iter()
            .any(|route| route.uart == *uart)));
    }
}

#[test]
fn every_selected_route_enumerates_the_full_77_chip_population_before_work_tx() {
    let bodies = full_77_chip_route_bodies();
    assert_eq!(bodies.len(), S19K_BHB56902_CHIP_COUNT as usize);
    // Each route independently reaches complete CRC-valid coverage through
    // the real admission the executor drives post-baud.
    for mask in 1u8..8u8 {
        for chain in 0..3u8 {
            if mask & (1 << chain) == 0 {
                continue;
            }
            let coverage = admit_bm1366_enum_response_bodies(
                &bodies,
                S19K_BHB56902_CHIP_COUNT as u8,
                S19K_AML_ADDR_INTERVAL,
                usize::from(S19K_BHB56902_CHIP_COUNT as u8),
            )
            .unwrap_or_else(|reason| panic!("route {chain} full population refused: {reason}"));
            assert_eq!(coverage.addresses.len(), usize::from(S19K_BHB56902_CHIP_COUNT as u8));
            assert_eq!(coverage.duplicate_frames, 0);
            assert!(coverage
                .addresses
                .iter()
                .enumerate()
                .all(|(index, address)| *address == (index as u8) * S19K_AML_ADDR_INTERVAL));
        }
    }
    // Short, contaminated, and off-geometry populations refuse: a route is
    // credited only with its full fresh CRC-valid geometry.
    assert!(admit_bm1366_enum_response_bodies(&bodies[..76], 77, S19K_AML_ADDR_INTERVAL, 77).is_err());
    assert!(
        admit_bm1366_enum_response_bodies(&bodies, 77, S19K_AML_ADDR_INTERVAL + 1, 77).is_err(),
        "wrong address stride must refuse"
    );
    let mut corrupt = bodies[10].clone();
    corrupt[1] ^= 0x40;
    let mut with_corrupt = bodies.clone();
    with_corrupt[10] = corrupt;
    assert!(
        admit_bm1366_enum_response_bodies(&with_corrupt, 77, S19K_AML_ADDR_INTERVAL, 77).is_err(),
        "a CRC-corrupt body must contaminate the window"
    );
    let mut wrong_chip = vec![0u8; 9];
    wrong_chip[0] = 0x13;
    wrong_chip[1] = 0x68; // BM1368 chip id from an S21 board is not BM1366
    let mut frames = full_77_chip_route_bodies();
    frames[0] = wrong_chip;
    assert!(
        admit_bm1366_enum_response_bodies(&frames, 77, S19K_AML_ADDR_INTERVAL, 77).is_err(),
        "a non-0x1366 ChipAddress must refuse"
    );
}

#[test]
fn native_post_baud_chain_credits_work_tx_only_after_fresh_switched_baud_response() {
    // Baud law: the stock S19k pairing is host B3000000 with chip 0x28 =
    // 0x00003011; the checked baseline is 115200. Everything else refuses.
    assert!(admit_s19k_bosminer_stock_fastuart_with_host_baud(BOSMINER_BM1366_AML_HOST_BAUD).is_ok());
    assert!(admit_s19k_bosminer_stock_fastuart_with_host_baud(S19K_78_DMESG_HOLD_BAUD).is_err());
    assert!(admit_s19k_bosminer_stock_fastuart_with_host_baud(3_125_000).is_err());

    // Fresh switched-baud response admitted → native work TX may start on
    // every selected route (still experimental, still not production).
    let observation =
        classify_s19k_post_baud_observation(S19kInitDialect::NativeExperimental, true, true)
            .expect("fresh switched-baud response classifies");
    assert_eq!(observation, S19kPostBaudObservation::FreshSwitchedBaudResponseAdmitted);
    admit_s19k_native_work_tx_after_post_baud(S19kInitDialect::NativeExperimental, observation)
        .expect("all selected routes are credited after the fresh response");

    // No fresh response, no baud switch, or a passthrough label: fail-closed
    // rollback BEFORE work TX on every arm.
    for (changed, fresh) in [(true, false), (false, false), (false, true)] {
        let observation =
            classify_s19k_post_baud_observation(S19kInitDialect::NativeExperimental, changed, fresh)
                .expect("classification itself cannot fail on the native dialect");
        assert_ne!(observation, S19kPostBaudObservation::FreshSwitchedBaudResponseAdmitted);
        let disposition = match observation {
            S19kPostBaudObservation::FreshSwitchedBaudResponseAdmitted => {
                S19kPostBaudWorkTxDisposition::NativeWorkTxAllowedAfterFreshResponse
            }
            _ => S19kPostBaudWorkTxDisposition::FailClosedRollbackBeforeWorkTx,
        };
        assert!(s19k_post_baud_failure_is_rollback_not_work_tx(disposition));
        assert!(admit_s19k_native_work_tx_after_post_baud(
            S19kInitDialect::NativeExperimental,
            observation
        )
        .is_err());
    }
    let passthrough = classify_s19k_post_baud_observation(S19kInitDialect::BraiinsPassthrough, false, true)
        .expect("passthrough unchanged-host classifies");
    assert!(admit_s19k_native_work_tx_after_post_baud(S19kInitDialect::BraiinsPassthrough, passthrough)
        .is_err());
    // An admitted native pass is STILL not production mining.
    assert!(refuse_native_post_baud_pass_as_production(
        S19kInitDialect::NativeExperimental,
        S19kPostBaudObservation::FreshSwitchedBaudResponseAdmitted,
    )
    .is_err());
    // A chip heard at 115200 is diagnostic only; never 3M work-TX proof.
    assert!(refuse_chip_heard_at_115200_as_3m_work_proof(S19kRxDiag::ChipHeardAt115200).is_err());
}

#[test]
fn native_typed_program_keeps_the_two_baud_barriers_and_77_chip_geometry() {
    let program = s19k_bm1366_native_execution_program(
        S19K_BHB56902_CHIP_COUNT as u8,
        600,
    )
    .expect("the exact 77-chip native program builds at a stock-class target");
    assert_eq!(program.expected_chip_count, 77);
    assert_eq!(program.address_interval, S19K_AML_ADDR_INTERVAL);
    assert_eq!(program.initial_host_baud, S19K_78_DMESG_HOLD_BAUD);
    assert_eq!(program.fast_host_baud, BOSMINER_BM1366_AML_HOST_BAUD);
    // Pre-baud section: broadcast bring-up + ChainInactive + exactly one
    // SetAddress per chip at the checked stride.
    let set_addresses = program
        .pre_baud_commands
        .iter()
        .filter(|command| matches!(command.op, S19kBm1366NativeCommandOp::SetAddress { .. }))
        .count();
    assert_eq!(set_addresses, 77);
    assert!(program
        .pre_baud_commands
        .iter()
        .any(|command| command.name == "chain_inactive"));
    // The FastUART command is the single section boundary; post-baud per-chip
    // writes follow only after the fresh switched-baud admission.
    assert_eq!(program.fast_uart_command.name, "fastuart_stock_3m125");
    assert_eq!(program.post_baud_commands.len(), 77 * 5);
    assert!(program.final_commands.iter().any(|command| command.name == "pll0_target"));
    assert!(program.final_commands.iter().any(|command| command.name.contains("hash")));
    // Other geometries and the PLL ramp start refuse: S19k's program is not
    // an XP/jXP/BM1368 ladder (R12/R13 own those).
    assert!(s19k_bm1366_native_execution_program(110, 600).is_err());
    assert!(s19k_bm1366_native_execution_program(76, 600).is_err());
    assert!(s19k_bm1366_native_execution_program(77, 50).is_err());
}

#[test]
fn native_work_transport_remains_bound_to_the_joined_cold_start_owner() {
    // The production multi-UART transport still requires the exact joined
    // owner, the default-off request flag, and `native_exact_mapping: true`
    // in the real daemon source; a test-only token issuer refuses.
    admit_s19k_production_native_transport_requires_joined_owner(DAEMON_SOURCE)
        .expect("native S19k transport owner contract drifted");
}

// ---------------------------------------------------------------------------
// Clause 3: failed identity / cooling / reset / baud retains cutoff behavior.
// ---------------------------------------------------------------------------

#[test]
fn failed_identity_refuses_before_any_power_reset_or_uart_mutation() {
    // Held production page decodes to the exact S19k identity triple.
    let held = include_bytes!("../src/serial_mining/fixtures/s19k-bhb56903.bin");
    let identity = decode_deployed_eeprom(held).expect("held BHB56903 page decodes");
    assert_eq!(identity.board_class, 0x05);
    assert_eq!(identity.region_1_crc5, Crc5Check::Match);
    assert_eq!(identity.board_name, "BHB56903");
    assert_eq!(
        observed_protocol_from_deployed_page(held),
        Some(AsicProtocolIdentity::Bm1366)
    );
    // A corrupted page refuses at the CRC check (fresh identity is required;
    // a stale or mutated page is never used for native init).
    let mut corrupt = held.to_vec();
    corrupt[3] ^= 0x01;
    assert!(decode_deployed_eeprom(&corrupt).is_err());
    // The XP-class page shares the 05:11-style preamble family but names a
    // different board; native S19k refuses it (R12 owns XP).
    let xp = include_bytes!("../src/serial_mining/fixtures/epic-bhb56801.bin");
    let xp_identity = decode_deployed_eeprom(xp).expect("held BHB56801 page decodes");
    assert_eq!(xp_identity.board_name, "BHB56801");
    assert!(xp_identity.board_name != "BHB56902" && xp_identity.board_name != "BHB56903");
    // Source-contract: identity capture sits before PSU-enable preparation
    // and before the APW enable call in the native run() order.
    let identity_at = DAEMON_SOURCE
        .find("s19k_native_identity::capture(&mapped, &service)")
        .expect("native identity capture anchor");
    let enable_prep_at = DAEMON_SOURCE
        .find(".prepare_s19k_native_enable(")
        .expect("native enable preparation anchor");
    let enable_at = DAEMON_SOURCE
        .find("psu_enable_operation.enable_psu_at_voltage(voltage)")
        .expect("native APW enable anchor");
    assert!(identity_at < enable_prep_at && enable_prep_at < enable_at);
    let refusal = daemon_region(
        "s19k_native_identity::capture(&mapped, &service)",
        "amlogic_power_thermal = Some(service);",
    );
    assert!(refusal.contains("native S19k service-owned EEPROM identity refused"));
}

#[test]
fn failed_cooling_refuses_and_the_closeout_still_executes_the_checked_cutoff() {
    // The cooling law is exact four-fan tach coverage at the 2,000 RPM
    // floor; the check is not weakened.
    assert!(DAEMON_SOURCE.contains("const S19K_NATIVE_MIN_FAN_RPM: u32 = 2_000;"));
    let cooling = daemon_region(
        "async fn admit_s19k_native_cooling(",
        "struct S19kNativeThermalAdmission",
    );
    assert!(cooling.contains("requires all four fresh tach channels"));
    assert!(cooling.contains("all four tachs at or above"));
    // On failure the closeout runs the first-stage GPIO cutoff and keeps the
    // watchdog armed when any leg fails — cutoff is retained, never skipped.
    let closeout = daemon_region(
        "async fn closeout_native_nopic_failure(",
        "async fn closeout_s19k_track1_failure(",
    );
    assert!(closeout.contains("first-stage safe-off"));
    assert!(closeout
        .contains("GPIO cutoff failed; bounded closeout and terminal checked safe-off continue with the watchdog armed"));
    // Cut-hash-before-noise: after a checked cut the panic action coasts the
    // fans; without a cut and without Track-1 authority nothing blasts.
    assert_eq!(
        s19k_nopic_panic_fan_action(false, true, false),
        S19kNoPicPanicFanAction::CoastAfterCheckedCut
    );
    assert_eq!(
        s19k_nopic_panic_fan_action(false, false, false),
        S19kNoPicPanicFanAction::LeaveUnchanged
    );
}

#[test]
fn resets_are_asserted_before_gpio437_enable_and_again_before_the_terminal_cut() {
    // Cold-start order: watchdog arm → route domains → reset-before-cut
    // custody → all-resets assertion → generation-bound APW enable.
    let cold_start = daemon_region(
        "Exact order: fresh identity/cooling/thermal were captured",
        "native S19k active-low GPIO437/APW enable completed under watchdog custody",
    );
    let resets_at = cold_start
        .find("assert_all_resets_checked()")
        .expect("cold-start reset assertion anchor");
    let enable_mint_at = cold_start
        .find("take_psu_enable_operation()")
        .expect("APW enable mint anchor");
    let enable_at = cold_start
        .find("enable_psu_at_voltage(voltage)")
        .expect("APW enable anchor");
    assert!(resets_at < enable_mint_at && enable_mint_at < enable_at);
    // Custody: enabling arms the reset-before-cut state and the teardown.
    let prepare = daemon_region(
        "fn prepare_s19k_native_enable(",
        "fn admit_s19k_native_terminal_custody",
    );
    assert!(prepare.contains("self.s19k_native_reset_before_cut = true;"));
    assert!(prepare.contains("arm_s19k_native_teardown("));
    // Terminal/drop path: resets are asserted before the checked GPIO437
    // cutoff, and a final raw-1 cut follows the management join.
    let drop = daemon_region("impl Drop for NoPicPsuGuard", "Quiet coast-down at PWM 30");
    let reset_before_cut_at = drop
        .find("let resets_checked = if s19k_native_reset_before_cut {")
        .expect("drop reset-before-cut assertion");
    let first_cut_at = drop
        .find("disable_s19k_track1_psu_checked()")
        .expect("drop checked cut");
    assert!(reset_before_cut_at < first_cut_at);
    let final_cut_at = drop
        .rfind("let final_cut = dcentrald_hal::platform::amlogic::disable_s19k_track1_psu_checked();")
        .expect("drop final raw-1 cut");
    let post_join_reset_at = drop
        .find("let final_resets =")
        .expect("drop post-join reset assertion");
    assert!(post_join_reset_at < final_cut_at);
}

#[test]
fn failed_baud_or_silence_rolls_back_and_never_reaches_work_tx() {
    // The executor's post-baud admission demands the exact 115200 baseline,
    // the exact stock 3M pairing, and refuses with a terminal-rollback
    // sentence; silence/short coverage cannot satisfy it.
    let window = daemon_region(
        "impl Bm1366NativePostBaudAdmission {",
        "fn admit_serial_driver_execution(",
    );
    assert!(window.contains("initial_host_baud == 115_200"));
    assert!(window.contains("terminal rollback is required before any work TX"));
    // Silence at 115200 and GetAddress silence are typed diagnostics, never
    // work-TX proof; work TX without a fresh switched-baud response is the
    // fail-closed arm the executor actually takes.
    assert!(refuse_chip_heard_at_115200_as_3m_work_proof(S19kRxDiag::GetAddressSilenceAt115200).is_ok(),
        "the diagnostic refusal targets ChipHeardAt115200 specifically");
    assert!(refuse_chip_heard_at_115200_as_3m_work_proof(S19kRxDiag::ChipHeardAt115200).is_err());
    let no_fresh_response = classify_s19k_post_baud_observation(
        S19kInitDialect::NativeExperimental,
        true,
        false,
    )
    .expect("switched-baud-without-fresh-response classifies");
    assert_eq!(
        no_fresh_response,
        S19kPostBaudObservation::SwitchedBaudWithoutFreshResponse
    );
    let error = admit_s19k_native_work_tx_after_post_baud(
        S19kInitDialect::NativeExperimental,
        no_fresh_response,
    )
    .expect_err("no fresh response must refuse work TX");
    assert!(error.contains("fail-closed rollback before 21 36"));
}
