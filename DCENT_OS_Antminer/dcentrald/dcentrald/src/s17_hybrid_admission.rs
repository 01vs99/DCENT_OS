//! One-shot admission for the AM2/Zynq BM1397 (S17-family) hybrid route.
//!
//! Mirrors [`crate::s19j_hybrid_admission`] for the 2026-08-27
//! `antminer17-unlock-armada` promotion (agent B1). `AsicProtocolAdmission`
//! proves only that a descriptor and one runtime ASIC identity agree; this
//! module additionally binds the exact carrier observation, the per-target
//! controller class from the stock-RE adjudication, and the configured ASIC
//! identity before the S17 hybrid engine may construct hardware.
//!
//! Evidence base (desk RE, no live unit):
//! - A1
//!   §V1: am2-s17p/am2-t17 are dsPIC33EP16GS202 (G2a framed) class;
//!   am2-s17plus/am2-t17plus are PIC16F1704 (G2b raw) class. Hashboards
//!   BHB07601/07701 (G2a) and BHB07602/07702 (G2b).
//! - A3 same dir `A3_CONTROLLER_EEPROM_SUMMARY.md` §2: byte-exact frame tables
//!   for both controller classes.

use crate::daemon_lifecycle::PlatformIdentitySnapshot;
use crate::runtime::hardware_info::OBSERVED_CONTROL_BOARD_ZYNQ_AM2;
use crate::RuntimeDispatchKind;
use dcentrald_common::{
    AsicProtocolIdentity, BoardFamily, ChainTransportKind, SlotPolicy, VoltageControllerClass,
    WorkEngineKind,
};

/// The exact promoted board-target set for the S17 hybrid lane.
///
/// Deliberately an exact set, never an `am2-*` prefix (ADR-0013 §6): promotion
/// is per registered descriptor, not per family spelling.
pub(crate) const S17_HYBRID_BOARD_TARGETS: [&str; 4] =
    ["am2-s17p", "am2-s17plus", "am2-t17", "am2-t17plus"];

/// Expected voltage-controller class per promoted target (A1 §V1 adjudication):
/// S17/S17 Pro and T17 use the dsPIC33EP16GS202 G2a framed plan; S17+ and T17+
/// use the PIC16F1704 G2b raw plan.
fn expected_controller(board_target: &str) -> Option<VoltageControllerClass> {
    match board_target {
        "am2-s17p" | "am2-t17" => Some(VoltageControllerClass::DsPic33Ep),
        "am2-s17plus" | "am2-t17plus" => Some(VoltageControllerClass::Pic16F1704),
        _ => None,
    }
}

/// Capability to construct and enter the AM2/Zynq BM1397 hybrid engine.
///
/// The private seal prevents sibling modules from constructing this value.
/// Deliberately do not implement `Clone` or `Copy`: one successful admission
/// authorizes one engine entry, not an indefinitely reusable protocol fact.
#[must_use = "S17 hybrid route admission must be consumed by the admitted engine"]
#[derive(Debug)]
pub(crate) struct S17HybridRouteAdmission {
    board_target: &'static str,
    _seal: Seal,
}

#[derive(Debug)]
enum Seal {
    Admitted,
}

impl S17HybridRouteAdmission {
    /// The exact admitted board target (one of [`S17_HYBRID_BOARD_TARGETS`]).
    pub(crate) fn board_target(&self) -> &'static str {
        self.board_target
    }
}

/// Bind immutable startup identity to the exact hardware-owning route.
///
/// Narrower than generic `BoardDesc` dispatch admission: the observed carrier
/// must be the canonical AM2 Zynq control board, the descriptor must be one of
/// the four promoted targets with its RE-adjudicated controller class, and the
/// configured ASIC identity must be exactly BM1397. Anything else fails closed.
pub(crate) fn admit_s17_hybrid_route(
    identity: &PlatformIdentitySnapshot,
    dispatch: RuntimeDispatchKind,
    configured_asic_protocol: Option<AsicProtocolIdentity>,
) -> Result<S17HybridRouteAdmission, String> {
    if dispatch != RuntimeDispatchKind::S17Hybrid {
        return Err(format!(
            "AM2 BM1397 hybrid admission requires the s17-hybrid runtime route, got {}",
            dispatch.label()
        ));
    }

    let board_target = identity.board_target();
    if !S17_HYBRID_BOARD_TARGETS.contains(&board_target) {
        return Err(format!(
            "AM2 BM1397 hybrid admission requires a promoted board target in {:?}, got {:?}",
            S17_HYBRID_BOARD_TARGETS, board_target
        ));
    }

    let board_desc = identity.board_desc.ok_or_else(|| {
        format!("AM2 BM1397 hybrid admission requires a registered {board_target} BoardDesc")
    })?;
    if board_desc.board_target != board_target {
        return Err(format!(
            "immutable board target {:?} contradicts bound BoardDesc {}",
            board_target, board_desc.board_target
        ));
    }

    let expected_controller =
        expected_controller(board_target).expect("promoted target has an expected controller");
    let exact_facets = board_desc.family == BoardFamily::Zynq
        && board_desc.chain_transport == ChainTransportKind::StockFpga
        && board_desc.work_engine == WorkEngineKind::FpgaWorkFifo
        && board_desc.asic_protocol == AsicProtocolIdentity::Bm1397
        && board_desc.voltage_controller == expected_controller
        && board_desc.slot_policy == SlotPolicy::ZynqAbFwSetenv;
    if !exact_facets {
        return Err(format!(
            "BoardDesc {} is not the exact AM2/Zynq BM1397 hybrid composition \
             (expected controller {expected_controller:?} per the 2026-08-27 stock-RE adjudication)",
            board_desc.board_target
        ));
    }

    // Bind the detector's canonical AM2 fabric observation only. Product
    // suffixes are not carrier evidence; hashboard/ASIC proof remains at its
    // independent admission boundary.
    if identity.observed_control_board != OBSERVED_CONTROL_BOARD_ZYNQ_AM2 {
        return Err(format!(
            "declared AM2 hybrid composition contradicts observed control board {:?}",
            identity.observed_control_board
        ));
    }

    if configured_asic_protocol != Some(AsicProtocolIdentity::Bm1397) {
        return Err(format!(
            "AM2 BM1397 hybrid admission requires exact configured ASIC identity Bm1397, got {configured_asic_protocol:?}"
        ));
    }

    Ok(S17HybridRouteAdmission {
        board_target: board_desc.board_target,
        _seal: Seal::Admitted,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("s17_hybrid_admission.rs");

    fn identity(board_target: &str, observed_control_board: &str) -> PlatformIdentitySnapshot {
        PlatformIdentitySnapshot {
            declared_board_target: Some(board_target.to_string()),
            observed_board_target: None,
            board_desc: dcentrald_common::BoardDesc::lookup(board_target),
            declared_platform_marker: Some("zynq-bm3-am2".to_string()),
            declared_subtype: None,
            declared_psu_hardware_variant: None,
            observed_control_board: observed_control_board.to_string(),
        }
    }

    #[test]
    fn all_four_promoted_compositions_admit() {
        for board_target in S17_HYBRID_BOARD_TARGETS {
            let admission = admit_s17_hybrid_route(
                &identity(board_target, OBSERVED_CONTROL_BOARD_ZYNQ_AM2),
                RuntimeDispatchKind::S17Hybrid,
                Some(AsicProtocolIdentity::Bm1397),
            )
            .unwrap_or_else(|error| panic!("{board_target} must admit: {error}"));
            assert_eq!(admission.board_target(), board_target);
        }
    }

    #[test]
    fn s19j_bm1362_reference_board_is_refused() {
        let error = admit_s17_hybrid_route(
            &identity("am2-s19j", OBSERVED_CONTROL_BOARD_ZYNQ_AM2),
            RuntimeDispatchKind::S17Hybrid,
            Some(AsicProtocolIdentity::Bm1362),
        )
        .expect_err("the BM1362 reference board must not enter the BM1397 engine");
        assert!(error.contains("promoted board target"));
    }

    #[test]
    fn s19pro_bm1398_board_is_refused() {
        assert!(admit_s17_hybrid_route(
            &identity("am2-s19pro", OBSERVED_CONTROL_BOARD_ZYNQ_AM2),
            RuntimeDispatchKind::S17Hybrid,
            Some(AsicProtocolIdentity::Bm1398),
        )
        .is_err());
    }

    #[test]
    fn s17e_bm1396_capture_first_board_is_refused() {
        // Same family spelling, different silicon lane: S17e owns its BM1396
        // factory startup and cannot enter the BM1397 hybrid dispatcher even
        // with a caller's BM1397 protocol claim.
        assert!(admit_s17_hybrid_route(
            &identity("am2-s17e", OBSERVED_CONTROL_BOARD_ZYNQ_AM2),
            RuntimeDispatchKind::S17Hybrid,
            Some(AsicProtocolIdentity::Bm1397),
        )
        .is_err());
    }

    #[test]
    fn stale_serial_descriptor_cannot_admit_the_native_fifo_owner() {
        for target in S17_HYBRID_BOARD_TARGETS {
            let exact = identity(target, OBSERVED_CONTROL_BOARD_ZYNQ_AM2);
            let descriptor = exact.board_desc.unwrap();
            assert_eq!(descriptor.chain_transport, ChainTransportKind::StockFpga);
            assert_eq!(descriptor.work_engine, WorkEngineKind::FpgaWorkFifo);
            for old_transport in [true, false] {
                let mut changed = identity(target, OBSERVED_CONTROL_BOARD_ZYNQ_AM2);
                let mut stale = descriptor.clone();
                if old_transport {
                    stale.chain_transport = ChainTransportKind::ZynqHybrid;
                } else {
                    stale.work_engine = WorkEngineKind::SerialWork;
                }
                changed.board_desc = Some(Box::leak(Box::new(stale)));
                assert!(admit_s17_hybrid_route(&changed, RuntimeDispatchKind::S17Hybrid,
                    Some(AsicProtocolIdentity::Bm1397)).is_err());
            }
        }
    }

    #[test]
    fn wrong_observed_carrier_fails_closed() {
        for observed_control_board in ["Zynq am1-s9", "BeagleBone S9", "AML Amlogic", "Unknown"] {
            assert!(
                admit_s17_hybrid_route(
                    &identity("am2-s17p", observed_control_board),
                    RuntimeDispatchKind::S17Hybrid,
                    Some(AsicProtocolIdentity::Bm1397),
                )
                .is_err(),
                "observed carrier {observed_control_board} must contradict AM2 admission"
            );
        }
    }

    #[test]
    fn wrong_route_or_asic_identity_fails_closed() {
        let am2 = identity("am2-s17p", OBSERVED_CONTROL_BOARD_ZYNQ_AM2);
        assert!(admit_s17_hybrid_route(
            &am2,
            RuntimeDispatchKind::S19jHybrid,
            Some(AsicProtocolIdentity::Bm1397),
        )
        .is_err());
        assert!(admit_s17_hybrid_route(
            &am2,
            RuntimeDispatchKind::S17Hybrid,
            Some(AsicProtocolIdentity::Bm1362),
        )
        .is_err());
        assert!(admit_s17_hybrid_route(&am2, RuntimeDispatchKind::S17Hybrid, None).is_err());
    }

    #[test]
    fn route_capability_has_no_public_mint_clone_or_copy_surface() {
        let production = SOURCE
            .split("#[cfg(test)]")
            .next()
            .expect("production source prefix");

        assert!(production.contains("pub(crate) struct S17HybridRouteAdmission"));
        assert!(production.contains("_seal: Seal"));
        assert!(!production.contains("pub struct S17HybridRouteAdmission"));
        assert!(!production.contains("pub fn admit_s17_hybrid_route"));
        assert!(!production.contains("impl Clone for S17HybridRouteAdmission"));
        assert!(!production.contains("impl Copy for S17HybridRouteAdmission"));

        let derive = production
            .split("pub(crate) struct S17HybridRouteAdmission")
            .next()
            .and_then(|prefix| prefix.lines().rev().find(|line| line.contains("derive")))
            .expect("route capability derive");
        assert!(!derive.contains("Clone"));
        assert!(!derive.contains("Copy"));
    }
}
