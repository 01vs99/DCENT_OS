//! Independent image capabilities derived from the actual board registry.
//!
//! A boot cut, a daemon work engine and a persistent storage writer are separate
//! authorities. None implies another, and publication eligibility is not an
//! installer or storage contract. Physical identity/polarity checks still apply.

use crate::{BoardDesc, ReleaseChannel, WorkEngineKind};
use dcent_schema::hardware::UpdateMechanism;

pub const RUNTIME_POLICY_SCHEMA: &str = "dcentos-board-runtime-policy/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoardRuntimePolicy {
    pub board_target: &'static str,
    pub release_channel: ReleaseChannel,
    pub boot_safeoff: bool,
    pub daemon_hardware: bool,
    pub ota_storage: bool,
    pub persistent_update_allowed: bool,
    pub update_mechanism: UpdateMechanism,
}

impl BoardRuntimePolicy {
    pub fn for_board(board: &BoardDesc) -> Option<Self> {
        let registered = BoardDesc::lookup(board.board_target)?;
        if registered != board {
            return None;
        }
        let daemon_hardware = board.release_channel.is_publishable()
            && board.work_engine != WorkEngineKind::ManagementOnly;
        // The distinct deployed NoPic row admits its existing boot cut only.
        // Exact full-row equality prevents borrowing this exception for another
        // board or for a caller-modified descriptor. It never enables mining.
        let boot_safeoff = daemon_hardware || *board == BoardDesc::am3_s19kpro_nopic();
        Some(Self {
            board_target: board.board_target,
            release_channel: board.release_channel,
            boot_safeoff,
            daemon_hardware,
            // A host rootfs-window writer cannot authorize on-target OTA-08.
            ota_storage: board.enablement.allows_persistent_update()
                && board.enablement.update_mechanism == UpdateMechanism::ZynqUbiFwSetenv,
            persistent_update_allowed: board.enablement.allows_persistent_update(),
            update_mechanism: board.enablement.update_mechanism,
        })
    }
}

/// Separate schema; the strict schema-4 Toolbox enablement matrix is unchanged.
pub fn board_runtime_policy_json() -> String {
    let mut output = format!("{{\n  \"schema\": \"{RUNTIME_POLICY_SCHEMA}\",\n  \"targets\": [\n");
    for (index, board) in BoardDesc::all_registered().iter().enumerate() {
        let row = BoardRuntimePolicy::for_board(board).expect("registry row must resolve exactly");
        if index != 0 {
            output.push_str(",\n");
        }
        output.push_str(&format!(
            "    {{\"board_target\":\"{}\",\"release_channel\":\"{}\",\"boot_safeoff\":{},\"daemon_hardware\":{},\"ota_storage\":{},\"persistent_update_allowed\":{},\"update_mechanism\":\"{}\"}}",
            row.board_target, row.release_channel.as_str(), row.boot_safeoff, row.daemon_hardware, row.ota_storage, row.persistent_update_allowed, row.update_mechanism.as_str(),
        ));
    }
    output.push_str("\n  ]\n}\n");
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_policy_registry_channels_never_grant_storage_by_inference() {
        for board in BoardDesc::all_registered() {
            let policy = BoardRuntimePolicy::for_board(board).unwrap();
            assert_eq!(
                policy.persistent_update_allowed,
                board.enablement.allows_persistent_update()
            );
            assert_eq!(
                policy.ota_storage,
                policy.persistent_update_allowed
                    && policy.update_mechanism == UpdateMechanism::ZynqUbiFwSetenv
            );
            if board.release_channel == ReleaseChannel::Unsupported {
                assert!(!policy.daemon_hardware, "{}", board.board_target);
            }
        }
    }

    #[test]
    fn runtime_policy_s19k_boot_daemon_and_storage_stay_independent() {
        let guarded = BoardRuntimePolicy::for_board(&BoardDesc::am3_s19kpro()).unwrap();
        assert!(guarded.boot_safeoff && guarded.daemon_hardware);
        assert!(!guarded.ota_storage);
        assert!(guarded.persistent_update_allowed);
        assert_eq!(guarded.update_mechanism, UpdateMechanism::HostRootfsWindow);
        let nopic = BoardRuntimePolicy::for_board(&BoardDesc::am3_s19kpro_nopic()).unwrap();
        assert!(nopic.boot_safeoff);
        assert!(!nopic.daemon_hardware && !nopic.ota_storage);
        let mut forged = BoardDesc::am3_s19kpro_nopic();
        forged.release_channel = ReleaseChannel::Beta;
        assert!(BoardRuntimePolicy::for_board(&forged).is_none());
    }

    #[test]
    fn committed_board_runtime_policy_matches_registry() {
        assert_eq!(
            include_str!("../../../docs/architecture/board_runtime_policy.json"),
            board_runtime_policy_json(),
            "regenerate via cargo run -p dcentrald-common --example export_runtime_policy"
        );
    }
}
