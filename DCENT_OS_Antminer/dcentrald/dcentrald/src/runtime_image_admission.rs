//! Signed-image admission is independent of hardware identity and operator Start.
//! Missing release metadata never selects the explicit laboratory path.

use dcentrald_api::runtime_image::{verify_installed_runtime_image, VerifiedRuntimeImage};
use dcentrald_common::BoardDesc;

#[derive(Debug)]
pub(crate) enum RuntimeImageAuthority {
    Signed(VerifiedRuntimeImage),
    #[cfg(feature = "lab")]
    Lab { board_target: &'static str },
    /// Cut-only startup keeps its pre-existing exact route and lifecycle checks.
    SafeOffOnly { board_target: &'static str },
}

impl RuntimeImageAuthority {
    pub(crate) fn hardware_recipe(&self) -> dcentrald_common::runtime_hardware_recipe::HardwareRecipeProfile {
        match self {
            Self::Signed(image) => image.hardware_recipe(),
            _ => dcentrald_common::runtime_hardware_recipe::HardwareRecipeProfile::BoardDefault,
        }
    }

    pub(crate) fn is_cut_only(&self) -> bool {
        matches!(self, Self::SafeOffOnly { .. })
    }

    pub(crate) fn board_target(&self) -> &str {
        match self {
            Self::Signed(image) => image.board_target(),
            #[cfg(feature = "lab")]
            Self::Lab { board_target } => board_target,
            Self::SafeOffOnly { board_target } => board_target,
        }
    }
}

pub(crate) async fn load(
    board: &BoardDesc,
    lab_requested: bool,
) -> Result<RuntimeImageAuthority, String> {
    if !board.release_channel.is_publishable() {
        return Err(format!("{} has no implemented work engine", board.board_target));
    }
    if lab_requested {
        #[cfg(feature = "lab")]
        return Ok(RuntimeImageAuthority::Lab { board_target: board.board_target });
        #[cfg(not(feature = "lab"))]
        return Err("laboratory runtime requires a binary compiled with the lab feature".into());
    }
    verify_installed_runtime_image(board.board_target, env!("CARGO_PKG_VERSION"))
        .await
        .map(RuntimeImageAuthority::Signed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{admit_board_desc_runtime_dispatch, RuntimeDispatchAdmission, RuntimeDispatchKind};
    use dcentrald_common::AsicProtocolIdentity;

    #[test]
    fn a_beta_registry_row_cannot_supply_unsigned_runtime_authority() {
        let board = BoardDesc::am1_s9();
        let declaration = admit_board_desc_runtime_dispatch(
            Some(&board), RuntimeDispatchKind::StandardDaemon, true,
            Some(AsicProtocolIdentity::Bm1387),
        ).unwrap();
        assert!(RuntimeDispatchAdmission::bind(declaration, None, false).is_err());
    }

    #[test]
    fn cut_only_authority_cannot_be_transferred_to_another_board() {
        let board = BoardDesc::am1_s9();
        let declaration = admit_board_desc_runtime_dispatch(
            Some(&board), RuntimeDispatchKind::StandardDaemon, true,
            Some(AsicProtocolIdentity::Bm1387),
        ).unwrap();
        let cut_only = RuntimeImageAuthority::SafeOffOnly { board_target: "am3-s19k" };
        assert!(RuntimeDispatchAdmission::bind(declaration, Some(cut_only), true).is_err());
    }

    #[test]
    fn same_board_cut_only_authority_cannot_admit_mining() {
        let board = BoardDesc::lookup("am3-s19k").unwrap();
        let declaration = || admit_board_desc_runtime_dispatch(
            Some(board), RuntimeDispatchKind::Serial, true,
            Some(AsicProtocolIdentity::Bm1366),
        ).unwrap();
        let proof = || Some(RuntimeImageAuthority::SafeOffOnly { board_target: "am3-s19k" });
        assert!(RuntimeDispatchAdmission::bind(declaration(), proof(), false).is_err());
        let cut_only = RuntimeDispatchAdmission::bind(declaration(), proof(), true).unwrap();
        assert!(cut_only.require_serial_asic_protocol_for_scope(AsicProtocolIdentity::Bm1366, false).is_err());
        let cut_only = RuntimeDispatchAdmission::bind(declaration(), proof(), true).unwrap();
        assert!(cut_only.require_serial_asic_protocol_for_scope(AsicProtocolIdentity::Bm1366, true).is_ok());
    }
}
