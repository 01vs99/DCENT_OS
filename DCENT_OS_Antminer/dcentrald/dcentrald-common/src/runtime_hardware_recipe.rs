//! Immutable startup parameters for an exact hardware composition.
//!
//! These values are defaults, never permission to touch hardware. Startup must
//! first verify the image and bind its target to the observed carrier and route;
//! only then may it install the recipe. No marker file or process environment is
//! read here, and an installed recipe cannot change during a retained session.

use std::sync::OnceLock;

use crate::{
    AsicProtocolIdentity, BoardDesc, BoardFamily, ChainTransportKind, VoltageControllerClass,
    WorkEngineKind,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HardwareRecipeProfile {
    #[default]
    BoardDefault,
    /// Separate .25 Loki wiring; never inferred from the general am2-s19j row.
    Xil25Loki,
}

impl HardwareRecipeProfile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BoardDefault => "board-default",
            Self::Xil25Loki => "am2-s19j-xil-loki",
        }
    }
}

impl std::str::FromStr for HardwareRecipeProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "board-default" => Ok(Self::BoardDefault),
            "am2-s19j-xil-loki" => Ok(Self::Xil25Loki),
            _ => Err("unknown hardware recipe profile"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerControlPolarity {
    ActiveLow,
    ActiveHigh,
}

impl PowerControlPolarity {
    pub const fn active_low(self) -> bool {
        matches!(self, Self::ActiveLow)
    }

    pub const fn off_level(self) -> bool {
        self.active_low()
    }
}

/// Combine a captured wiring default with an optional lab-only declaration.
/// Presence is supplied separately so explicit false/conflicting lab values
/// cannot silently fall through to a production polarity.
pub fn resolve_power_control_polarity(
    declared: Option<PowerControlPolarity>,
    lab_override: Option<(bool, bool)>,
) -> Result<PowerControlPolarity, &'static str> {
    match lab_override {
        Some((true, false)) => Ok(PowerControlPolarity::ActiveLow),
        Some((false, true)) => Ok(PowerControlPolarity::ActiveHigh),
        Some(_) => Err("PWR_CONTROL polarity declaration is empty or conflicting"),
        None => declared.ok_or("PWR_CONTROL polarity is unknown for the exact hardware recipe"),
    }
}

/// Positive parameters from the shipped am2-s19jpro S82 and XIL defaults.
/// Every lab override retains its own original parser at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Am2HardwareFlag {
    SafeI2cSlave,
    BosminerDsPicPacing,
    FramedGetVersion,
    MmapPsuBitbang,
    EepromBusWarmup,
    UartMcrOut2,
    UartIerParity,
    Bm1362UartRelay,
    SkipFastUart,
    SkipLegacy115200PerChip,
    SerialWorkDispatch,
}

impl Am2HardwareFlag {
    /// Compatibility mapping for existing call-site parsers. Unknown or unsafe
    /// diagnostic flags have no production default in this table.
    pub fn from_env_name(name: &str) -> Option<Self> {
        Some(match name {
            "DCENT_AM2_I2C_SLAVE_SAFE" => Self::SafeI2cSlave,
            "DCENT_AM2_DSPIC_BOSMINER_FAITHFUL" => Self::BosminerDsPicPacing,
            "DCENT_AM2_GET_VERSION_FRAMED_4B" => Self::FramedGetVersion,
            "DCENT_AM2_PSU_BITBANG_USE_MMAP" => Self::MmapPsuBitbang,
            "DCENT_AM2_EEPROM_BUS_WARMUP" => Self::EepromBusWarmup,
            "DCENT_AM2_MCR_OUT2" => Self::UartMcrOut2,
            "DCENT_AM2_IER_BOSMINER_PARITY" => Self::UartIerParity,
            "DCENT_BM1362_ENABLE_UART_RELAY_LAB" => Self::Bm1362UartRelay,
            "DCENT_AM2_SKIP_FAST_UART" => Self::SkipFastUart,
            "DCENT_AM2_SKIP_115200_PER_CHIP" => Self::SkipLegacy115200PerChip,
            "DCENT_AM2_SERIAL_WORK_DISPATCH" => Self::SerialWorkDispatch,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeHardwareRecipe {
    board_target: &'static str,
    profile: HardwareRecipeProfile,
    am2_bm1362: bool,
    gpio907_polarity: Option<PowerControlPolarity>,
}

impl RuntimeHardwareRecipe {
    /// Resolve parameters after the caller has joined verified image identity
    /// with the immutable platform snapshot. This is deliberately not an
    /// admission token; the hardware-owning constructors still require theirs.
    pub fn resolve(
        board: &BoardDesc,
        observed_control_board: &str,
        dispatch_label: &str,
        profile: HardwareRecipeProfile,
    ) -> Result<Self, String> {
        let registered = BoardDesc::lookup(board.board_target)
            .ok_or("hardware recipe requires an exact registered board target")?;
        if registered != board {
            return Err("hardware recipe descriptor contradicts the registered composition".into());
        }
        let am2_bm1362 = board.board_target == "am2-s19j"
            && board.family == BoardFamily::Zynq
            && board.chain_transport == ChainTransportKind::ZynqHybrid
            && board.work_engine == WorkEngineKind::SerialWork
            && board.asic_protocol == AsicProtocolIdentity::Bm1362
            && board.voltage_controller == VoltageControllerClass::DsPic33Ep;
        let s17 = matches!(
            board.board_target,
            "am2-s17p" | "am2-s17plus" | "am2-t17" | "am2-t17plus"
        );
        let am2_bm1398 = matches!(
            board.board_target,
            "am2-s19pro" | "am2-s19" | "am2-t19" | "am2-s19a" | "am2-s19plus"
        ) && board.family == BoardFamily::Zynq
            && board.chain_transport == ChainTransportKind::FpgaUio
            && board.work_engine == WorkEngineKind::FpgaWorkFifo
            && board.asic_protocol == AsicProtocolIdentity::Bm1398
            && board.voltage_controller == VoltageControllerClass::Pic16F1704;
        if am2_bm1362 || s17 || am2_bm1398 {
            if observed_control_board != "Zynq am2" {
                return Err("AM2 hardware recipe requires the observed Zynq am2 carrier".into());
            }
            let route_matches = if am2_bm1362 {
                matches!(dispatch_label, "s19j-hybrid" | "serial")
            } else if s17 {
                dispatch_label == "s17-hybrid"
            } else {
                dispatch_label == "serial"
            };
            if !route_matches {
                return Err("AM2 hardware recipe contradicts the selected native route".into());
            }
        }
        if profile == HardwareRecipeProfile::Xil25Loki && !am2_bm1362 {
            return Err("XIL .25 Loki recipe belongs only to exact am2-s19j/BM1362".into());
        }
        // S17 native set_psu_gpio_at follows stock power_api.c: 0=ON, 1=OFF.
        // The old S82 active-high declaration conflicts with that retained
        // native implementation and cannot supply an electrical safe-off proof.
        // am2-s19j's generic row has NO proved universal polarity: its S82
        // explicitly scopes active-low to xil, not sibling AM2 units.
        // Each exact held stock image has the same semantic sequence: GPIO907
        // high, PSU setup, then GPIO907 low only after setup succeeds. These
        // are software observations, not measured electrical claims:
        // s19/s19-pro-20211116: ON 0x419b0, OFF 0x419e8;
        // t19-20230320: ON 0x42188, OFF 0x421c0;
        // s19a-20221206: ON 0x42540, OFF 0x42578.
        // Exact S19+ VNish rc5 cgminer (sha256 db0656ecdba3484767ffbd88992d0fb61
        // dac446bf57430120bae5e777d1f72bf) reads generated model-info at 0x94ddc;
        // startup 0x6b1b4 selects Xilinx platform 0. Factory 0xe1d5c installs
        // ON 0xfc780 / OFF 0xfc8bc. Semantic Power ON 0x6477c and Power OFF
        // 0x63cc0 reach those callbacks through 0xe90e4/0xe90e8. They write
        // raw GPIO907 0/1 via 0x10b300, without active_low conversion.
        // The held Bitmain DTBs identify xlnx,zynq-gpio-1.0 at e000a000. The native
        // owner separately requires that observed controller to own 906..1023
        // and checks raw active_low=0 before touching the retained pin.
        let gpio907_polarity = if s17 || am2_bm1398 || profile == HardwareRecipeProfile::Xil25Loki {
            Some(PowerControlPolarity::ActiveLow)
        } else {
            None
        };
        Ok(Self {
            board_target: board.board_target,
            profile,
            am2_bm1362,
            gpio907_polarity,
        })
    }

    pub const fn board_target(self) -> &'static str {
        self.board_target
    }
    pub const fn profile(self) -> HardwareRecipeProfile {
        self.profile
    }
    pub const fn gpio907_polarity(self) -> Option<PowerControlPolarity> {
        self.gpio907_polarity
    }

    pub const fn am2_flag(self, flag: Am2HardwareFlag) -> bool {
        // The shipped positive transport defaults all belong to this one exact
        // BM1362 composition. S17's MiscCtrl/FPGA path must not inherit them.
        match flag {
            Am2HardwareFlag::SafeI2cSlave
            | Am2HardwareFlag::BosminerDsPicPacing
            | Am2HardwareFlag::FramedGetVersion
            | Am2HardwareFlag::MmapPsuBitbang
            | Am2HardwareFlag::EepromBusWarmup
            | Am2HardwareFlag::UartMcrOut2
            | Am2HardwareFlag::UartIerParity
            | Am2HardwareFlag::Bm1362UartRelay
            | Am2HardwareFlag::SkipFastUart
            | Am2HardwareFlag::SkipLegacy115200PerChip
            | Am2HardwareFlag::SerialWorkDispatch => self.am2_bm1362,
        }
    }
}

static INSTALLED: OnceLock<RuntimeHardwareRecipe> = OnceLock::new();

/// Startup-only publication of defaults; refuses even identical reinstallation.
/// Call only after image/route identity binding and before any hardware owner.
pub fn install(recipe: RuntimeHardwareRecipe) -> Result<(), &'static str> {
    INSTALLED
        .set(recipe)
        .map_err(|_| "runtime hardware recipe is already installed")
}

pub fn installed() -> Option<&'static RuntimeHardwareRecipe> {
    INSTALLED.get()
}

pub fn am2_default(flag: Am2HardwareFlag) -> bool {
    installed().is_some_and(|recipe| recipe.am2_flag(flag))
}

/// The admitted startup session's captured polarity. Unknown stays unknown.
pub fn gpio907_polarity() -> Option<PowerControlPolarity> {
    installed().and_then(|recipe| recipe.gpio907_polarity())
}

#[cfg(test)]
mod bm1398_recipe_tests {
    use super::*;

    #[test]
    fn bm1398_power_recipe_requires_exact_registered_native_composition() {
        for target in [
            "am2-s19pro",
            "am2-s19",
            "am2-t19",
            "am2-s19a",
            "am2-s19plus",
        ] {
            let board = BoardDesc::lookup(target).unwrap();
            let recipe = RuntimeHardwareRecipe::resolve(
                board,
                "Zynq am2",
                "serial",
                HardwareRecipeProfile::BoardDefault,
            )
            .unwrap();
            assert_eq!(
                recipe.gpio907_polarity(),
                Some(PowerControlPolarity::ActiveLow)
            );
            assert!(!recipe.am2_flag(Am2HardwareFlag::Bm1362UartRelay));
            for (carrier, route) in [
                ("Zynq am1", "serial"),
                ("Amlogic am3", "serial"),
                ("Zynq am2", "s19j-hybrid"),
                ("Zynq am2", "s17-hybrid"),
            ] {
                assert!(RuntimeHardwareRecipe::resolve(
                    board,
                    carrier,
                    route,
                    HardwareRecipeProfile::BoardDefault
                )
                .is_err());
            }
            assert!(RuntimeHardwareRecipe::resolve(
                board,
                "Zynq am2",
                "serial",
                HardwareRecipeProfile::Xil25Loki
            )
            .is_err());
            let mut contradicted = board.clone();
            contradicted.chain_transport = ChainTransportKind::ZynqHybrid;
            assert!(RuntimeHardwareRecipe::resolve(
                &contradicted,
                "Zynq am2",
                "serial",
                HardwareRecipeProfile::BoardDefault
            )
            .is_err());
        }
    }
}
