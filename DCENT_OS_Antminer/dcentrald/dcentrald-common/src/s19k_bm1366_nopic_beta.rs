//! S19k Pro BM1366 NoPic tryable-BETA skeleton (checklist A / issue #1).
//!
//! Host-testable pins from:
//! -  (G1–G6)
//!
//!
//! This module is **admission/policy data only**. It does not energize rails,
//! open UART sessions, or claim mining. Wire (G7–G11), AML-install (G12–G14),
//! and Bench-HOLD (G15–G19) stay out of scope.
//!
//! Geometry note: HashSource / Lead / `hashboard_catalog` use **77** chips
//! (11×7). `dcentrald-silicon-profiles` still documents a stock hashcounting
//! 76-chip constant — that tension is intentional and not resolved here.

use crate::s19k_bm1366_init_seq::{
    BOSMINER_BM1366_AML_HOST_BAUD, BOSMINER_BM1366_FASTUART_3M125,
    BOSMINER_BM1366_REQUESTED_FAST_BAUD,
};
use crate::{AsicProtocolIdentity, BoardDesc, VoltageControllerClass, WorkEngineKind};
use std::fmt;

/// Exact HashSource PT board_name set for S19k BM1366 NoPic admission (G1).
pub const S19K_BM1366_NOPIC_BOARD_NAMES: &[&str] =
    &["BHB56901", "BHB56902", "BHB56903", "BHB56906", "BHB56907"];

/// S21 public fixture board_name — must never admit as S19k BM1366 (G1/G12 identity).
pub const S21_BM1368_FIXTURE_BOARD_NAME: &str = "BHB68603";

pub const S19K_BM1366_CHIP_ID: u16 = 0x1366;
pub const S19K_BM1366_ASIC_NUM: u16 = 77;
pub const S19K_BM1366_VOLTAGE_DOMAINS: u8 = 11;
pub const S19K_BM1366_CHIPS_PER_DOMAIN: u8 = 7;
pub const S19K_BM1366_MIDSTATE_NUMBER: u8 = 8;
pub const S21_BM1368_FIXTURE_MIDSTATE_NUMBER: u8 = 16;
/// Exact stock semantic chip baud requested by the S19k BM1366 driver.
pub const S19K_BM1366_BAUD_HZ: u32 = BOSMINER_BM1366_REQUESTED_FAST_BAUD;
/// Exact Amlogic Linux termios rate paired with the semantic 3.125 Mbaud
/// request. Do not configure host 3.125 Mbaud or treat this as a readback.
pub const S19K_BM1366_HOST_BAUD_HZ: u32 = BOSMINER_BM1366_AML_HOST_BAUD;
pub const S19K_BM1366_FASTUART_VALUE: u32 = BOSMINER_BM1366_FASTUART_3M125;
/// HashSource/AMTC factory-jig class retained as evidence only. It is not the
/// stock production driver pair and must not pass the NoPic runtime admission.
pub const S19K_BM1366_JIG_BAUD_HZ: u32 = 12_000_000;
pub const S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV: u16 = 1500;
pub const S19K_BM1366_INC_FREQ_DELAY_MS: u16 = 100;
pub const S19K_BM1366_VOLTAGE_ADJUST_STEP: u16 = 10;
/// CtrlBoard LM75A indices from HashSource PT configs (G2).
pub const S19K_CTRLBOARD_LM75_ADDRS: [u8; 2] = [0, 4];
/// Amlogic PWR_EN number. am3-s19k / Braiins S19k Pro SafeOff is sysfs **1**
/// (T6: `0=ON`, `1=OFF`). S21-class NoPic SafeOff=0 is a **different**
/// board_target — do not copy it here. See [`crate::s19k_am3_gpio437`].
pub const S19K_GPIO_PWR_EN: u32 = 437;
pub const S19K_GPIO_PWR_EN_SAFE_OFF_VALUE: u8 = crate::s19k_am3_gpio437::S19K_AM3_GPIO437_VALUE_OFF;
pub const S19K_HAS_PIC: bool = false;
pub const S19K_AM3_BOARD_TARGET: &str = "am3-s19k";
pub const S19K_AM3_PLATFORM_TARGET: &str = "am3-aml-s19k";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kBm1366NopicSkeleton {
    pub board_name: &'static str,
    pub chip_id: u16,
    pub asic_num: u16,
    pub voltage_domains: u8,
    pub chips_per_domain: u8,
    pub midstate_number: u8,
    /// Semantic baud requested from the ASIC driver.
    pub baud_hz: u32,
    pub host_baud_hz: u32,
    pub fast_uart_value: u32,
    pub pre_open_core_voltage_cv: u16,
    pub inc_freq_delay_ms: u16,
    pub voltage_adjust_step: u16,
    pub has_pic: bool,
    pub ctrlboard_lm75_addrs: [u8; 2],
    pub gpio_pwr_en: u32,
    pub gpio_pwr_en_safe_off_value: u8,
}

pub const S19K_BM1366_NOPIC_SKELETON: S19kBm1366NopicSkeleton = S19kBm1366NopicSkeleton {
    board_name: "BHB56902",
    chip_id: S19K_BM1366_CHIP_ID,
    asic_num: S19K_BM1366_ASIC_NUM,
    voltage_domains: S19K_BM1366_VOLTAGE_DOMAINS,
    chips_per_domain: S19K_BM1366_CHIPS_PER_DOMAIN,
    midstate_number: S19K_BM1366_MIDSTATE_NUMBER,
    baud_hz: S19K_BM1366_BAUD_HZ,
    host_baud_hz: S19K_BM1366_HOST_BAUD_HZ,
    fast_uart_value: S19K_BM1366_FASTUART_VALUE,
    pre_open_core_voltage_cv: S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
    inc_freq_delay_ms: S19K_BM1366_INC_FREQ_DELAY_MS,
    voltage_adjust_step: S19K_BM1366_VOLTAGE_ADJUST_STEP,
    has_pic: S19K_HAS_PIC,
    ctrlboard_lm75_addrs: S19K_CTRLBOARD_LM75_ADDRS,
    gpio_pwr_en: S19K_GPIO_PWR_EN,
    gpio_pwr_en_safe_off_value: S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S19kBm1366NopicAdmitError {
    UnknownBoardName {
        observed: String,
    },
    S21FixtureBoardNameForbidden,
    ChipIdMismatch {
        observed: u16,
    },
    GeometryMismatch,
    MidstateMustBeEight {
        observed: u8,
    },
    PicOwnerForbidden,
    BaudClassMismatch {
        observed: u32,
    },
    StockBaudPairMismatch {
        requested_chip_baud_hz: u32,
        host_baud_hz: u32,
        fast_uart_value: u32,
    },
    PreOpenDefaultsMismatch,
    Lm75MapMismatch,
    GpioSafeOffContractBroken,
    VoltageControllerNotNoPic {
        observed: String,
    },
    BoardTargetMismatch {
        observed: String,
    },
    AsicProtocolMismatch,
    MiningDefaultMustStayOff,
    WorkEngineMustBeSerial,
}

impl fmt::Display for S19kBm1366NopicAdmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownBoardName { observed } => {
                write!(f, "S19k NoPic admit: unknown board_name {observed:?}")
            }
            Self::S21FixtureBoardNameForbidden => {
                write!(f, "S19k NoPic admit: S21 BM1368 fixture board_name forbidden")
            }
            Self::ChipIdMismatch { observed } => {
                write!(f, "S19k NoPic admit: chip_id {observed:#06x} is not BM1366")
            }
            Self::GeometryMismatch => write!(f, "S19k NoPic admit: geometry must be 77 = 11x7"),
            Self::MidstateMustBeEight { observed } => {
                write!(f, "S19k NoPic admit: midstate_number {observed} must be 8")
            }
            Self::PicOwnerForbidden => write!(
                f,
                "S19k NoPic admission hard-fail: PIC/dsPIC ownership selected; NoPic fabric required"
            ),
            Self::BaudClassMismatch { observed } => {
                write!(
                    f,
                    "S19k NoPic admit: requested chip baud {observed} is not stock 3.125 Mbaud"
                )
            }
            Self::StockBaudPairMismatch {
                requested_chip_baud_hz,
                host_baud_hz,
                fast_uart_value,
            } => write!(
                f,
                "S19k NoPic admit: stock baud pair mismatch requested={requested_chip_baud_hz} host={host_baud_hz} FastUART={fast_uart_value:#010x}"
            ),
            Self::PreOpenDefaultsMismatch => {
                write!(f, "S19k NoPic admit: pre-open defaults mismatch")
            }
            Self::Lm75MapMismatch => {
                write!(f, "S19k NoPic admit: CtrlBoard LM75 map must be [0, 4]")
            }
            Self::GpioSafeOffContractBroken => {
                write!(f, "S19k NoPic admit: GPIO437 SafeOff contract broken")
            }
            Self::VoltageControllerNotNoPic { observed } => write!(
                f,
                "S19k NoPic admission hard-fail: voltage controller {observed} is a PIC/dsPIC (or non-NoPic) owner; NoPic fabric required"
            ),
            Self::BoardTargetMismatch { observed } => {
                write!(f, "S19k NoPic admit: board_target {observed:?} is not am3-s19k")
            }
            Self::AsicProtocolMismatch => {
                write!(f, "S19k NoPic admit: asic_protocol must be BM1366")
            }
            Self::MiningDefaultMustStayOff => {
                write!(f, "S19k NoPic admit: mining_default_enabled must stay false")
            }
            Self::WorkEngineMustBeSerial => {
                write!(
                    f,
                    "S19k NoPic admit: work_engine must be SerialWork (production construction)"
                )
            }
        }
    }
}

/// True when the voltage/thermal ownership class is a PIC/dsPIC (or framed PIC ABI).
pub const fn voltage_controller_is_pic_owner(vc: VoltageControllerClass) -> bool {
    matches!(
        vc,
        VoltageControllerClass::Pic16F1704
            | VoltageControllerClass::DsPic33Ep
            | VoltageControllerClass::Pic1704
            | VoltageControllerClass::Bm1396FramedI2c11
    )
}

/// Fail-closed gate: S19k / AmlogicNoPicProfile::S19k must not construct when a
/// PIC/dsPIC voltage or thermal owner would be selected.
pub fn admit_s19k_nopic_voltage_controller(
    voltage_controller: VoltageControllerClass,
) -> Result<(), S19kBm1366NopicAdmitError> {
    if voltage_controller_is_pic_owner(voltage_controller)
        || voltage_controller != VoltageControllerClass::NoPic
    {
        return Err(S19kBm1366NopicAdmitError::VoltageControllerNotNoPic {
            observed: format!("{voltage_controller:?}"),
        });
    }
    Ok(())
}

/// BoardDesc construction / runtime-dispatch pin for `am3_s19kpro`.
pub fn admit_s19k_am3_board_desc(desc: &BoardDesc) -> Result<(), S19kBm1366NopicAdmitError> {
    if desc.board_target != S19K_AM3_BOARD_TARGET {
        return Err(S19kBm1366NopicAdmitError::BoardTargetMismatch {
            observed: desc.board_target.to_string(),
        });
    }
    if desc.asic_protocol != AsicProtocolIdentity::Bm1366 {
        return Err(S19kBm1366NopicAdmitError::AsicProtocolMismatch);
    }
    if desc.mining_default_enabled {
        return Err(S19kBm1366NopicAdmitError::MiningDefaultMustStayOff);
    }
    if desc.work_engine != WorkEngineKind::SerialWork {
        return Err(S19kBm1366NopicAdmitError::WorkEngineMustBeSerial);
    }
    admit_s19k_nopic_voltage_controller(desc.voltage_controller)?;
    Ok(())
}

/// Ordered NoPic bring-up phases for S19k (twin BM1368 CtrlBoard LM75-before-probe).
///
/// Production code must advance through these in discriminant order. Skipping
/// [`S19kNopicBringupPhase::CtrlBoardLm75Fabric`] before ASIC GetAddress/probe
/// is a hard refuse — not the AM3-BB dsPIC LM75 bridge path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum S19kNopicBringupPhase {
    /// Skeleton / BoardDesc / voltage-controller admission complete.
    AdmittedIdentity = 0,
    /// CtrlBoard LM75 fabric at indices [0, 4] required before ASIC probe.
    CtrlBoardLm75Fabric = 1,
    /// ASIC GetAddress / probe (Wire-owned bytes; Daemon orders this after LM75).
    AsicProbeGetAddress = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum S19kNopicBringupOrderError {
    PhaseSkipped {
        attempted: S19kNopicBringupPhase,
        required: S19kNopicBringupPhase,
    },
    AsicProbeBeforeLm75,
}

impl fmt::Display for S19kNopicBringupOrderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PhaseSkipped { attempted, required } => write!(
                f,
                "S19k NoPic bring-up order hard-fail: attempted {attempted:?} before required {required:?}"
            ),
            Self::AsicProbeBeforeLm75 => write!(
                f,
                "S19k NoPic bring-up order hard-fail: ASIC GetAddress/probe before CtrlBoard LM75 fabric [0,4]"
            ),
        }
    }
}

/// Session gate that refuses ASIC probe if CtrlBoard LM75 setup was skipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kNopicBringupSession {
    phase: S19kNopicBringupPhase,
    lm75_addrs: [u8; 2],
}

impl S19kNopicBringupSession {
    /// Smallest construction point after identity/NoPic voltage admission.
    pub fn from_am3_board_desc(desc: &BoardDesc) -> Result<Self, S19kBm1366NopicAdmitError> {
        admit_s19k_am3_board_desc(desc)?;
        Ok(Self {
            phase: S19kNopicBringupPhase::AdmittedIdentity,
            lm75_addrs: S19K_CTRLBOARD_LM75_ADDRS,
        })
    }

    pub fn phase(&self) -> S19kNopicBringupPhase {
        self.phase
    }

    pub fn ctrlboard_lm75_addrs(&self) -> [u8; 2] {
        self.lm75_addrs
    }

    /// Record CtrlBoard LM75 fabric setup (indices must match HashSource [0, 4]).
    pub fn record_ctrlboard_lm75_fabric(
        &mut self,
        addrs: [u8; 2],
    ) -> Result<(), S19kNopicBringupOrderError> {
        if self.phase < S19kNopicBringupPhase::AdmittedIdentity {
            return Err(S19kNopicBringupOrderError::PhaseSkipped {
                attempted: S19kNopicBringupPhase::CtrlBoardLm75Fabric,
                required: S19kNopicBringupPhase::AdmittedIdentity,
            });
        }
        if addrs != S19K_CTRLBOARD_LM75_ADDRS {
            return Err(S19kNopicBringupOrderError::PhaseSkipped {
                attempted: S19kNopicBringupPhase::CtrlBoardLm75Fabric,
                required: S19kNopicBringupPhase::CtrlBoardLm75Fabric,
            });
        }
        self.lm75_addrs = addrs;
        self.phase = S19kNopicBringupPhase::CtrlBoardLm75Fabric;
        Ok(())
    }

    /// Admit ASIC GetAddress/probe only after CtrlBoard LM75 fabric is recorded.
    pub fn admit_asic_probe_get_address(&mut self) -> Result<(), S19kNopicBringupOrderError> {
        if self.phase < S19kNopicBringupPhase::CtrlBoardLm75Fabric {
            return Err(S19kNopicBringupOrderError::AsicProbeBeforeLm75);
        }
        self.phase = S19kNopicBringupPhase::AsicProbeGetAddress;
        Ok(())
    }
}

/// G1–G5 fail-closed admit for the tryable-BETA skeleton (no energize).
/// Admit only the held-stock S19k BM1366 ASIC/host/FastUART triple. The 12M
/// AMTC/HashSource jig setting is retained separately and deliberately fails.
pub fn admit_s19k_bm1366_stock_baud_pair(
    requested_chip_baud_hz: u32,
    host_baud_hz: u32,
    fast_uart_value: u32,
) -> Result<(), S19kBm1366NopicAdmitError> {
    if requested_chip_baud_hz != S19K_BM1366_BAUD_HZ
        || host_baud_hz != S19K_BM1366_HOST_BAUD_HZ
        || fast_uart_value != S19K_BM1366_FASTUART_VALUE
    {
        return Err(S19kBm1366NopicAdmitError::StockBaudPairMismatch {
            requested_chip_baud_hz,
            host_baud_hz,
            fast_uart_value,
        });
    }
    Ok(())
}

pub fn admit_s19k_bm1366_nopic_skeleton(
    board_name: &str,
    chip_id: u16,
    asic_num: u16,
    midstate_number: u8,
    has_pic: bool,
    baud_hz: u32,
    pre_open_core_voltage_cv: u16,
    inc_freq_delay_ms: u16,
    voltage_adjust_step: u16,
    ctrlboard_lm75_addrs: [u8; 2],
    gpio_pwr_en: u32,
    gpio_safe_off_value: u8,
) -> Result<(), S19kBm1366NopicAdmitError> {
    if board_name == S21_BM1368_FIXTURE_BOARD_NAME {
        return Err(S19kBm1366NopicAdmitError::S21FixtureBoardNameForbidden);
    }
    if !S19K_BM1366_NOPIC_BOARD_NAMES.contains(&board_name) {
        return Err(S19kBm1366NopicAdmitError::UnknownBoardName {
            observed: board_name.to_string(),
        });
    }
    if chip_id != S19K_BM1366_CHIP_ID {
        return Err(S19kBm1366NopicAdmitError::ChipIdMismatch { observed: chip_id });
    }
    if asic_num != S19K_BM1366_ASIC_NUM
        || u16::from(S19K_BM1366_VOLTAGE_DOMAINS) * u16::from(S19K_BM1366_CHIPS_PER_DOMAIN)
            != S19K_BM1366_ASIC_NUM
    {
        return Err(S19kBm1366NopicAdmitError::GeometryMismatch);
    }
    if midstate_number != S19K_BM1366_MIDSTATE_NUMBER {
        return Err(S19kBm1366NopicAdmitError::MidstateMustBeEight {
            observed: midstate_number,
        });
    }
    if has_pic || S19K_HAS_PIC {
        return Err(S19kBm1366NopicAdmitError::PicOwnerForbidden);
    }
    if baud_hz != S19K_BM1366_BAUD_HZ {
        return Err(S19kBm1366NopicAdmitError::BaudClassMismatch { observed: baud_hz });
    }
    admit_s19k_bm1366_stock_baud_pair(
        baud_hz,
        S19K_BM1366_HOST_BAUD_HZ,
        S19K_BM1366_FASTUART_VALUE,
    )?;
    if pre_open_core_voltage_cv != S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV
        || inc_freq_delay_ms != S19K_BM1366_INC_FREQ_DELAY_MS
        || voltage_adjust_step != S19K_BM1366_VOLTAGE_ADJUST_STEP
    {
        return Err(S19kBm1366NopicAdmitError::PreOpenDefaultsMismatch);
    }
    if ctrlboard_lm75_addrs != S19K_CTRLBOARD_LM75_ADDRS {
        return Err(S19kBm1366NopicAdmitError::Lm75MapMismatch);
    }
    if gpio_pwr_en != S19K_GPIO_PWR_EN {
        return Err(S19kBm1366NopicAdmitError::GpioSafeOffContractBroken);
    }
    if crate::s19k_am3_gpio437::refuse_re4c_safe_off_as_am3_s19k_cut(gpio_safe_off_value).is_err()
        || gpio_safe_off_value != S19K_GPIO_PWR_EN_SAFE_OFF_VALUE
    {
        return Err(S19kBm1366NopicAdmitError::GpioSafeOffContractBroken);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const S19K_TOML: &str = include_str!("../../dcentrald_s19k.toml");
    const SERIAL_MINING: &str = include_str!("../../dcentrald/src/serial_mining.rs");
    const INSTALL_SCRIPT: &str = include_str!("../../../scripts/install_amlogic_persistent.sh");
    const OVERLAY: &str = include_str!(
        "../../../br2_external_dcentos/board/amlogic/am3-s19kpro/rootfs-overlay/etc/dcentrald.toml"
    );
    const TMP_TRIAL: &str = include_str!("../../../scripts/dcentrald_s19k_tmp_trial.sh");
    const BETA_SRC: &str = include_str!("s19k_bm1366_nopic_beta.rs");

    fn admit_ok(board: &str) {
        admit_s19k_bm1366_nopic_skeleton(
            board,
            S19K_BM1366_CHIP_ID,
            S19K_BM1366_ASIC_NUM,
            S19K_BM1366_MIDSTATE_NUMBER,
            false,
            S19K_BM1366_BAUD_HZ,
            S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
            S19K_BM1366_INC_FREQ_DELAY_MS,
            S19K_BM1366_VOLTAGE_ADJUST_STEP,
            S19K_CTRLBOARD_LM75_ADDRS,
            S19K_GPIO_PWR_EN,
            S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
        )
        .unwrap_or_else(|e| panic!("admit {board}: {e:?}"));
    }

    #[test]
    fn g1_catalog_board_names_and_chip_id() {
        for board in S19K_BM1366_NOPIC_BOARD_NAMES {
            admit_ok(board);
        }
        assert_eq!(
            AsicProtocolIdentity::from_chip_id(S19K_BM1366_CHIP_ID),
            Some(AsicProtocolIdentity::Bm1366)
        );
        assert!(matches!(
            admit_s19k_bm1366_nopic_skeleton(
                S21_BM1368_FIXTURE_BOARD_NAME,
                S19K_BM1366_CHIP_ID,
                S19K_BM1366_ASIC_NUM,
                S19K_BM1366_MIDSTATE_NUMBER,
                false,
                S19K_BM1366_BAUD_HZ,
                S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
                S19K_BM1366_INC_FREQ_DELAY_MS,
                S19K_BM1366_VOLTAGE_ADJUST_STEP,
                S19K_CTRLBOARD_LM75_ADDRS,
                S19K_GPIO_PWR_EN,
                S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
            ),
            Err(S19kBm1366NopicAdmitError::S21FixtureBoardNameForbidden)
        ));
        assert!(matches!(
            admit_s19k_bm1366_nopic_skeleton(
                "BHB56902",
                0x1368,
                S19K_BM1366_ASIC_NUM,
                S19K_BM1366_MIDSTATE_NUMBER,
                false,
                S19K_BM1366_BAUD_HZ,
                S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
                S19K_BM1366_INC_FREQ_DELAY_MS,
                S19K_BM1366_VOLTAGE_ADJUST_STEP,
                S19K_CTRLBOARD_LM75_ADDRS,
                S19K_GPIO_PWR_EN,
                S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
            ),
            Err(S19kBm1366NopicAdmitError::ChipIdMismatch { observed: 0x1368 })
        ));
    }

    #[test]
    fn g1_bhb56903_admits_like_56902() {
        // Lead GO 2026-08-11: HashSource topol twin of 56902 (BM1366 / 77 / 11x7).
        // PT Config*56903* was omitted; product topol chain.pic must NOT authorize PIC owners.
        admit_ok("BHB56903");
        assert!(S19K_BM1366_NOPIC_BOARD_NAMES.contains(&"BHB56903"));
        assert!(matches!(
            admit_s19k_bm1366_nopic_skeleton(
                S21_BM1368_FIXTURE_BOARD_NAME,
                S19K_BM1366_CHIP_ID,
                S19K_BM1366_ASIC_NUM,
                S19K_BM1366_MIDSTATE_NUMBER,
                false,
                S19K_BM1366_BAUD_HZ,
                S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
                S19K_BM1366_INC_FREQ_DELAY_MS,
                S19K_BM1366_VOLTAGE_ADJUST_STEP,
                S19K_CTRLBOARD_LM75_ADDRS,
                S19K_GPIO_PWR_EN,
                S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
            ),
            Err(S19kBm1366NopicAdmitError::S21FixtureBoardNameForbidden)
        ));
    }

    #[test]
    fn g1_geometry_is_77_equals_11_by_7() {
        assert_eq!(
            u16::from(S19K_BM1366_VOLTAGE_DOMAINS) * u16::from(S19K_BM1366_CHIPS_PER_DOMAIN),
            S19K_BM1366_ASIC_NUM
        );
        assert!(matches!(
            admit_s19k_bm1366_nopic_skeleton(
                "BHB56902",
                S19K_BM1366_CHIP_ID,
                76,
                S19K_BM1366_MIDSTATE_NUMBER,
                false,
                S19K_BM1366_BAUD_HZ,
                S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
                S19K_BM1366_INC_FREQ_DELAY_MS,
                S19K_BM1366_VOLTAGE_ADJUST_STEP,
                S19K_CTRLBOARD_LM75_ADDRS,
                S19K_GPIO_PWR_EN,
                S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
            ),
            Err(S19kBm1366NopicAdmitError::GeometryMismatch)
        ));
    }

    #[test]
    fn g2_nopic_fabric_refuses_pic_and_pins_lm75_map() {
        assert!(!S19K_HAS_PIC);
        assert_eq!(S19K_CTRLBOARD_LM75_ADDRS, [0, 4]);
        assert!(matches!(
            admit_s19k_bm1366_nopic_skeleton(
                "BHB56902",
                S19K_BM1366_CHIP_ID,
                S19K_BM1366_ASIC_NUM,
                S19K_BM1366_MIDSTATE_NUMBER,
                true,
                S19K_BM1366_BAUD_HZ,
                S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
                S19K_BM1366_INC_FREQ_DELAY_MS,
                S19K_BM1366_VOLTAGE_ADJUST_STEP,
                S19K_CTRLBOARD_LM75_ADDRS,
                S19K_GPIO_PWR_EN,
                S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
            ),
            Err(S19kBm1366NopicAdmitError::PicOwnerForbidden)
        ));
        let desc = BoardDesc::am3_s19kpro();
        assert_eq!(desc.asic_protocol, AsicProtocolIdentity::Bm1366);
        assert_eq!(desc.voltage_controller, VoltageControllerClass::NoPic);
        assert_eq!(desc.work_engine, WorkEngineKind::SerialWork);
        assert!(!desc.mining_default_enabled);
        assert!(!matches!(
            desc.voltage_controller,
            VoltageControllerClass::DsPic33Ep
                | VoltageControllerClass::Pic16F1704
                | VoltageControllerClass::Pic1704
        ));
    }

    #[test]
    fn nopic_profile_plus_pic_voltage_controller_hard_fails_with_pic_nopic_string() {
        let pic_owners = [
            VoltageControllerClass::Pic16F1704,
            VoltageControllerClass::DsPic33Ep,
            VoltageControllerClass::Pic1704,
            VoltageControllerClass::Bm1396FramedI2c11,
        ];
        for vc in pic_owners {
            let err = admit_s19k_nopic_voltage_controller(vc).expect_err("PIC must hard-fail");
            let msg = err.to_string();
            assert!(
                msg.contains("PIC") && msg.contains("NoPic"),
                "error must mention PIC and NoPic: {msg}"
            );
            assert!(matches!(
                err,
                S19kBm1366NopicAdmitError::VoltageControllerNotNoPic { .. }
            ));
        }
        assert!(matches!(
            admit_s19k_nopic_voltage_controller(VoltageControllerClass::RuntimeDiscovered),
            Err(S19kBm1366NopicAdmitError::VoltageControllerNotNoPic { .. })
        ));
        admit_s19k_nopic_voltage_controller(VoltageControllerClass::NoPic).unwrap();
        admit_s19k_am3_board_desc(&BoardDesc::am3_s19kpro()).unwrap();
        // Mutating a PIC owner onto an otherwise S19k-shaped desc must refuse.
        let mut bad = BoardDesc::am3_s19kpro();
        bad.voltage_controller = VoltageControllerClass::DsPic33Ep;
        let err = admit_s19k_am3_board_desc(&bad).expect_err("PIC BoardDesc must refuse");
        let msg = err.to_string();
        assert!(msg.contains("PIC") && msg.contains("NoPic"), "{msg}");
    }

    #[test]
    fn g3_midstate_eight_not_s21_sixteen() {
        assert_eq!(S19K_BM1366_MIDSTATE_NUMBER, 8);
        assert_ne!(
            S19K_BM1366_MIDSTATE_NUMBER,
            S21_BM1368_FIXTURE_MIDSTATE_NUMBER
        );
        assert!(matches!(
            admit_s19k_bm1366_nopic_skeleton(
                "BHB56902",
                S19K_BM1366_CHIP_ID,
                S19K_BM1366_ASIC_NUM,
                16,
                false,
                S19K_BM1366_BAUD_HZ,
                S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
                S19K_BM1366_INC_FREQ_DELAY_MS,
                S19K_BM1366_VOLTAGE_ADJUST_STEP,
                S19K_CTRLBOARD_LM75_ADDRS,
                S19K_GPIO_PWR_EN,
                S19K_GPIO_PWR_EN_SAFE_OFF_VALUE,
            ),
            Err(S19kBm1366NopicAdmitError::MidstateMustBeEight { observed: 16 })
        ));
    }

    #[test]
    fn g4_g5_baud_and_preopen_defaults() {
        assert_eq!(S19K_BM1366_BAUD_HZ, 3_125_000);
        assert_eq!(S19K_BM1366_HOST_BAUD_HZ, 3_000_000);
        assert_eq!(S19K_BM1366_FASTUART_VALUE, 0x0000_3011);
        assert_eq!(S19K_BM1366_JIG_BAUD_HZ, 12_000_000);
        assert!(admit_s19k_bm1366_stock_baud_pair(
            S19K_BM1366_BAUD_HZ,
            S19K_BM1366_HOST_BAUD_HZ,
            S19K_BM1366_FASTUART_VALUE,
        )
        .is_ok());
        assert!(admit_s19k_bm1366_stock_baud_pair(
            S19K_BM1366_JIG_BAUD_HZ,
            S19K_BM1366_HOST_BAUD_HZ,
            S19K_BM1366_FASTUART_VALUE,
        )
        .is_err());
        assert!(admit_s19k_bm1366_stock_baud_pair(
            S19K_BM1366_BAUD_HZ,
            3_125_000,
            S19K_BM1366_FASTUART_VALUE,
        )
        .is_err());
        assert!(admit_s19k_bm1366_stock_baud_pair(
            S19K_BM1366_BAUD_HZ,
            S19K_BM1366_HOST_BAUD_HZ,
            0x0000_3001,
        )
        .is_err());
        assert_eq!(S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV, 1500);
        assert_eq!(S19K_BM1366_INC_FREQ_DELAY_MS, 100);
        assert_eq!(S19K_BM1366_VOLTAGE_ADJUST_STEP, 10);
        admit_ok("BHB56902");
    }

    #[test]
    fn g6_mining_default_off_autotune_default_on_in_s19k_toml() {
        assert!(S19K_TOML.contains("[mining]"));
        assert!(S19K_TOML.contains("enabled = false"));
        assert!(S19K_TOML.contains("[autotuner]"));
        let mining = S19K_TOML
            .split("[autotuner]")
            .next()
            .expect("mining section precedes autotuner");
        assert!(mining.contains("enabled = false"));
        let autotuner = S19K_TOML
            .split("[autotuner]")
            .nth(1)
            .expect("autotuner section");
        // C3a flip (operator decision 2026-09-01): autotune config is default-ON
        // everywhere; the s19k honesty marker pins that this stays a config
        // posture, not a tuning claim (no tuner runtime on this lane).
        assert!(autotuner.contains("enabled = true"));
        assert!(autotuner.contains("no tuner runtime yet"));
        assert!(autotuner.contains("posture, not a tuning claim"));
        assert!(!BoardDesc::am3_s19kpro().public_beta_install());
    }

    #[test]
    fn fabric_claim_requires_the_separate_native_runtime_owner() {
        const NOPIC_ADMISSION: &str =
            include_str!("../../dcentrald-silicon-profiles/src/s19k_nopic_admission.rs");
        assert!(NOPIC_ADMISSION.contains(
            "pub const S19K_NATIVE_MINING_REFUSAL: &str = \"native BM1366 execution requires the exact runtime owner"
        ));
        assert!(NOPIC_ADMISSION.contains("Self::NativeOwnerRequired => S19K_NATIVE_MINING_REFUSAL"));
        // Single source of truth: the serial engine must not re-inline a
        // drifting copy of the refusal.
        assert!(!SERIAL_MINING.contains("NOT IMPLEMENTED: native BM1366 catalog identities"));
        // Normal exact beta dispatch already requests native cold start;
        // the old lab knob is only an additional diagnostic request.
        assert!(SERIAL_MINING.contains("fn s19k_native_request_from_dispatch("));
        assert!(SERIAL_MINING.contains("DCENT_S19K_NATIVE_COLD_START"));
        assert!(SERIAL_MINING
            .contains("fn s19k_native_cold_start_opt_in_from(raw: Option<&str>) -> bool"));
        assert!(SERIAL_MINING.contains("matches!(raw, Some(\"1\"))"));
    }

    #[test]
    fn gpio437_safeoff_required_before_amlogic_nand_mutation() {
        assert!(INSTALL_SCRIPT.contains("Step 7b/10: GPIO437 PWR_EN SafeOff"));
        assert!(INSTALL_SCRIPT.contains("refusing NAND mutation"));
        let safe = INSTALL_SCRIPT
            .find("Step 7b/10: GPIO437 PWR_EN SafeOff")
            .expect("safeoff");
        let refusal = INSTALL_SCRIPT
            .find("CLEAR_FOR_FLASH=false")
            .expect("immutable flash refusal");
        let flash = INSTALL_SCRIPT
            .find("    flash_erase $ROOTFS_MTD $ROOTFS_OFFSET_HEX $ROOTFS_ERASE_COUNT")
            .expect("flash");
        assert!(
            refusal < safe,
            "fail-closed gate must make the destructive sequence unreachable"
        );
        assert!(safe < flash, "SafeOff must precede destructive flash_erase");
        assert_eq!(S19K_GPIO_PWR_EN, 437);
        assert_eq!(S19K_GPIO_PWR_EN_SAFE_OFF_VALUE, 1);
        assert!(
            crate::s19k_am3_gpio437::refuse_re4c_safe_off_as_am3_s19k_cut(
                S19K_GPIO_PWR_EN_SAFE_OFF_VALUE
            )
            .is_ok()
        );
        assert!(crate::s19k_am3_gpio437::refuse_re4c_safe_off_as_am3_s19k_cut(0).is_err());
        assert!(matches!(
            admit_s19k_bm1366_nopic_skeleton(
                "BHB56902",
                S19K_BM1366_CHIP_ID,
                S19K_BM1366_ASIC_NUM,
                S19K_BM1366_MIDSTATE_NUMBER,
                false,
                S19K_BM1366_BAUD_HZ,
                S19K_BM1366_PRE_OPEN_CORE_VOLTAGE_CV,
                S19K_BM1366_INC_FREQ_DELAY_MS,
                S19K_BM1366_VOLTAGE_ADJUST_STEP,
                S19K_CTRLBOARD_LM75_ADDRS,
                S19K_GPIO_PWR_EN,
                0,
            ),
            Err(S19kBm1366NopicAdmitError::GpioSafeOffContractBroken)
        ));
    }

    #[test]
    fn skeleton_constant_matches_admit_surface() {
        let s = S19K_BM1366_NOPIC_SKELETON;
        admit_s19k_bm1366_stock_baud_pair(s.baud_hz, s.host_baud_hz, s.fast_uart_value).unwrap();
        admit_s19k_bm1366_nopic_skeleton(
            s.board_name,
            s.chip_id,
            s.asic_num,
            s.midstate_number,
            s.has_pic,
            s.baud_hz,
            s.pre_open_core_voltage_cv,
            s.inc_freq_delay_ms,
            s.voltage_adjust_step,
            s.ctrlboard_lm75_addrs,
            s.gpio_pwr_en,
            s.gpio_pwr_en_safe_off_value,
        )
        .unwrap();
    }

    #[test]
    fn am3_s19kpro_not_fused_with_s21_bm1368_constructor() {
        let s19k = BoardDesc::am3_s19kpro();
        let s21 = BoardDesc::am3_s21();
        assert_ne!(s19k.board_target, s21.board_target);
        assert_eq!(s19k.asic_protocol, AsicProtocolIdentity::Bm1366);
        assert_eq!(s21.asic_protocol, AsicProtocolIdentity::Bm1368);
        assert_ne!(s19k, s21);
    }

    #[test]
    fn configs_align_and_tmp_trial_only_aliases_hardened_deployer() {
        assert!(S19K_TOML.contains("model = \"s19k\""));
        assert!(S19K_TOML.contains("serial_chip_count = 77"));
        assert!(S19K_TOML.contains("serial_chip_type = \"BM1366\""));
        assert!(S19K_TOML.contains("serial_device = \"/dev/ttyS2\""));
        // Typed [platform] identity required; FS markers still staged by trial helper.
        assert!(S19K_TOML.lines().any(|l| l.trim() == "[platform]"));
        assert!(S19K_TOML.contains("target = \"am3-aml-s19k\""));
        assert!(S19K_TOML.contains("board_target = \"am3-s19k\""));
        assert!(S19K_TOML.contains("/etc/dcentos/board_target"));
        assert!(S19K_TOML.contains("am3-s19k"));
        assert!(S19K_TOML.contains("NoPic") || S19K_TOML.contains("am3-s19k"));
        assert!(OVERLAY.contains("model = \"s19k\""));
        assert!(OVERLAY.contains("serial_chip_type = \"BM1366\"") || OVERLAY.contains("BM1366"));
        assert!(OVERLAY.contains("serial_chip_count = 77") || OVERLAY.contains("77"));
        assert!(OVERLAY.lines().any(|l| l.trim() == "[platform]"));
        assert!(OVERLAY.contains("/etc/dcentos/board_target") || OVERLAY.contains("am3-s19k"));
        assert!(OVERLAY.contains("serial_device = \"/dev/ttyS2\""));
        assert!(OVERLAY.to_ascii_lowercase().contains("nopic"));
        let host_mining = S19K_TOML.split("[autotuner]").next().expect("host mining");
        assert!(host_mining.contains("enabled = false"));
        let overlay_mining = OVERLAY.split("[autotuner]").next().expect("overlay mining");
        assert!(overlay_mining.contains("enabled = false"));
        assert!(OVERLAY.contains("[autotuner]"));
        let overlay_at = OVERLAY
            .split("[autotuner]")
            .nth(1)
            .expect("overlay autotuner");
        // C3a flip: default-ON with the refuse-never-tune-blind safety contract
        // carried in the same comment block.
        assert!(overlay_at.contains("enabled = true"));
        assert!(overlay_at.contains("to tune blind"));
        assert!(TMP_TRIAL.contains("dcentrald_s19k_tmp_deploy.sh"));
        assert!(TMP_TRIAL.contains("exec \"$SCRIPT_DIR/dcentrald_s19k_tmp_deploy.sh\" \"$@\""));
        for retired_surface in [
            "scp -O",
            "/etc/dcentos",
            "/dev/tty",
            "/sys/class/gpio",
            "serial_chip_count",
            "fw_setenv",
        ] {
            assert!(
                !TMP_TRIAL.contains(retired_surface),
                "compatibility entry point must not reintroduce {retired_surface}"
            );
        }
    }

    #[test]
    fn lm75_before_asic_probe_order_is_enforced() {
        let desc = BoardDesc::am3_s19kpro();
        let mut session = S19kNopicBringupSession::from_am3_board_desc(&desc).unwrap();
        assert_eq!(session.phase(), S19kNopicBringupPhase::AdmittedIdentity);
        let skip = session
            .admit_asic_probe_get_address()
            .expect_err("ASIC probe before LM75 must refuse");
        assert!(matches!(
            skip,
            S19kNopicBringupOrderError::AsicProbeBeforeLm75
        ));
        let msg = skip.to_string();
        assert!(
            msg.contains("LM75") && msg.contains("probe"),
            "order error must mention LM75 and probe: {msg}"
        );

        session
            .record_ctrlboard_lm75_fabric(S19K_CTRLBOARD_LM75_ADDRS)
            .unwrap();
        assert_eq!(session.phase(), S19kNopicBringupPhase::CtrlBoardLm75Fabric);
        session.admit_asic_probe_get_address().unwrap();
        assert_eq!(session.phase(), S19kNopicBringupPhase::AsicProbeGetAddress);

        // Source-order pin: CtrlBoard LM75 phase must appear before AsicProbe in this module.
        let lm75_phase = BETA_SRC
            .find("CtrlBoardLm75Fabric = 1")
            .expect("LM75 phase discriminant");
        let asic_phase = BETA_SRC
            .find("AsicProbeGetAddress = 2")
            .expect("ASIC probe phase discriminant");
        assert!(
            lm75_phase < asic_phase,
            "CtrlBoardLm75Fabric must order before AsicProbeGetAddress in source"
        );
        let lm75_const = BETA_SRC
            .find("S19K_CTRLBOARD_LM75_ADDRS")
            .expect("LM75 addr const");
        let get_address_marker = BETA_SRC
            .find("AsicProbeGetAddress")
            .expect("GetAddress phase name");
        assert!(
            lm75_const < get_address_marker,
            "LM75 fabric constants must be declared before ASIC GetAddress phase"
        );
        assert!(
            (S19kNopicBringupPhase::CtrlBoardLm75Fabric as u8)
                < (S19kNopicBringupPhase::AsicProbeGetAddress as u8)
        );
        // Explicitly not the AM3-BB dsPIC LM75 bridge — CtrlBoard indices only.
        assert!(
            BETA_SRC.contains("not the AM3-BB dsPIC LM75 bridge"),
            "must pin CtrlBoard LM75 path as distinct from AM3-BB dsPIC bridge"
        );
        assert_eq!(S19K_CTRLBOARD_LM75_ADDRS, [0, 4]);
    }
}
