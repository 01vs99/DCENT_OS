//! STM32MP15 / Braiins BCB100 platform scaffold.
//!
//! BCB100 is a Braiins replacement control board for S19-family Antminers.
//! Public hardware docs establish the non-destructive platform identity:
//! STM32MP157-class SoC, 4 GB eMMC, microSD boot, four hashboard connectors,
//! four fan headers, and direct SoC I/O rather than a Bitmain FPGA.
//!
//! This module is intentionally conservative. The public files do not expose
//! a live-proved map for hashboard reset, plug detect, fan PWM/tach, PSU
//! control, or PIC bus ownership. Until a bench BCB100 probe captures those
//! facts, construction is gated behind `DCENT_BCB100_ACCEPT_UNVERIFIED=1`,
//! fan/GPIO control returns an error, and per-chain PIC addresses are unset.
//!
//! I2C discovery is also unavailable. The generic raw/service `ReadBytes`
//! paths select a slave with controller-affecting ioctl policy and may recover
//! an errored backend by dropping/reopening it; raw EEPROM reads additionally
//! depend on an unproven current pointer. None is a no-FORCE/no-recovery
//! observation contract. [`Platform::open_i2c`] therefore always refuses on
//! BCB100. The explicitly lab-gated serial passthrough is separate from this
//! I2C boundary and grants no I2C, GPIO, fan, PSU, or voltage authority.

use std::fs;
use std::path::Path;
use std::sync::Mutex;

use super::config::{
    probe_tty_chain_device, ChainConfig, ChainTransport, PlatformConfig, VoltageControllerKind,
};
use super::{BoardType, ChainAccess, FanAccess, GpioAccess, Platform};
use crate::i2c::I2cBus;
use crate::serial::SerialChain;
use crate::{HalError, Result};

/// Lab-only acceptance gate for constructing the BCB100 HAL.
pub const BCB100_ACCEPT_UNVERIFIED_ENV: &str = "DCENT_BCB100_ACCEPT_UNVERIFIED";

/// Candidate STM32MP15 Linux UART device names for the four BCB100 chain ports.
///
/// Source status: DERIVED FROM BRAIINS' OWN DEVICE TREE, not a DCENT live pin
/// probe. The `aliases` node of the `ii1-am2` DTB
/// (`model = "Braiins STM32MP157C (ii1-am2) Control Board"`, extracted
/// 2026-08-12 to )
/// fixes the `/dev/ttySTMn` numbering exactly:
///
/// | alias    | node             | peripheral | role                   |
/// |----------|------------------|------------|------------------------|
/// | serial0  | `0x40010000`     | UART4      | **Linux debug console**|
/// | serial1  | `0x4000f000`     | USART3     | chain A / HB0          |
/// | serial2  | `0x40011000`     | UART5      | chain B / HB1          |
/// | serial3  | `0x40018000`     | UART7      | chain C / HB2          |
/// | serial4  | `0x40019000`     | UART8      | chain D / HB3          |
///
/// So the chain ports are `ttySTM1..4`, and this array is index-aligned with
/// [`board_map::CHAINS`] (USART3/UART5/UART7/UART8).
///
/// CORRECTED 2026-08-12: the previous value was `ttySTM0..3`, which was wrong in
/// both directions — it would have opened `ttySTM0` (the **debug console**) as
/// chain A, and it omitted `ttySTM4` (HB3) entirely. Do not "simplify" this back
/// to a 0-based range.
///
/// This resolves the ordering the module docs flagged as UNRESOLVED, but it is
/// still DT-derived, not probed: keep using these for lab discovery /
/// passthrough only, never for cold-boot reset or voltage.
pub const BCB100_CANDIDATE_CHAIN_UARTS: [&str; 4] = [
    "/dev/ttySTM1",
    "/dev/ttySTM2",
    "/dev/ttySTM3",
    "/dev/ttySTM4",
];

/// Standard hashboard EEPROM deny range used across BHB42xxx/BHB56xxx boards.
///
/// Retained as the immutable BCB100 policy boundary for any future exact
/// transport; no BCB100 I2C handle is currently exposed.
pub const BCB100_HASHBOARD_EEPROM_DENYLIST: [u8; 8] =
    [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

/// Returns true when a DT-compatible or CPU-info blob names STM32MP15.
pub fn compatible_bytes_look_like_stm32mp15(data: &[u8]) -> bool {
    let haystack = String::from_utf8_lossy(data).to_ascii_lowercase();
    haystack.contains("stm32mp15") || haystack.contains("stm32mp157")
}

fn read_bytes(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_default()
}

fn env_flag(name: &str) -> bool {
    dcentrald_common::lab_env::var(name)
        .map(|v| {
            matches!(
                v.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

/// Host signature for STM32MP15-class boards, including BCB100.
pub fn looks_like_bcb100_host() -> bool {
    let compatible = read_bytes("/proc/device-tree/compatible");
    let compatible_alt = read_bytes("/sys/firmware/devicetree/base/compatible");
    let cpuinfo = read_bytes("/proc/cpuinfo");

    compatible_bytes_look_like_stm32mp15(&compatible)
        || compatible_bytes_look_like_stm32mp15(&compatible_alt)
        || compatible_bytes_look_like_stm32mp15(&cpuinfo)
        || BCB100_CANDIDATE_CHAIN_UARTS
            .iter()
            .any(|path| Path::new(path).exists())
}

fn tty_candidates_for_chain(chain: &ChainConfig) -> Vec<String> {
    let declared = match &chain.transport {
        ChainTransport::Serial { device, .. } => device.clone(),
        _ => return Vec::new(),
    };
    let Some(default) = BCB100_CANDIDATE_CHAIN_UARTS.get(chain.chain_id as usize) else {
        return vec![declared];
    };
    if declared == *default {
        vec![declared]
    } else {
        vec![declared, (*default).to_string()]
    }
}

/// Braiins BCB100 / STM32MP15 platform.
pub struct Bcb100Platform {
    config: PlatformConfig,
}

impl Bcb100Platform {
    pub fn new() -> Result<Self> {
        if !looks_like_bcb100_host() {
            return Err(HalError::Platform(
                "BCB100: no STM32MP15 or ttySTM signature found".to_string(),
            ));
        }

        if !env_flag(BCB100_ACCEPT_UNVERIFIED_ENV) {
            return Err(HalError::Platform(format!(
                "BCB100/STM32MP15 detected but disabled: set {}=1 only for lab discovery. \
                 GPIO, fan, PSU, and PIC maps are not live-verified.",
                BCB100_ACCEPT_UNVERIFIED_ENV
            )));
        }

        tracing::warn!(
            env = BCB100_ACCEPT_UNVERIFIED_ENV,
            "BCB100 platform scaffold enabled for lab discovery; cold boot is not wired"
        );
        Ok(Self {
            config: PlatformConfig::bcb100_s19_lab(),
        })
    }

    #[cfg(test)]
    fn with_config(config: PlatformConfig) -> Self {
        Self { config }
    }
}

impl Platform for Bcb100Platform {
    fn board_type(&self) -> BoardType {
        BoardType::Stm32Mp15
    }

    fn chain_count(&self) -> u8 {
        self.config.chains.len() as u8
    }

    fn open_chain(&self, chain_id: u8) -> Result<Box<dyn ChainAccess>> {
        let chain_config = self
            .config
            .chains
            .iter()
            .find(|c| c.chain_id == chain_id)
            .ok_or_else(|| HalError::Platform(format!("chain {} not configured", chain_id)))?;

        match &chain_config.transport {
            ChainTransport::Serial { device, baud } => {
                let candidates = tty_candidates_for_chain(chain_config);
                let candidate_refs: Vec<&str> = candidates.iter().map(String::as_str).collect();
                let label = format!("bcb100-chain-{}", chain_id);
                let resolved =
                    probe_tty_chain_device(&candidate_refs, &label).unwrap_or_else(|| {
                        tracing::warn!(
                            chain = chain_id,
                            declared = %device,
                            "BCB100 tty probe failed; trying declared device directly"
                        );
                        device.clone()
                    });
                let serial = SerialChain::open(&resolved, *baud).map_err(|e| {
                    HalError::Platform(format!(
                        "BCB100 chain {}: open {} failed ({}). Stop bosminer first or use a read-only probe.",
                        chain_id, resolved, e
                    ))
                })?;
                Ok(Box::new(Bcb100ChainAccess {
                    serial: Mutex::new(serial),
                }))
            }
            other => Err(HalError::Platform(format!(
                "unexpected transport for BCB100 chain {}: {:?}",
                chain_id, other
            ))),
        }
    }

    fn open_i2c(&self, bus: u8) -> Result<I2cBus> {
        Err(HalError::Platform(format!(
            "BCB100: Platform::open_i2c({bus}) is disabled; held evidence proves no exact no-FORCE/no-recovery read-only transport"
        )))
    }

    fn open_fan(&self) -> Result<Box<dyn FanAccess>> {
        Err(HalError::Fan(
            "BCB100 fan PWM/tach map is not live-verified; refusing fan control".to_string(),
        ))
    }

    fn open_gpio(&self) -> Result<Box<dyn GpioAccess>> {
        Err(HalError::Platform(
            "BCB100 GPIO reset/plug map is not live-verified; refusing GPIO control".to_string(),
        ))
    }

    fn voltage_controller(&self) -> VoltageControllerKind {
        // The lab config's legacy informational value is not discovery
        // evidence. Do not expose a controller protocol until a typed BCB100
        // endpoint has been observed without write-side probing.
        VoltageControllerKind::NoPic
    }
}

struct Bcb100ChainAccess {
    serial: Mutex<SerialChain>,
}

impl ChainAccess for Bcb100ChainAccess {
    fn send_command(&self, data: &[u8]) -> Result<()> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.write_bytes(data)
    }

    fn read_response(&self, buf: &mut [u8]) -> Result<usize> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.read_bytes(buf)
    }

    fn send_work(&self, data: &[u8]) -> Result<()> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.write_bytes(data)
    }

    fn read_nonce(&self, buf: &mut [u8]) -> Result<usize> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.read_bytes(buf)
    }

    fn set_baud(&self, baud: u32) -> Result<()> {
        let mut serial = self
            .serial
            .lock()
            .map_err(|_| HalError::Platform("serial mutex poisoned".into()))?;
        serial.set_baud(baud)
    }

    fn wait_for_nonce(&self) -> Result<()> {
        std::thread::yield_now();
        Ok(())
    }
}

/// BCB100 STM32MP157 board map — netlist-derived STATIC wiring (data, not drive).
///
/// Source of record: the published **CERN-OHL-S** BCB100 hardware design held at
///  (a mirror of github.com/braiins/BCB100), namely
/// the IPC-2581 netlist `FAB-…/IPC-2581 Files/BRR_CB_P03_REV_A1_1-STM32MP157.cvg`
/// joined to `SRC-…/MPU.SchDoc`, as derived in
/// .
/// This is Braiins' own OPEN-SOURCE control board — the map is a hardware FACT
/// (net → BGA ball → STM32 pin), not RE of a proprietary binary.
///
/// STATIC net→pin assignments are HIGH confidence and encoded here as data so the
/// STM32MP15 HAL can consume them once the DYNAMIC half is live-confirmed.
///
/// A second, INDEPENDENT source landed 2026-08-12: Braiins' own `ii1-am2` device
/// tree, extracted from the bootable image in the third-party `BCB100_Mujina`
/// repo and preserved at
///
/// (`model = "Braiins STM32MP157C (ii1-am2) Control Board"`). It **confirms every
/// static pin fact above** via a different path than the IPC-2581 netlist, and it
/// closed two of the four DYNAMIC cells:
///   * `/dev/ttySTMn` ⇄ chain index ordering — RESOLVED (DT `aliases`; chains are
///     `ttySTM1..4`, `ttySTM0` is the debug console). See
///     [`BCB100_CANDIDATE_CHAIN_UARTS`].
///   * PWM **TIMx channel** — RESOLVED (TIM1_CH4 / TIM2_CH3). PWM **period** is
///     still unresolved.
///
/// Still UNRESOLVED, and still deliberately NOT encoded as drive behavior:
/// per-chain reset **active polarity** (not derivable — the net has no pull,
/// inverter, or buffer), the PWM **period**, and every rail/electrical value.
/// Note the DT is Braiins' configuration, not a measurement: it proves what their
/// software drives, not what the silicon does.
///
/// Consistent with the load-bearing rule that an unknown board never inherits a
/// drive envelope, `open_gpio()`/`open_fan()` stay fail-closed until a live probe
/// confirms those cells — this module gives the map, never a blind pulse.
pub mod board_map {
    /// One hashboard chain's static wiring. All fields are HIGH-confidence net→pin
    /// facts from the IPC-2581 netlist; the reset field's ACTIVE POLARITY is NOT a
    /// fact here — it is UNRESOLVED and must never be pulsed blind.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ChainPins {
        /// STM32 UART peripheral driving this chain (e.g. "USART3"). Direct 3.3 V
        /// LVCMOS to the connector — no RS-485 transceiver, no FPGA.
        pub uart_peripheral: &'static str,
        /// TX pin name (e.g. "PD8").
        pub tx_pin: &'static str,
        /// RX pin name (e.g. "PD9").
        pub rx_pin: &'static str,
        /// Per-chain reset GPIO (output). ACTIVE POLARITY UNRESOLVED — never pulse blind.
        ///
        /// Re-confirmed UNRESOLVED 2026-08-12: each `HBn_RESET` net has exactly two
        /// nodes (SoC pin ⇄ connector) with no pull, inverter, or buffer anywhere in
        /// the schematic, so polarity is **not** derivable from the hardware package.
        /// A third-party fork asserts "active-low"; that is unsupported by any
        /// engineering data we hold. Keep `open_gpio()` fail-closed until measured.
        pub reset_gpio: &'static str,
        /// Per-chain plug-detect GPIO (input). 4k7 pull-**DOWN** (`R87A`–`R87D`) ⇒
        /// **active-HIGH**: a populated slot drives the line high, and an empty slot
        /// reads low.
        ///
        /// CORRECTED 2026-08-12 (was "4k7 pull to switched 3V3" — wrong direction).
        /// Source: schematic text layer of
        /// …/Schematic Prints.PDF`. Not yet
        /// DMM-verified.
        pub plug_detect_gpio: &'static str,
        /// Per-chain 3V3 logic load-switch enable (TPS22919 `ON`, active-HIGH).
        ///
        /// ⚠️ CORRECTED 2026-08-12 — SAFETY-RELEVANT. This previously read
        /// "Default OFF", which is **backwards**: each `HB_PWR_CTL` line carries a
        /// 4k7 pull-**UP** into an active-high enable, so hashboard logic power is
        /// **ON by default** at power-on and whenever the SoC pin is left floating
        /// (reset, pre-userspace, crashed daemon). Do not assume a cold board is
        /// unpowered. Drive OFF explicitly to de-energize; still assert OFF on
        /// teardown/fault.
        ///
        /// Source: schematic text layer of
        /// …/Schematic Prints.PDF`. Not yet
        /// DMM-verified — treat "may already be ON" as the safe assumption either way.
        pub logic_enable_gpio: &'static str,
    }

    /// The four hashboard chains A/B/C/D (index = chain slot). Netlist peripherals:
    /// USART3(A) / UART5(B) / UART7(C) / UART8(D).
    /// (`2026-05-21-bcb100-board-map-paper-re.md` §"Hashboard chains".)
    pub const CHAINS: [ChainPins; 4] = [
        ChainPins {
            uart_peripheral: "USART3",
            tx_pin: "PD8",
            rx_pin: "PD9",
            reset_gpio: "PD10",
            plug_detect_gpio: "PD4",
            logic_enable_gpio: "PD15",
        },
        ChainPins {
            uart_peripheral: "UART5",
            tx_pin: "PB6",
            rx_pin: "PB5",
            reset_gpio: "PF9",
            plug_detect_gpio: "PG10",
            logic_enable_gpio: "PG12",
        },
        ChainPins {
            uart_peripheral: "UART7",
            tx_pin: "PE8",
            rx_pin: "PE7",
            reset_gpio: "PF8",
            plug_detect_gpio: "PE10",
            logic_enable_gpio: "PE15",
        },
        ChainPins {
            uart_peripheral: "UART8",
            tx_pin: "PE1",
            rx_pin: "PE0",
            reset_gpio: "PE11",
            plug_detect_gpio: "PE13",
            logic_enable_gpio: "PG14",
        },
    ];

    /// I2C1 = single shared hashboard EEPROM/sensor bus (all 4 chains,
    /// address-multiplexed; the 0x50–0x57 write-denylist applies here).
    pub const I2C1_HASHBOARD_SCL_PIN: &str = "PD12";
    /// I2C1 SDA (shared hashboard bus).
    pub const I2C1_HASHBOARD_SDA_PIN: &str = "PD13";
    /// I2C2 = PSU comm bus only.
    pub const I2C2_PSU_SCL_PIN: &str = "PD7";
    /// I2C2 SDA (PSU comm).
    pub const I2C2_PSU_SDA_PIN: &str = "PG15";

    /// Linux bus number for the shared hashboard bus (STM32 peripheral **I2C1**).
    ///
    /// The STM32 peripheral number is NOT the Linux bus number. Braiins' `ii1-am2`
    /// DT `aliases` pin it: `i2c0 = i2c@40012000` (I2C1) and `i2c1 = i2c@40013000`
    /// (I2C2). Reading `I2C1_*` as `/dev/i2c-1` is an off-by-one that would talk to
    /// the PSU bus instead of the hashboard EEPROMs.
    pub const I2C_LINUX_BUS_HASHBOARD: u8 = 0;
    /// Linux bus number for the PSU bus (STM32 peripheral **I2C2**).
    ///
    /// ⚠️ In Braiins' shipped `ii1-am2` DTB this node is `status = "disabled"`, so
    /// `/dev/i2c-1` does **not** exist on that image — any PSU client targeting it
    /// fails at open. A DCENT_OS device tree must enable I2C2 before PSU control is
    /// possible. (Observed 2026-08-12 in `evidence-bcb100-ii1-am2.dts`.)
    pub const I2C_LINUX_BUS_PSU: u8 = 1;

    /// Fan PWM duty GROUP A pin — drives headers CON1 **and** CON2 (open-drain via
    /// 2N7002, INVERTED at the FET). Timer channel: **TIM1_CH4** (see
    /// [`FAN_PWM_GROUP_A_TIMER`]). Period/frequency still UNRESOLVED.
    pub const FAN_PWM_GROUP_A_PIN: &str = "PE14";
    /// Fan PWM duty GROUP B pin — drives CON3 **and** CON4. Same inversion caveat.
    /// Timer channel: **TIM2_CH3** (see [`FAN_PWM_GROUP_B_TIMER`]).
    pub const FAN_PWM_GROUP_B_PIN: &str = "PB10";

    /// Timer/channel behind [`FAN_PWM_GROUP_A_PIN`] (`PE14` alternate function).
    ///
    /// Resolved 2026-08-12: `timer@44000000` (TIM1) has its `pwm` child `okay` with
    /// a pinctrl group in Braiins' `ii1-am2` DTB, and `PE14` is TIM1_CH4 on
    /// STM32MP15. Channel only — the PWM **period** is still UNRESOLVED, and the
    /// 2N7002 inversion means duty must be complemented before it reaches the fan.
    pub const FAN_PWM_GROUP_A_TIMER: &str = "TIM1_CH4";
    /// Timer/channel behind [`FAN_PWM_GROUP_B_PIN`] (`PB10` alternate function).
    /// `timer@40000000` (TIM2) `pwm` is likewise `okay`; `PB10` is TIM2_CH3.
    /// Same period-unresolved and inversion caveats as group A.
    pub const FAN_PWM_GROUP_B_TIMER: &str = "TIM2_CH3";
    /// The four independent fan tach inputs (CON1..CON4). Capture timer UNRESOLVED.
    pub const FAN_TACH_PINS: [&str; 4] = ["PA5", "PA0", "PA3", "PA6"];

    /// PSU master enable GPIO (`PWR_CONTROL`). Treat as the "hash power" gate;
    /// default OFF, assert OFF on teardown/fault.
    pub const PSU_PWR_CONTROL_PIN: &str = "PD5";

    /// Linux debug console UART (PA12/PA11) — NOT a chain port. Present so callers
    /// know one `/dev/ttySTMn` is the console, so chain-count ≠ ttySTM-node count.
    pub const DEBUG_CONSOLE_UART: &str = "UART4";

    /// The static chain wiring for chain `idx` (0..3), fail-closed for anything else.
    ///
    /// `idx` is the schematic chain slot A/B/C/D. It is NOT a `/dev/ttySTM` index,
    /// but the two are now index-ALIGNED: the DT supplied the mapping this comment
    /// used to say was missing, and slot `idx` is served by
    /// `BCB100_CANDIDATE_CHAIN_UARTS[idx]` (= `/dev/ttySTM{idx + 1}`, because
    /// `ttySTM0` is the Linux debug console). Keep the two arrays in the same order.
    pub fn chain(idx: u8) -> Option<ChainPins> {
        CHAINS.get(idx as usize).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stm32mp15_signature_handles_nul_separated_compatible() {
        assert!(compatible_bytes_look_like_stm32mp15(
            b"st,stm32mp157c-ii1\0st,stm32mp157\0"
        ));
        assert!(compatible_bytes_look_like_stm32mp15(
            b"Hardware\t: STM32MP15"
        ));
        assert!(!compatible_bytes_look_like_stm32mp15(b"am33xx"));
    }

    #[test]
    fn bcb100_with_config_reports_lab_board_type() {
        let platform = Bcb100Platform::with_config(PlatformConfig::bcb100_s19_lab());
        assert_eq!(platform.board_type(), BoardType::Stm32Mp15);
        assert_eq!(platform.chain_count(), 4);
        assert!(matches!(
            platform.voltage_controller(),
            VoltageControllerKind::NoPic
        ));
    }

    #[test]
    fn generic_platform_i2c_is_always_denied_before_open() {
        let platform = Bcb100Platform::with_config(PlatformConfig::bcb100_s19_lab());
        for bus in [0, 1, 2, u8::MAX] {
            let error = match platform.open_i2c(bus) {
                Ok(_) => panic!("BCB100 generic I2C unexpectedly opened bus {bus}"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(message.contains("Platform::open_i2c"));
            assert!(message.contains("no-FORCE/no-recovery read-only transport"));
        }
    }

    #[test]
    fn bcb100_exposes_no_i2c_discovery_and_retains_eeprom_policy() {
        assert_eq!(
            BCB100_HASHBOARD_EEPROM_DENYLIST,
            [0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57]
        );
        let source = include_str!("stm32mp15.rs");
        let forbidden_method = ["pub fn open_i2c", "_discovery"].concat();
        let forbidden_capability = ["Bcb100", "ReadOnlyI2c"].concat();
        let public_test_constructor = ["pub fn ", "with_config"].concat();
        assert!(!source.contains(&forbidden_method));
        assert!(!source.contains(&forbidden_capability));
        assert!(!source.contains(&public_test_constructor));
        assert!(source.contains("#[cfg(test)]\n    fn with_config"));
    }

    #[test]
    fn bcb100_board_map_matches_ipc2581_netlist() {
        use board_map::*;
        // Byte-exact vs 2026-05-21-bcb100-board-map-paper-re.md §"Hashboard chains"
        // (IPC-2581 BRR_CB_P03_REV_A1_1-STM32MP157.cvg ⋈ MPU.SchDoc).
        assert_eq!(CHAINS.len(), 4);
        assert_eq!(CHAINS[0].uart_peripheral, "USART3");
        assert_eq!((CHAINS[0].tx_pin, CHAINS[0].rx_pin), ("PD8", "PD9"));
        assert_eq!(CHAINS[1].uart_peripheral, "UART5");
        assert_eq!(
            (CHAINS[2].uart_peripheral, CHAINS[3].uart_peripheral),
            ("UART7", "UART8")
        );
        // Per-chain reset / plug / 3V3-enable GPIOs (A/B/C/D).
        assert_eq!(
            [
                CHAINS[0].reset_gpio,
                CHAINS[1].reset_gpio,
                CHAINS[2].reset_gpio,
                CHAINS[3].reset_gpio
            ],
            ["PD10", "PF9", "PF8", "PE11"]
        );
        assert_eq!(
            [
                CHAINS[0].plug_detect_gpio,
                CHAINS[1].plug_detect_gpio,
                CHAINS[2].plug_detect_gpio,
                CHAINS[3].plug_detect_gpio
            ],
            ["PD4", "PG10", "PE10", "PE13"]
        );
        assert_eq!(
            [
                CHAINS[0].logic_enable_gpio,
                CHAINS[1].logic_enable_gpio,
                CHAINS[2].logic_enable_gpio,
                CHAINS[3].logic_enable_gpio
            ],
            ["PD15", "PG12", "PE15", "PG14"]
        );
        // Bus split: I2C1 = shared hashboard bus, I2C2 = PSU.
        assert_eq!(
            (I2C1_HASHBOARD_SCL_PIN, I2C1_HASHBOARD_SDA_PIN),
            ("PD12", "PD13")
        );
        assert_eq!((I2C2_PSU_SCL_PIN, I2C2_PSU_SDA_PIN), ("PD7", "PG15"));
        // Fan: 2 PWM groups + 4 tach; PSU master enable.
        assert_eq!((FAN_PWM_GROUP_A_PIN, FAN_PWM_GROUP_B_PIN), ("PE14", "PB10"));
        assert_eq!(FAN_TACH_PINS, ["PA5", "PA0", "PA3", "PA6"]);
        assert_eq!(PSU_PWR_CONTROL_PIN, "PD5");
        assert_eq!(DEBUG_CONSOLE_UART, "UART4");
        // Accessor is fail-closed past the 4 real chains.
        assert_eq!(chain(0), Some(CHAINS[0]));
        assert_eq!(chain(3), Some(CHAINS[3]));
        assert_eq!(chain(4), None);
    }

    #[test]
    fn bcb100_map_encodes_data_only_drive_stays_fail_closed() {
        // The static map exists, but the DYNAMIC half is unresolved, so the
        // platform's drive accessors MUST still refuse (never pulse blind).
        let platform = Bcb100Platform::with_config(PlatformConfig::bcb100_s19_lab());
        assert!(
            platform.open_gpio().is_err(),
            "GPIO drive must stay fail-closed until polarity is live-verified"
        );
        assert!(
            platform.open_fan().is_err(),
            "fan PWM must stay fail-closed until TIM channel/polarity is live-verified"
        );
        assert!(matches!(
            platform.voltage_controller(),
            VoltageControllerKind::NoPic
        ));
        assert!(platform
            .config
            .chains
            .iter()
            .all(|chain| chain.pic_address.is_none()));
    }
}
