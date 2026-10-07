//! Platform configuration — eliminates hardcoded S9 constants.
//!
//! Each platform provides its hardware configuration at init time.
//! This replaces the `const` values in daemon.rs with a runtime-configurable
//! structure that each Platform implementation populates.
//!
//! For Zynq S9: chains [6,7,8], PICs at [0x55,0x56,0x57], UIO-based
//! For Zynq S17/S17e: chains [6,7,8], dsPIC33 at [0x20,0x21,0x22], UIO-based
//! For Zynq S17+/T17/T17+: chains [6,7,8], PIC16 at [0x50,0x51,0x52], UIO-based
//! For Amlogic S21: chains [0,1,2], NO PICs, serial /dev/ttyS1, /dev/ttyS2,
//! /dev/ttyS4 (ttyS3 is not a chain UART on the verified S21 AXG DTB)
//! For Amlogic S19k: chains [0,1,2], NO PICs, serial /dev/ttyS1, /dev/ttyS2,
//! /dev/ttyS3 (ttyS4 is an S21 path and is refused for S19k)
//! For CVitek S19k: chains [0,1,2], PICs at [0x50,0x51,0x52], serial + uart_trans
//! For Braiins BCB100: STM32MP15 / Cortex-A7, direct Linux UART. GPIO, fan,
//! PSU, and PIC mapping are not live-verified yet, so the default config is
//! lab-only and intentionally avoids static PIC/GPIO addresses.

use serde::{Deserialize, Serialize};

/// Probe a list of candidate tty device paths in priority order. Returns
/// the first one that exists AND can be opened for read+write. Logs the
/// resolved path with `tracing::info!`. Returns `None` if no candidate
/// is openable.
///
/// Candidate order is platform-specific: S21 retains its historical AXG
/// fallback, while S19k is restricted to the held ttyS3 endpoint so a missing
/// node fails closed instead of opening the S21-only ttyS4 path.
///
///  W10-E (2026-05-06): converts a silent-failure drift into a
/// self-diagnostic boot log.
pub fn probe_tty_chain_device(candidates: &[&str], chain_label: &str) -> Option<String> {
    for path in candidates {
        if std::path::Path::new(path).exists() {
            // Try a non-blocking open to confirm it's a real device.
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(_) => {
                    tracing::info!(
                        chain = %chain_label,
                        device = %path,
                        candidates = ?candidates,
                        "Wave-10 W10-E: tty chain device resolved via runtime probe"
                    );
                    return Some((*path).to_string());
                }
                Err(e) => {
                    tracing::debug!(
                        chain = %chain_label,
                        device = %path,
                        error = %e,
                        "tty candidate failed to open; trying next"
                    );
                }
            }
        }
    }
    tracing::warn!(
        chain = %chain_label,
        candidates = ?candidates,
        "Wave-10 W10-E: no tty chain device probed successfully"
    );
    None
}

/// Per-chain hardware configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    /// Chain identifier (e.g., 6/7/8 for S9, 0/1/2 for S21).
    pub chain_id: u8,

    /// Transport type for ASIC communication.
    pub transport: ChainTransport,

    /// PIC I2C address for this chain's voltage controller (None for NoPic models like S21).
    pub pic_address: Option<u8>,

    /// I2C bus number for PIC communication.
    pub i2c_bus: u8,

    /// GPIO pin for hash board plug detect (None if not available).
    pub plug_detect_gpio: Option<u32>,

    /// GPIO pin for hash board reset/enable (None if not available).
    pub enable_gpio: Option<u32>,
}

/// Chain transport mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainTransport {
    /// Zynq FPGA UIO: specify UIO base number, 4 UIO devices per chain.
    /// (common=base, cmd=base+1, work_rx=base+2, work_tx=base+3)
    /// Used on S9 where the FPGA handles both commands and work.
    FpgaUio { uio_base: u8 },

    /// Zynq hybrid: PL UART (NS16550A) for ASIC commands + FPGA UIO for work.
    ///
    /// The S19/S17+ Zynq platform has BOTH:
    ///   - PL UARTs (ttyS1-4) at 0x4100x000 for ASIC command/control
    ///   - FPGA work engine (UIO) at 0x43Cx0000 for mining work dispatch
    ///
    /// This transport uses the serial port for commands (register read/write,
    /// chip enumeration) and the FPGA UIO devices for work-tx/work-rx.
    ZynqHybrid {
        /// Serial device for ASIC commands (e.g., "/dev/ttyS1").
        cmd_device: String,
        /// Initial baud rate for commands (115200 for enumeration).
        cmd_baud: u32,
        /// UIO base number for FPGA work engine (common, cmd-rx, work-rx, work-tx).
        /// On S19: chain1=uio0, chain2=uio4, chain3=uio8, chain4=uio12.
        uio_base: u8,
    },

    /// Standard Linux serial port (BeagleBone /dev/ttyO*, Amlogic /dev/ttyS*).
    /// Commands and work share the same UART. No FPGA.
    Serial { device: String, baud: u32 },

    /// CVitek uart_trans kernel module.
    UartTrans { device: String, baud: u32 },

    /// Stock Bitmain FPGA: single flat register space for ALL chains.
    ///
    /// Unlike FpgaUio (BraiinsOS per-chain UIO devices), the stock FPGA uses:
    ///   - /dev/axi_fpga_dev (major 245) for 352-byte register block at 0x43C00000
    ///   - /dev/fpga_mem (major 244) for a 16 MB DMA buffer at the
    ///     RAM-dependent stock base (0x0F000000/0x1F000000/0x3F000000)
    ///   - BC_WRITE_COMMAND register for ASIC commands (broadcast to chains)
    ///   - DHASH accelerator + DMA for work dispatch (all chains simultaneously)
    ///   - Shared RETURN_NONCE FIFO for nonce collection
    ///   - FPGA IIC_COMMAND register for PIC I2C (no /dev/i2c-*)
    ///
    /// The stock_chain_id is the Bitmain chain numbering (5, 6, 7) which maps
    /// to physical connectors (J6, J7, J8) -- different from BraiinsOS's 6, 7, 8.
    StockFpga {
        /// Stock Bitmain chain ID (5, 6, or 7).
        /// Maps to HASH_ON_PLUG bit position for board detection.
        stock_chain_id: u8,
    },
}

/// S21 AXG chain-2 UART order. `/dev/ttyS4` is the documented third chain
/// UART on the verified S21 DTB; `/dev/ttyS3` remains a fallback.
pub const AMLOGIC_CHAIN2_TTY_CANDIDATES: [&str; 2] = ["/dev/ttyS4", "/dev/ttyS3"];
/// S19k `a lab unit` dmesg: meson ttyS1+S2+S3 are the hash UARTs. ttyS4 is the
/// S21 AXG third port, not the S19k third hash UART.
pub const S19K_AMLOGIC_CHAIN2_TTY_CANDIDATES: [&str; 1] = ["/dev/ttyS3"];

/// Candidate serial devices for an Amlogic chain in priority order.
pub fn amlogic_tty_candidate_order(chain: &ChainConfig) -> Vec<String> {
    let declared = match &chain.transport {
        ChainTransport::Serial { device, .. } => device.as_str(),
        _ => return Vec::new(),
    };

    match chain.chain_id {
        2 if declared == "/dev/ttyS1" => vec![declared.to_string()],
        2 => {
            let prefs: &[&str] = if declared == "/dev/ttyS3" {
                &S19K_AMLOGIC_CHAIN2_TTY_CANDIDATES
            } else {
                &AMLOGIC_CHAIN2_TTY_CANDIDATES
            };
            prefs
                .iter()
                .map(|candidate| (*candidate).to_string())
                .collect()
        }
        _ => vec![declared.to_string()],
    }
}

/// Fan controller configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FanConfig {
    /// Fan access method.
    pub method: FanMethod,
    /// Number of fans to control.
    pub fan_count: u8,
}

/// Fan control method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FanMethod {
    /// Zynq FPGA fan controller via UIO.
    FpgaUio { uio_number: u8 },
    /// Linux sysfs hwmon PWM (typical for Amlogic/CVitek).
    SysfsPwm { hwmon_path: String, pwm_channel: u8 },
    /// GPIO-based fan control (bit-bang PWM).
    Gpio { pwm_gpio: u32, tach_gpio: u32 },
}

/// Complete platform hardware configuration.
///
/// This is the runtime-configurable version of what used to be hardcoded
/// `const` values in daemon.rs. Each Platform implementation provides this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Human-readable platform name.
    pub name: String,

    /// Per-chain hardware configuration.
    pub chains: Vec<ChainConfig>,

    /// Fan controller configuration.
    pub fan: FanConfig,

    /// Whether this platform has PIC voltage controllers.
    /// S9/S17/S19: true. S21/S21 Pro: false (NoPic).
    pub has_pic: bool,

    /// PIC firmware expected type (stock bmminer vs BraiinsOS).
    /// Relevant only when has_pic = true.
    pub pic_type: PicType,

    /// Voltage control method for NoPic platforms.
    pub voltage_control: VoltageControl,

    /// XADC/ADC availability for die temperature and voltage monitoring.
    pub has_xadc: bool,

    /// Architecture (for cross-compilation and binary compatibility).
    pub arch: Architecture,

    /// Informational voltage-controller classification. This is not an
    /// energization capability; mutating services should consume a
    /// `crate::platform::VoltageControllerEndpoint` issued from discovery.
    /// Missing serialized data defaults to `NoPic` so schema drift cannot
    /// silently select dsPIC wire bytes.
    #[serde(default = "default_voltage_controller")]
    pub voltage_controller: VoltageControllerKind,
}

/// Fail-closed serde default for legacy configs without controller identity.
fn default_voltage_controller() -> VoltageControllerKind {
    VoltageControllerKind::NoPic
}

/// PIC microcontroller type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PicType {
    /// Source-bound classic AML application protocol; this names a dialect,
    /// not an inferred MCU part or permission to use a generic PIC driver.
    ClassicAmlFw89,
    /// Microchip PIC16F1704 (S9, S17+, S19).
    Pic16F1704,
    /// Microchip dsPIC33EP16GS202 (S17, S17e only).
    DsPic33EP16GS202,
    /// No PIC on hash board (S21, S21 Pro).
    NoPic,
}

/// Voltage-controller kind selected for the runtime hashboard.
///
/// W2A.2 / W10 PIC1704 wire-up (2026-05-09): platforms expose the observed
/// controller family for compatibility and telemetry without hardcoding board
/// names. This enum is not authority to construct a mutating service.
///
/// This is **runtime-classified** by `crate::platform::subtype` from a
/// combination of `/etc/subtype` and an `i2cdetect 0x20` ACK probe — the
/// stored value is the result of that classification, not a static platform
/// default. Missing or contradictory evidence projects to `NoPic`; new
/// service construction consumes an opaque discovery-bound endpoint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VoltageControllerKind {
    /// Exact retained classic AML fw89 application and APW12 composition.
    /// Generic subtype discovery and legacy mutating services cannot mint it.
    ClassicAmlFw89,
    /// PIC1704-class voltage controller at I²C 0x20. Used by the
    /// BHB42XXX hashboard family across CV1835, AM335x BB, and Amlogic
    /// (S19j Pro variants). See `dcentrald-asic::pic1704`.
    Pic1704,
    /// dsPIC33EP16GS202 family on exact model-scoped x17/x19 routes. This
    /// kind does not authorize S21 or any other catalog-wide association.
    Dspic33Ep,
    /// PIC16F1704 (S9 stock + BraiinsOS BM1387 hashboards).
    Pic16f1704,
    /// Fail-closed no-PIC classification. Some exact Amlogic S21 routes use a
    /// non-PIC voltage controller, but this fallback is not proof of its type,
    /// endpoint, or mutation authority.
    NoPic,
}

impl VoltageControllerKind {
    /// Short descriptor for tracing logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            VoltageControllerKind::ClassicAmlFw89 => "classic-aml-fw89",
            VoltageControllerKind::Pic1704 => "pic1704",
            VoltageControllerKind::Dspic33Ep => "dspic33ep",
            VoltageControllerKind::Pic16f1704 => "pic16f1704",
            VoltageControllerKind::NoPic => "nopic",
        }
    }
}

/// Voltage control method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoltageControl {
    /// PIC I2C DAC (S9/S17+/T17/T17+). Voltage = (1608.42 - pic_val) / 170.42.
    PicDac,
    /// dsPIC33EP digital voltage controller on x17/x19-class hashboards.
    DsPic,
    /// TPS546D24A PMBus buck converter (BitAxe/Mujina).
    PmBus { address: u8 },
    /// No voltage command is described by the profile; tuning may vary only
    /// frequency. This is not a claim about the physical regulator topology.
    FrequencyOnly,
    /// Direct I2C DAC on control board (some S19 XP).
    I2cDac { address: u8 },
}

/// Source-level capability ceiling for voltage controller/method identities.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VoltageCapabilityState {
    /// An implementation/descriptor exists, but exact construction and safe
    /// runtime composition are model-scoped elsewhere.
    SourceAbstractionModelScoped,
    /// A fail-closed absence/fallback identity, not a physical-controller
    /// assertion.
    NoControllerFallback,
}

/// Exact, non-authorizing capability record for one controller kind.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct VoltageControllerKindCapability {
    pub kind: VoltageControllerKind,
    pub state: VoltageCapabilityState,
    pub implementation: &'static str,
    pub construction_authorized: bool,
    pub runtime_admission_authorized: bool,
    pub mutation_authorized: bool,
}

/// Exact, non-authorizing capability record for one [`VoltageControl`] method
/// family. Data-bearing addresses remain caller/profile values and are not
/// admitted by this registry.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct VoltageControlMethodCapability {
    pub method: &'static str,
    pub state: VoltageCapabilityState,
    pub implementation_scope: &'static str,
    pub endpoint_identity_verified: bool,
    pub runtime_admission_authorized: bool,
    pub mutation_authorized: bool,
}

/// Exhaustive capability ceiling for [`VoltageControllerKind`].
pub const VOLTAGE_CONTROLLER_KIND_CAPABILITIES: &[VoltageControllerKindCapability] = &[
    VoltageControllerKindCapability {
        kind: VoltageControllerKind::Pic1704,
        state: VoltageCapabilityState::SourceAbstractionModelScoped,
        implementation: "dcentrald_asic::pic1704",
        construction_authorized: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
    VoltageControllerKindCapability {
        kind: VoltageControllerKind::Dspic33Ep,
        state: VoltageCapabilityState::SourceAbstractionModelScoped,
        implementation: "dcentrald_asic::dspic",
        construction_authorized: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
    VoltageControllerKindCapability {
        kind: VoltageControllerKind::Pic16f1704,
        state: VoltageCapabilityState::SourceAbstractionModelScoped,
        implementation: "dcentrald_asic::pic",
        construction_authorized: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
    VoltageControllerKindCapability {
        kind: VoltageControllerKind::NoPic,
        state: VoltageCapabilityState::NoControllerFallback,
        implementation: "fail-closed fallback",
        construction_authorized: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
];

/// Exhaustive capability ceiling for the five [`VoltageControl`] variants.
pub const VOLTAGE_CONTROL_METHOD_CAPABILITIES: &[VoltageControlMethodCapability] = &[
    VoltageControlMethodCapability {
        method: "PicDac",
        state: VoltageCapabilityState::SourceAbstractionModelScoped,
        implementation_scope: "profile descriptor for PIC DAC control",
        endpoint_identity_verified: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
    VoltageControlMethodCapability {
        method: "DsPic",
        state: VoltageCapabilityState::SourceAbstractionModelScoped,
        implementation_scope: "profile descriptor for dsPIC control",
        endpoint_identity_verified: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
    VoltageControlMethodCapability {
        method: "PmBus",
        state: VoltageCapabilityState::SourceAbstractionModelScoped,
        implementation_scope: "data-bearing PMBus descriptor",
        endpoint_identity_verified: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
    VoltageControlMethodCapability {
        method: "FrequencyOnly",
        state: VoltageCapabilityState::NoControllerFallback,
        implementation_scope: "no voltage-command descriptor",
        endpoint_identity_verified: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
    VoltageControlMethodCapability {
        method: "I2cDac",
        state: VoltageCapabilityState::SourceAbstractionModelScoped,
        implementation_scope: "data-bearing I2C DAC descriptor",
        endpoint_identity_verified: false,
        runtime_admission_authorized: false,
        mutation_authorized: false,
    },
];

/// Target CPU architecture.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Architecture {
    /// ARM Cortex-A9, armv7, hardfloat (Zynq 7010).
    Armv7Hf,
    /// ARM Cortex-A53, aarch64 (Amlogic A113D, CVitek CV1835).
    Aarch64,
    /// ARM Cortex-A8, armv7, hardfloat (BeagleBone AM335x).
    Armv7HfBbb,
    /// STM32MP15 dual Cortex-A7, armv7 hard-float (Braiins BCB100).
    Armv7HfStm32Mp15,
}

// ─── Default configurations for known platforms ───

impl PlatformConfig {
    /// Antminer S9 on stock Bitmain firmware (stock FPGA bitstream).
    ///
    /// Uses the stock Bitmain FPGA register interface (/dev/axi_fpga_dev)
    /// instead of BraiinsOS UIO devices. No BraiinsOS boot components required.
    ///
    /// Key differences from s9_zynq():
    ///   - Transport: StockFpga (single register block) instead of FpgaUio (per-chain UIO)
    ///   - Chain IDs: 5, 6, 7 (stock numbering) instead of 6, 7, 8 (BraiinsOS)
    ///   - I2C: Via FPGA IIC_COMMAND register, not /dev/i2c-0 or AXI IIC
    ///   - Fan: Via FPGA FAN_CONTROL register, not UIO fan controller
    ///   - Work: DMA double-buffer, not per-chain FIFO
    ///   - Kernel: 3.14.0-xilinx with bitmain_axi.ko + fpga_mem_driver.ko
    ///
    /// PIC I2C addresses are the same (0x55-0x57) -- the PICs don't care which
    /// FPGA bitstream is loaded, only the access method differs.
    pub fn s9_stock() -> Self {
        Self {
            name: "Antminer S9 (Stock Bitmain FPGA)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 5,
                    transport: ChainTransport::StockFpga { stock_chain_id: 5 },
                    pic_address: Some(0x55),
                    i2c_bus: 0,             // Not used -- I2C via FPGA register
                    plug_detect_gpio: None, // Plug detect via FPGA HASH_ON_PLUG register
                    enable_gpio: None,      // Board reset via FPGA RESET_HASHBOARD register
                },
                ChainConfig {
                    chain_id: 6,
                    transport: ChainTransport::StockFpga { stock_chain_id: 6 },
                    pic_address: Some(0x56),
                    i2c_bus: 0,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
                ChainConfig {
                    chain_id: 7,
                    transport: ChainTransport::StockFpga { stock_chain_id: 7 },
                    pic_address: Some(0x57),
                    i2c_bus: 0,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
            ],
            fan: FanConfig {
                // Stock FPGA has built-in fan control at register 0x084.
                // No UIO device -- will need a StockFpga fan method.
                // For now, use GPIO placeholder since there's no FanMethod::StockFpga yet.
                method: FanMethod::Gpio {
                    pwm_gpio: 0,
                    tach_gpio: 0,
                },
                fan_count: 2,
            },
            has_pic: true,
            pic_type: PicType::Pic16F1704,
            voltage_control: VoltageControl::PicDac,
            has_xadc: true,
            arch: Architecture::Armv7Hf,
            voltage_controller: VoltageControllerKind::Pic16f1704,
        }
    }

    /// Antminer S9 on Zynq XC7Z010 (BraiinsOS boot).
    pub fn s9_zynq() -> Self {
        Self {
            name: "Antminer S9 (Zynq)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 6,
                    transport: ChainTransport::FpgaUio { uio_base: 1 },
                    pic_address: Some(0x55),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(902),
                    enable_gpio: Some(893),
                },
                ChainConfig {
                    chain_id: 7,
                    transport: ChainTransport::FpgaUio { uio_base: 5 },
                    pic_address: Some(0x56),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(903),
                    enable_gpio: Some(894),
                },
                ChainConfig {
                    chain_id: 8,
                    transport: ChainTransport::FpgaUio { uio_base: 9 },
                    pic_address: Some(0x57),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(904),
                    enable_gpio: Some(895),
                },
            ],
            fan: FanConfig {
                method: FanMethod::FpgaUio { uio_number: 0 },
                fan_count: 2,
            },
            has_pic: true,
            pic_type: PicType::Pic16F1704,
            voltage_control: VoltageControl::PicDac,
            has_xadc: true,
            arch: Architecture::Armv7Hf,
            voltage_controller: VoltageControllerKind::Pic16f1704,
        }
    }

    /// Antminer S19 on Zynq XC7Z010/XC7Z020 (am2-s17 control board, BraiinsOS boot).
    ///
    /// FPGA-only transport variant. Uses the FPGA cmd FIFO for ASIC commands,
    /// same approach as S9. This works with the BraiinsOS FPGA bitstream which
    /// provides both cmd FIFOs and work FIFOs.
    ///
    /// The S19 reuses the S17 control board ("am2-s17" platform). Key differences from S9:
    /// - 4 FPGA chain slots (1-indexed: chain1-4), but only 3 physical hash boards
    /// - UIO layout: 0-3=chain1, 4-7=chain2, 8-11=chain3, 12-15=chain4, 16=fan, 17=board-ctrl, 18=glitch
    /// - dsPIC I2C addresses: 0x20/0x21/0x22. Firmware IDs such as
    ///   0x88/0x89/0xB9/0xFE are version bytes, not bus addresses.
    /// - 76 BM1398 chips per hash board (vs S9's 63 BM1387)
    /// - Voltage: 13.8V default (vs S9's ~9.1V), range 11940-15140 mV
    /// - GPIO: plug detect at gpio902-905 (4 pins), reset at gpio897-901
    ///
    /// Source: Live probe of S19 at 203.0.113.80 running BraiinsOS+ 24.09.1
    pub fn s19_zynq() -> Self {
        Self {
            name: "Antminer S19 (Zynq am2-s17)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 1,
                    transport: ChainTransport::FpgaUio { uio_base: 0 },
                    pic_address: Some(0x20),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(902),
                    enable_gpio: Some(897),
                },
                ChainConfig {
                    chain_id: 2,
                    transport: ChainTransport::FpgaUio { uio_base: 4 },
                    pic_address: Some(0x21),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(903),
                    enable_gpio: Some(898),
                },
                ChainConfig {
                    chain_id: 3,
                    transport: ChainTransport::FpgaUio { uio_base: 8 },
                    pic_address: Some(0x22),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(904),
                    enable_gpio: Some(899),
                },
                // Chain 4 exists in FPGA but S19 only has 3 physical hash board slots.
                // Included for completeness — will be skipped if no board detected.
                ChainConfig {
                    chain_id: 4,
                    transport: ChainTransport::FpgaUio { uio_base: 12 },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: Some(905),
                    enable_gpio: Some(900),
                },
            ],
            fan: FanConfig {
                method: FanMethod::FpgaUio { uio_number: 16 },
                fan_count: 4,
            },
            has_pic: true,
            pic_type: PicType::DsPic33EP16GS202,
            voltage_control: VoltageControl::DsPic,
            has_xadc: true,
            arch: Architecture::Armv7Hf,
            voltage_controller: VoltageControllerKind::Dspic33Ep,
        }
    }

    /// Antminer S19 on Zynq — hybrid serial+FPGA transport.
    ///
    /// Uses PL NS16550A UARTs (/dev/ttyS1-4) for ASIC command/control and
    /// FPGA UIO work engine for mining work dispatch. This matches BraiinsOS's
    /// native approach on the am2-s17 platform.
    ///
    /// PL UART addresses (from live probe):
    ///   ttyS1: 0x41001000 (chain 1), base_baud 6,249,999 Hz
    ///   ttyS2: 0x41011000 (chain 2)
    ///   ttyS3: 0x41021000 (chain 3)
    ///   ttyS4: 0x41031000 (chain 4)
    ///
    /// FPGA work engine UIO addresses:
    ///   chain1: uio0-3  @ 0x43C00000
    ///   chain2: uio4-7  @ 0x43C10000
    ///   chain3: uio8-11 @ 0x43C20000
    ///   chain4: uio12-15 @ 0x43C30000
    ///
    /// Source: Live probe of S19 at 203.0.113.80, BraiinsOS+ 24.09.1
    pub fn s19_zynq_hybrid() -> Self {
        Self {
            name: "Antminer S19 (Zynq hybrid serial+FPGA)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 1,
                    transport: ChainTransport::ZynqHybrid {
                        cmd_device: "/dev/ttyS1".to_string(),
                        cmd_baud: 115200,
                        uio_base: 0,
                    },
                    pic_address: Some(0x20),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(902),
                    enable_gpio: Some(897),
                },
                ChainConfig {
                    chain_id: 2,
                    transport: ChainTransport::ZynqHybrid {
                        cmd_device: "/dev/ttyS2".to_string(),
                        cmd_baud: 115200,
                        uio_base: 4,
                    },
                    pic_address: Some(0x21),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(903),
                    enable_gpio: Some(898),
                },
                ChainConfig {
                    chain_id: 3,
                    transport: ChainTransport::ZynqHybrid {
                        cmd_device: "/dev/ttyS3".to_string(),
                        cmd_baud: 115200,
                        uio_base: 8,
                    },
                    pic_address: Some(0x22),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(904),
                    enable_gpio: Some(899),
                },
                ChainConfig {
                    chain_id: 4,
                    transport: ChainTransport::ZynqHybrid {
                        cmd_device: "/dev/ttyS4".to_string(),
                        cmd_baud: 115200,
                        uio_base: 12,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: Some(905),
                    enable_gpio: Some(900),
                },
            ],
            fan: FanConfig {
                method: FanMethod::FpgaUio { uio_number: 16 },
                fan_count: 4,
            },
            has_pic: true,
            pic_type: PicType::DsPic33EP16GS202,
            voltage_control: VoltageControl::DsPic,
            has_xadc: true,
            arch: Architecture::Armv7Hf,
            voltage_controller: VoltageControllerKind::Dspic33Ep,
        }
    }

    fn x17_zynq_with_controller(
        name: &str,
        pic_addrs: [u8; 3],
        pic_type: PicType,
        voltage_control: VoltageControl,
        voltage_controller: VoltageControllerKind,
    ) -> Self {
        Self {
            name: name.to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 6,
                    transport: ChainTransport::FpgaUio { uio_base: 1 },
                    pic_address: Some(pic_addrs[0]),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(897),
                    enable_gpio: Some(902),
                },
                ChainConfig {
                    chain_id: 7,
                    transport: ChainTransport::FpgaUio { uio_base: 5 },
                    pic_address: Some(pic_addrs[1]),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(898),
                    enable_gpio: Some(903),
                },
                ChainConfig {
                    chain_id: 8,
                    transport: ChainTransport::FpgaUio { uio_base: 9 },
                    pic_address: Some(pic_addrs[2]),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(899),
                    enable_gpio: Some(904),
                },
            ],
            fan: FanConfig {
                method: FanMethod::FpgaUio { uio_number: 12 },
                fan_count: 2,
            },
            has_pic: true,
            pic_type,
            voltage_control,
            has_xadc: true,
            arch: Architecture::Armv7Hf,
            voltage_controller,
        }
    }

    /// Antminer S17/S17e on Zynq (BraiinsOS boot).
    ///
    /// S17 and S17e use dsPIC33EP hashboard controllers. Do not reuse the
    /// PIC16 S17+/T17 path for these SKUs; voltage writes are protocol-specific.
    pub fn s17_zynq() -> Self {
        Self::x17_zynq_with_controller(
            "Antminer S17/S17e (Zynq dsPIC)",
            [0x20, 0x21, 0x22],
            PicType::DsPic33EP16GS202,
            VoltageControl::DsPic,
            VoltageControllerKind::Dspic33Ep,
        )
    }

    /// Antminer S17+ on Zynq (BraiinsOS boot).
    pub fn s17plus_zynq() -> Self {
        Self::x17_zynq_with_controller(
            "Antminer S17+ (Zynq PIC16)",
            [0x50, 0x51, 0x52],
            PicType::Pic16F1704,
            VoltageControl::PicDac,
            VoltageControllerKind::Pic16f1704,
        )
    }

    /// Antminer T17 on Zynq (BraiinsOS boot).
    pub fn t17_zynq() -> Self {
        Self::x17_zynq_with_controller(
            "Antminer T17 (Zynq PIC16)",
            [0x50, 0x51, 0x52],
            PicType::Pic16F1704,
            VoltageControl::PicDac,
            VoltageControllerKind::Pic16f1704,
        )
    }

    /// Antminer T17+ on Zynq (BraiinsOS boot).
    pub fn t17plus_zynq() -> Self {
        Self::x17_zynq_with_controller(
            "Antminer T17+ (Zynq PIC16)",
            [0x50, 0x51, 0x52],
            PicType::Pic16F1704,
            VoltageControl::PicDac,
            VoltageControllerKind::Pic16f1704,
        )
    }

    /// Antminer S19K Pro NoPic on Amlogic A113D (am3-aml).
    ///
    /// Live-verified from `a lab unit` (BraiinsOS+ 25.07-plus, 2026-04-29):
    /// - Model: "Antminer S19K Pro NoPic" (per `/etc/bosminer.toml`).
    /// - Chip: BM1366, 77 chips/chain × 3 chains.
    /// - 0x50/0x51/0x52 on i2c-1 are AT24 EEPROMs (NOT PICs).
    /// - Chain UARTs are /dev/ttyS1, /dev/ttyS2, /dev/ttyS3 (`a lab unit` dmesg).
    ///   `/dev/ttyS4` is the S21 AXG third port, not the S19k third hash UART.
    /// - Voltage: TAS5782M kernel-managed at i2c-0 0x49/0x4A/0x4B (DTB).
    /// - PSU: APW121215f (fw=0x76) on i2c-1.
    /// - Temp: LM75BCCnCopy on i2c-1 (inlets 0x48-0x4A, outlets 0x4C-0x4E).
    /// - UART paths are logical endpoints, not physical slot identities. Held
    ///   `.88` has ttyS1 answering while plug GPIO439/slot0 is absent, so the
    ///   per-chain physical GPIO fields stay `None` until ASIC-side EEPROM
    ///   identity supplies a unique tty-to-slot binding.
    pub fn s19k_amlogic() -> Self {
        Self {
            name: "Antminer S19K Pro NoPic (Amlogic)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 0,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyS1".to_string(),
                        baud: 115200,
                    },
                    pic_address: None, // NoPic — TAS5782M kernel-managed
                    i2c_bus: 1,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
                ChainConfig {
                    chain_id: 1,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyS2".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 1,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
                // S19k Pro NoPic Amlogic chain-2 device:
                // `a lab unit` dmesg: meson ttyS3 @ ff804000 irq 14 is a hash UART
                // (bosminer 0→9600→115200). ttyS4 is the S21 AXG third port.
                ChainConfig {
                    chain_id: 2,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyS3".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 1,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
            ],
            fan: FanConfig {
                method: FanMethod::SysfsPwm {
                    hwmon_path: "/sys/class/hwmon/hwmon0".to_string(),
                    pwm_channel: 0,
                },
                fan_count: 4,
            },
            has_pic: false,
            pic_type: PicType::NoPic,
            voltage_control: VoltageControl::FrequencyOnly,
            has_xadc: false,
            arch: Architecture::Aarch64,
            // S19K Pro NoPic on am3-aml: voltage is TAS5782M kernel-managed,
            // no per-hashboard PIC. Frequency-only voltage envelope.
            voltage_controller: VoltageControllerKind::NoPic,
        }
    }

    /// Antminer S21 on Amlogic A113D (NoPic).
    pub fn s21_amlogic() -> Self {
        Self {
            name: "Antminer S21 (Amlogic)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 0,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyS3".to_string(),
                        baud: 115200,
                    },
                    pic_address: None, // NoPic!
                    i2c_bus: 0,
                    plug_detect_gpio: Some(439),
                    enable_gpio: Some(454),
                },
                ChainConfig {
                    chain_id: 1,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyS2".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: Some(440),
                    enable_gpio: Some(455),
                },
                // Exact held production physical1/2/3 -> ttyS3/ttyS2/ttyS1.
                // first, ttyS3 as a legacy fallback. The candidate order is
                // pinned by `amlogic_tty_candidate_order()` host tests.
                ChainConfig {
                    chain_id: 2,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyS1".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: Some(441),
                    enable_gpio: Some(456),
                },
            ],
            fan: FanConfig {
                method: FanMethod::SysfsPwm {
                    hwmon_path: "/sys/class/hwmon/hwmon0".to_string(),
                    pwm_channel: 0,
                },
                fan_count: 4,
            },
            has_pic: false,
            pic_type: PicType::NoPic,
            voltage_control: VoltageControl::FrequencyOnly,
            has_xadc: false,
            arch: Architecture::Aarch64,
            // Native runtime voltage is programmed by its retained GPIO APW owner.
            voltage_controller: VoltageControllerKind::NoPic,
        }
    }

    /// Exact production AML backend used by the S21 Pro BM1370 profile.
    /// Physical slots0/1/2 route to ttyS3/2/1, independently of chip count.
    pub fn s21pro_amlogic() -> Self {
        let mut config = Self::s21_amlogic();
        config.name = "Antminer S21 Pro (Amlogic)".to_string();
        config
    }

    pub fn s21xp_amlogic() -> Self {
        let mut config = Self::s21_amlogic();
        config.name = "Antminer S21 XP (Amlogic)".to_string();
        config
    }

    /// Exact modern AM3 production registry0x767090/0x86452c.
    /// NoPic denotes the runtime voltage owner; optional board PICs are unused.
    pub fn s19xp_amlogic() -> Self {
        let mut config = Self::s21_amlogic();
        config.name = "Antminer S19 XP (Amlogic)".to_string();
        config
    }

    pub fn s19jxp_amlogic() -> Self {
        let mut config = Self::s21_amlogic();
        config.name = "Antminer S19j XP (Amlogic)".to_string();
        config
    }

    /// Independently traced BM1362 AM3 registry: three UART/reset routes,
    /// GPIO437 active-low PSU owner, direct LM75 sensor translation. Classic
    /// PIC-controlled BHB42601/21/41 must not resolve through these profiles.
    pub fn s19jproa_amlogic() -> Self {
        let mut config = Self::s21_amlogic();
        config.name = "Antminer S19j Pro A (Amlogic)".to_string();
        config
    }

    /// R10 exact AM3 registry key3, UART86452c, PIC bus0/address physical+1f,
    /// protected factory bus1 and independent GPIO437 raw1-off. Construction
    /// is metadata only; ClassicAmlPowerOwner admits current physical custody.
    pub fn s19jpro_classic_amlogic() -> Self {
        let mut config = Self::s21_amlogic();
        config.name = "Antminer S19j Pro classic (Amlogic fw89 PIC)".into();
        config.has_pic = true;
        config.pic_type = PicType::ClassicAmlFw89;
        config.voltage_controller = VoltageControllerKind::ClassicAmlFw89;
        // Generic frequency/voltage adapters do not own the exact APW12/PIC
        // composition. Only the native runtime may alter its shared rail.
        config.voltage_control = VoltageControl::FrequencyOnly;
        for chain in &mut config.chains {
            chain.pic_address = Some(0x20 + chain.chain_id);
            chain.i2c_bus = 0;
        }
        config
    }

    pub fn s19jproplus_amlogic() -> Self {
        let mut config = Self::s21_amlogic();
        config.name = "Antminer S19j Pro+ (Amlogic)".to_string();
        config
    }

    /// Antminer S19j Pro on BeagleBone AM335x (BHB42601 hashboards, BM1362).
    ///
    /// Live-verified from .79 (Stock Bitmain Dec 2022, kernel 3.8.13+, 2026-04-29):
    /// - Hardware: TI AM335x BeagleBone Black control board (no FPGA).
    /// - Hashboards: 3× BHB42601 with BM1362 chips, 126 chips/chain @ 545 MHz.
    /// - 4 ASIC UARTs available on board: /dev/ttyO1, ttyO2, ttyO4, ttyO5.
    ///   ttyO3 is DISABLED in the BB DTB (verbatim per VNish FW RE doc §3.1).
    /// - S19j Pro 3-board variant populates chains 0-2 (ttyO1/2/4); chain 3
    ///   (ttyO5) is reserved for 4-board SKUs.
    /// - Single I2C bus: /dev/i2c-0 (i2c-1 is unbound on stock BB).
    /// - Voltage controller: dsPIC33EP16GS202 at I2C 0x20/0x21/0x22 (same chip
    ///   family as am2 — BHB42xxx series uses dsPIC across both Zynq and BB
    ///   carrier boards).
    /// - Pinout (from /etc/init.d/S70cgminer on .79):
    ///     PLUG0..3: GPIO 51/48/47/44 (input, active HIGH)
    ///     RST0..3:  GPIO 5/4/27/22 (output, default HIGH = running)
    ///     PSU_EN:   GPIO 65 (output, HIGH after PSU init)
    ///     LEDs:     GPIO 23 (green), GPIO 45 (red)
    ///     Fan PWM:  pwm1 (EHRPWM0B / P9_29, front), pwm2 (ECAP2_PWM2 / P9_28, rear)
    ///               both 100 µs period (10 kHz)
    ///     Fan tach: GPIO 7/20/110/112 (falling-edge IRQ)
    ///
    /// Source:
    ///         STOCK_BITMAIN_BB_DEEP_INTEL.md, S70cgminer init script verbatim.
    pub fn s19j_beaglebone() -> Self {
        Self {
            name: "Antminer S19j Pro (BeagleBone AM335x)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 0,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyO1".to_string(),
                        baud: 115200,
                    },
                    pic_address: Some(0x20),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(51),
                    enable_gpio: Some(5),
                },
                ChainConfig {
                    chain_id: 1,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyO2".to_string(),
                        baud: 115200,
                    },
                    pic_address: Some(0x21),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(48),
                    enable_gpio: Some(4),
                },
                ChainConfig {
                    chain_id: 2,
                    transport: ChainTransport::Serial {
                        // ttyO3 is disabled in BB DTB; chain 2 wired to ttyO4 (UART5).
                        device: "/dev/ttyO4".to_string(),
                        baud: 115200,
                    },
                    pic_address: Some(0x22),
                    i2c_bus: 0,
                    plug_detect_gpio: Some(47),
                    enable_gpio: Some(27),
                },
                // Chain 3 (ttyO5) — 4-board SKUs only. Skipped if no board detected.
                ChainConfig {
                    chain_id: 3,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttyO5".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: Some(44),
                    enable_gpio: Some(22),
                },
            ],
            fan: FanConfig {
                // BB has 4 fans (2 front + 2 rear) on 2 PWM channels (pwm1/pwm2).
                // Period 100000 ns (10 kHz) per S70cgminer; tach via GPIO falling-edge IRQ.
                method: FanMethod::SysfsPwm {
                    hwmon_path: "/sys/class/pwm/pwmchip0".to_string(),
                    pwm_channel: 1, // pwm1 = front fans; pwm2 mirrored in fan impl
                },
                fan_count: 4,
            },
            has_pic: true,
            // BM1362 hashboards use dsPIC33EP16GS202 (same as am2 S19j Pro).
            pic_type: PicType::DsPic33EP16GS202,
            voltage_control: VoltageControl::DsPic,
            has_xadc: false,
            arch: Architecture::Armv7HfBbb,
            // BBCtrl_BHB42XXX uses PIC1704 in the new BraiinsOS+/DCENT_OS path
            // when subtype detection + 0x20 ACK probe both pass at runtime.
            // The static default keeps the existing dsPIC path so production
            // s19jpro (sustained-mining unit running existing dsPIC code)
            // is never silently re-routed without an explicit subtype probe.
            // The runtime classification in `crate::platform::subtype` is what
            // upgrades a BHB42XXX BB unit to `Pic1704`.
            voltage_controller: VoltageControllerKind::Dspic33Ep,
        }
    }

    /// Braiins BCB100 replacement control board for S19-family Antminers.
    ///
    /// Status: lab scaffold only. Public BCB100 materials identify the SoC
    /// (STM32MP157), eMMC/SD boot shape, four hashboard connectors, four fan
    /// headers, and OpenWrt target family. They do not publish a DCENT-safe
    /// live pin map for hashboard reset, plug detect, fan PWM/tach, PSU
    /// control, or PIC bus/address ownership. Keep those destructive surfaces
    /// unset until a bench BCB100 probe captures them.
    ///
    /// UART names come from the `aliases` node of Braiins' own `ii1-am2` device
    /// tree (extracted 2026-08-12; see
    /// `dcentrald_hal::platform::stm32mp15::BCB100_CANDIDATE_CHAIN_UARTS`).
    /// Chains are `ttySTM1..4`; `ttySTM0` is the Linux **debug console** and must
    /// never be opened as a chain. Still suitable for discovery and warm
    /// passthrough experiments only, not cold boot.
    ///
    /// `i2c_bus: 0` is likewise the DT-confirmed Linux number for the shared
    /// hashboard EEPROM bus (STM32 peripheral I2C1) — not peripheral number 1.
    pub fn bcb100_s19_lab() -> Self {
        Self {
            name: "Braiins BCB100 S19-family (STM32MP15, lab)".to_string(),
            chains: vec![
                ChainConfig {
                    chain_id: 0,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttySTM1".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
                ChainConfig {
                    chain_id: 1,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttySTM2".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
                ChainConfig {
                    chain_id: 2,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttySTM3".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
                ChainConfig {
                    chain_id: 3,
                    transport: ChainTransport::Serial {
                        device: "/dev/ttySTM4".to_string(),
                        baud: 115200,
                    },
                    pic_address: None,
                    i2c_bus: 0,
                    plug_detect_gpio: None,
                    enable_gpio: None,
                },
            ],
            fan: FanConfig {
                method: FanMethod::SysfsPwm {
                    hwmon_path: "/sys/class/hwmon".to_string(),
                    pwm_channel: 0,
                },
                fan_count: 4,
            },
            has_pic: true,
            pic_type: PicType::DsPic33EP16GS202,
            voltage_control: VoltageControl::DsPic,
            has_xadc: false,
            arch: Architecture::Armv7HfStm32Mp15,
            voltage_controller: VoltageControllerKind::Dspic33Ep,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classic_aml_profile_retains_exact_pic_routes_without_inheriting_nopic_or_pic1704() {
        let config = PlatformConfig::s19jpro_classic_amlogic();
        assert_eq!(
            config.voltage_controller,
            VoltageControllerKind::ClassicAmlFw89
        );
        assert_eq!(config.pic_type, PicType::ClassicAmlFw89);
        assert!(config.has_pic);
        assert_eq!(config.chains.len(), 3);
        for (slot, (chain, uart)) in config
            .chains
            .iter()
            .zip(["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"])
            .enumerate()
        {
            assert_eq!(chain.chain_id, slot as u8);
            assert_eq!(chain.pic_address, Some(0x20 + slot as u8));
            assert_eq!(chain.i2c_bus, 0);
            assert!(
                matches!(&chain.transport, ChainTransport::Serial { device, baud }
                if device == uart && *baud == 115200)
            );
        }
    }

    #[test]
    fn missing_serialized_controller_identity_defaults_to_nopic() {
        assert_eq!(default_voltage_controller(), VoltageControllerKind::NoPic);
    }

    #[test]
    fn s19k_amlogic_is_nopic_with_kernel_managed_voltage() {
        let cfg = PlatformConfig::s19k_amlogic();
        assert!(!cfg.has_pic, "S19K Pro NoPic must declare has_pic=false");
        assert!(
            matches!(cfg.pic_type, PicType::NoPic),
            "pic_type must be NoPic, got {:?}",
            cfg.pic_type
        );
        assert!(
            matches!(cfg.voltage_control, VoltageControl::FrequencyOnly),
            "voltage_control must be FrequencyOnly (TAS5782M kernel-managed)"
        );
        assert!(matches!(cfg.arch, Architecture::Aarch64));
        for chain in &cfg.chains {
            assert!(
                chain.pic_address.is_none(),
                "S19K Pro NoPic must NOT declare PIC at any chain (was {:?})",
                chain.pic_address
            );
        }
        assert_eq!(cfg.chains.len(), 3, "S19K Pro has 3 chains");
        assert_eq!(cfg.fan.fan_count, 4);
    }

    #[test]
    fn s19k_amlogic_mirrors_s21_amlogic_voltage_topology() {
        // Both are am3-aml NoPic — must share PicType + VoltageControl.
        let s19k = PlatformConfig::s19k_amlogic();
        let s21 = PlatformConfig::s21_amlogic();
        assert_eq!(s19k.has_pic, s21.has_pic);
        assert!(matches!(s19k.pic_type, PicType::NoPic));
        assert!(matches!(s21.pic_type, PicType::NoPic));
        // Same voltage-control discipline (TAS5782M DTB).
        assert_eq!(
            std::mem::discriminant(&s19k.voltage_control),
            std::mem::discriminant(&s21.voltage_control),
        );
    }

    // ───  W10-E: runtime probe tests ───

    #[test]
    fn bcb100_lab_config_is_stm32mp15_direct_serial_without_static_gpio() {
        let cfg = PlatformConfig::bcb100_s19_lab();
        assert!(matches!(cfg.arch, Architecture::Armv7HfStm32Mp15));
        assert_eq!(
            cfg.chains.len(),
            4,
            "BCB100 exposes four hashboard connectors"
        );
        assert_eq!(cfg.fan.fan_count, 4);
        for (idx, chain) in cfg.chains.iter().enumerate() {
            match &chain.transport {
                ChainTransport::Serial { device, baud } => {
                    // Chains are ttySTM1..4, NOT ttySTM0..3: Braiins' ii1-am2 DT
                    // `aliases` map serial0 -> UART4 (the Linux debug console) and
                    // serial1..4 -> USART3/UART5/UART7/UART8 (HB0..HB3). Opening
                    // ttySTM0 as a chain would grab the console; omitting ttySTM4
                    // would drop HB3. Regression-pins the 2026-08-12 correction.
                    assert_eq!(device, &format!("/dev/ttySTM{}", idx + 1));
                    assert_eq!(*baud, 115200);
                }
                other => panic!("BCB100 chain should use direct serial, got {:?}", other),
            }
            assert_eq!(chain.pic_address, None);
            assert_eq!(chain.plug_detect_gpio, None);
            assert_eq!(chain.enable_gpio, None);
        }
        assert!(
            !cfg.chains.iter().any(|chain| matches!(
                &chain.transport,
                ChainTransport::Serial { device, .. } if device == "/dev/ttySTM0"
            )),
            "ttySTM0 is the STM32MP15 debug console (UART4) and must never be a chain port"
        );
    }

    #[test]
    fn x17_zynq_voltage_controller_split_is_per_sku() {
        let s17 = PlatformConfig::s17_zynq();
        assert_eq!(s17.name, "Antminer S17/S17e (Zynq dsPIC)");
        assert_eq!(
            s17.chains
                .iter()
                .map(|chain| chain.pic_address)
                .collect::<Vec<_>>(),
            vec![Some(0x20), Some(0x21), Some(0x22)]
        );
        assert!(matches!(s17.pic_type, PicType::DsPic33EP16GS202));
        assert!(matches!(s17.voltage_control, VoltageControl::DsPic));
        assert_eq!(s17.voltage_controller, VoltageControllerKind::Dspic33Ep);

        for cfg in [
            PlatformConfig::s17plus_zynq(),
            PlatformConfig::t17_zynq(),
            PlatformConfig::t17plus_zynq(),
        ] {
            assert_eq!(
                cfg.chains
                    .iter()
                    .map(|chain| chain.pic_address)
                    .collect::<Vec<_>>(),
                vec![Some(0x50), Some(0x51), Some(0x52)],
                "{} must stay on the PIC16 address lane",
                cfg.name
            );
            assert!(
                matches!(cfg.pic_type, PicType::Pic16F1704),
                "{} must not inherit the S17 dsPIC controller",
                cfg.name
            );
            assert!(matches!(cfg.voltage_control, VoltageControl::PicDac));
            assert_eq!(cfg.voltage_controller, VoltageControllerKind::Pic16f1704);
        }
    }

    #[test]
    fn probe_tty_picks_first_existing_candidate() {
        // Use a unique sub-directory under env::temp_dir() so we don't depend
        // on an external dev-dep (`tempfile` is not in this crate).
        let nonce = format!(
            "dcentrald_hal_probe_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let dir = std::env::temp_dir().join(nonce);
        std::fs::create_dir_all(&dir).unwrap();

        let primary = dir.join("ttyS_primary");
        let fallback = dir.join("ttyS_fallback");
        // Only the fallback exists. The primary should be skipped, fallback wins.
        std::fs::File::create(&fallback).unwrap();

        let primary_str = primary.to_str().unwrap().to_string();
        let fallback_str = fallback.to_str().unwrap().to_string();
        let candidates = [primary_str.as_str(), fallback_str.as_str()];

        let resolved = probe_tty_chain_device(&candidates, "test-chain");
        assert_eq!(resolved.as_deref(), Some(fallback_str.as_str()));

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_tty_returns_none_when_no_candidates_exist() {
        let resolved = probe_tty_chain_device(
            &[
                "/this-does-not-exist/dcentrald_w10e_a",
                "/this-does-not-exist/dcentrald_w10e_b",
            ],
            "test-chain",
        );
        assert!(resolved.is_none(), "no candidate exists, must return None");
    }

    #[test]
    fn s19k_amlogic_uses_verified_axg_chain_uarts() {
        let cfg = PlatformConfig::s19k_amlogic();
        let devices: Vec<&str> = cfg
            .chains
            .iter()
            .map(|chain| match &chain.transport {
                ChainTransport::Serial { device, .. } => device.as_str(),
                other => panic!("unexpected s19k transport: {:?}", other),
            })
            .collect();

        assert_eq!(devices, vec!["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]);
        assert!(
            !devices.contains(&"/dev/ttyS4"),
            "ttyS4 is the S21 AXG third port, not the S19k third hash UART"
        );
    }

    #[test]
    fn s19k_amlogic_uart_endpoints_do_not_claim_disproven_physical_slots() {
        let cfg = PlatformConfig::s19k_amlogic();
        for chain in &cfg.chains {
            assert_eq!(
                chain.i2c_bus, 1,
                "S19k management EEPROM/TMP75 evidence is on Linux i2c-1"
            );
            assert_eq!(
                chain.plug_detect_gpio, None,
                "logical UART endpoint {} must not claim a physical plug GPIO",
                chain.chain_id
            );
            assert_eq!(
                chain.enable_gpio, None,
                "logical UART endpoint {} must not claim a physical reset GPIO",
                chain.chain_id
            );
        }
    }

    #[test]
    fn s21_amlogic_uses_verified_axg_chain_uarts() {
        let cfg = PlatformConfig::s21_amlogic();
        let devices: Vec<&str> = cfg
            .chains
            .iter()
            .map(|chain| match &chain.transport {
                ChainTransport::Serial { device, .. } => device.as_str(),
                other => panic!("unexpected s21 transport: {:?}", other),
            })
            .collect();

        assert_eq!(devices, vec!["/dev/ttyS3", "/dev/ttyS2", "/dev/ttyS1"]);
        assert!(
            !devices.contains(&"/dev/ttyS4"),
            "the held exact S21 route is ttyS3/ttyS2/ttyS1 and has no ttyS4"
        );
    }

    #[test]
    fn amlogic_chain2_candidate_order_is_explicit_and_pure() {
        let s19k_chain2 = PlatformConfig::s19k_amlogic()
            .chains
            .into_iter()
            .find(|chain| chain.chain_id == 2)
            .expect("s19k chain 2");
        assert_eq!(
            amlogic_tty_candidate_order(&s19k_chain2),
            vec!["/dev/ttyS3"]
        );
        assert!(
            !amlogic_tty_candidate_order(&s19k_chain2)
                .iter()
                .any(|path| path == "/dev/ttyS4"),
            "S19k must fail closed when ttyS3 is unavailable, never fall through to S21 ttyS4"
        );
        let s21_chain2 = PlatformConfig::s21_amlogic()
            .chains
            .into_iter()
            .find(|chain| chain.chain_id == 2)
            .expect("s21 chain 2");
        assert_eq!(amlogic_tty_candidate_order(&s21_chain2), vec!["/dev/ttyS1"]);
    }

    #[test]
    fn voltage_capability_registries_are_exhaustive_and_non_authorizing() {
        assert_eq!(VOLTAGE_CONTROLLER_KIND_CAPABILITIES.len(), 4);
        let kinds: std::collections::BTreeSet<&str> = VOLTAGE_CONTROLLER_KIND_CAPABILITIES
            .iter()
            .map(|capability| capability.kind.as_str())
            .collect();
        assert_eq!(kinds.len(), VOLTAGE_CONTROLLER_KIND_CAPABILITIES.len());
        for capability in VOLTAGE_CONTROLLER_KIND_CAPABILITIES {
            assert!(!capability.construction_authorized);
            assert!(!capability.runtime_admission_authorized);
            assert!(!capability.mutation_authorized);
        }

        assert_eq!(VOLTAGE_CONTROL_METHOD_CAPABILITIES.len(), 5);
        let methods: std::collections::BTreeSet<&str> = VOLTAGE_CONTROL_METHOD_CAPABILITIES
            .iter()
            .map(|capability| capability.method)
            .collect();
        assert_eq!(methods.len(), VOLTAGE_CONTROL_METHOD_CAPABILITIES.len());
        for capability in VOLTAGE_CONTROL_METHOD_CAPABILITIES {
            assert!(!capability.endpoint_identity_verified);
            assert!(!capability.runtime_admission_authorized);
            assert!(!capability.mutation_authorized);
        }

        let frequency_only = VOLTAGE_CONTROL_METHOD_CAPABILITIES
            .iter()
            .find(|capability| capability.method == "FrequencyOnly")
            .unwrap();
        assert_eq!(
            frequency_only.state,
            VoltageCapabilityState::NoControllerFallback
        );
    }
}
