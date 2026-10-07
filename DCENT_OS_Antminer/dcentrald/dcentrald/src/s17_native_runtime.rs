// SPDX-License-Identifier: GPL-3.0-or-later
//! Native BM1397 execution for the S17 AM2 fabric. No stock miner is launched.
//!
//! Hardware parameters are data, not opt-in switches. The installed profile
//! binds an exact EEPROM project marker, PIC application and sensor topology.
//! Stock S17 libplatform (Apr 2020) and the BHB07601 factory jig are the wire
//! authorities; stock AXI register offsets are never used on the s17io fabric.

use super::*;
use anyhow::{bail, ensure};
use std::collections::HashSet;
use std::path::Path;
use std::time::Instant;

use dcentrald_asic::drivers::{bm1397::Bm1397Driver, ChipDriver};
use dcentrald_hal::fan::{Am2FanModePolicy, FanController, FanVariant};
use dcentrald_hal::fpga_chain::FpgaChain;
use dcentrald_hal::gpio::{GpioController, GpioLayout};
use dcentrald_hal::i2c::{I2cMutationLabel, I2cServiceHandle, I2cTransactionStep};
use dcentrald_stratum::types::{JobTemplate, StratumStatus, ValidShare};
use dcentrald_stratum::work::WorkBuilder;
use serde::Deserialize;

use crate::runtime::safety_watchdog::{S17WatchdogShutdownManifest, WatchdogDisarmPermit};
use crate::runtime::teardown_budget::{TeardownBudgetView, TeardownDisarmAuthority, TeardownStage};

#[path = "s17_fabric_identity.rs"]
mod fabric;
#[path = "s17_factory_profile.rs"]
mod factory;
pub(super) use fabric::FabricIdentity as S17FabricIdentity;

const PROFILE_PATH: &str = "/etc/dcent/s17-runtime.json";
const GPIO_ROOT: &str = "/sys/class/gpio";
// REGISTER_WAIT now lives in the `wire` leaf (re-exported by super::*).
const PROFILE_MAX_BYTES: u64 = 32 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorProfile {
    /// Jig TempSensorN is one-based; this is the already resolved ASIC address.
    chip_address: u8,
    /// Exact jig sensor_model, not an inferred model from a temperature value.
    model: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChainProfile {
    slot: u8,
    eeprom_address: u8,
    eeprom_project_offset: usize,
    eeprom_project_bytes: Vec<u8>,
    pic_application: Option<u8>,
    sensors: Vec<SensorProfile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct S17RuntimeProfile {
    schema: u32,
    board_target: String,
    hashboard_part: String,
    /// Source hash for the exact factory profile, retained in the beta record.
    source_sha256: String,
    psu_voltage_cv: u16,
    frequency_mhz: u16,
    fan_pwm: u8,
    max_temperature_c: i16,
    open_core_gap_ms: u16,
    chains: Vec<ChainProfile>,
    /// Constructed from the compiled held-source profile, never from JSON.
    #[serde(skip)]
    factory_defaults: bool,
}

impl S17RuntimeProfile {
    pub(super) fn load(board: &str) -> Result<Self> {
        let file = match std::fs::File::open(PROFILE_PATH) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Self::builtin(board)
            }
            Err(error) => return Err(error).context("cannot read installed S17 hardware profile"),
        };
        ensure!(
            file.metadata()?.len() <= PROFILE_MAX_BYTES,
            "S17 profile exceeds size limit"
        );
        let profile: Self = serde_json::from_reader(file)?;
        profile.validate(board)?;
        Ok(profile)
    }

    fn builtin(board: &str) -> Result<Self> {
        let layout = factory::layout(board)?;
        let profile = Self {
            schema: 1,
            board_target: board.into(),
            hashboard_part: s17_hashboard_part_number(board)
                .context("missing S17-family board identity")?
                .into(),
            source_sha256: layout.source_sha256.into(),
            // Replaced with CRC-checked factory mode before any power write.
            psu_voltage_cv: 1850,
            frequency_mhz: 100,
            fan_pwm: 30,
            max_temperature_c: 80,
            open_core_gap_ms: 5,
            chains: (0..3)
                .map(|slot| ChainProfile {
                    slot,
                    eeprom_address: 0x50 | slot,
                    eeprom_project_offset: 0,
                    eeprom_project_bytes: vec![0x97, 0x13],
                    pic_application: None,
                    sensors: layout
                        .sensor_addresses
                        .into_iter()
                        .map(|chip_address| SensorProfile {
                            chip_address,
                            model: 1,
                        })
                        .collect(),
                })
                .collect(),
            factory_defaults: true,
        };
        profile.validate(board)?;
        Ok(profile)
    }

    fn validate(&self, board: &str) -> Result<()> {
        ensure!(
            self.schema == 1 && self.board_target == board,
            "S17 profile target/schema mismatch"
        );
        ensure!(
            Some(self.hashboard_part.as_str()) == s17_hashboard_part_number(board),
            "S17 profile hashboard mismatch"
        );
        ensure!(
            self.source_sha256.len() == 64
                && self.source_sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "S17 profile lacks exact source hash"
        );
        ensure!(
            self.chains.len() == S17_CHAIN_COUNT as usize,
            "S17 profile must describe all three physical slots"
        );
        // APW9 conversion's held envelope is 14.5–21 V. A profile must select
        // its SKU voltage within it; the S17e/BM1396 clamp is not an authority.
        ensure!(
            (1450..=2100).contains(&self.psu_voltage_cv),
            "S17 APW9 target outside held transfer-law envelope"
        );
        ensure!(
            (50..=500).contains(&self.frequency_mhz),
            "initial S17 beta frequency must be 50..500 MHz"
        );
        ensure!(
            (1..=30).contains(&self.fan_pwm),
            "S17 beta home fan PWM must be 1..30"
        );
        ensure!(
            (40..=85).contains(&self.max_temperature_c),
            "S17 thermal cutoff outside conservative envelope"
        );
        ensure!(
            (1..=100).contains(&self.open_core_gap_ms),
            "S17 open-core gap out of range"
        );
        let stride = s17_addr_interval(board).context("S17 address stride")?;
        let chips = s17_chips_per_chain(board).context("S17 chip count")?;
        let mut slots = HashSet::new();
        let mut addresses = HashSet::new();
        for chain in &self.chains {
            ensure!(
                chain.slot < 3 && slots.insert(chain.slot),
                "duplicate/invalid S17 slot"
            );
            ensure!(
                (0x50..=0x57).contains(&chain.eeprom_address)
                    && addresses.insert(chain.eeprom_address),
                "duplicate/invalid protected EEPROM endpoint"
            );
            ensure!(
                chain.eeprom_project_bytes.len() >= 2
                    && chain.eeprom_project_bytes.len() <= 16
                    && chain.eeprom_project_offset + chain.eeprom_project_bytes.len() <= 256,
                "invalid S17 project identity span"
            );
            ensure!(
                !matches!(chain.pic_application, Some(0 | 0x86 | 0xCC | 0xFF)),
                "non-application/degraded S17 PIC firmware"
            );
            ensure!(
                !chain.sensors.is_empty() && chain.sensors.len() <= 4,
                "S17 requires 1..4 exact sensors per chain"
            );
            let mut sensors = HashSet::new();
            for sensor in &chain.sensors {
                ensure!((1..=8).contains(&sensor.model), "unknown S17 sensor model");
                ensure!(
                    sensor.chip_address % stride == 0
                        && sensor.chip_address / stride < chips
                        && sensors.insert(sensor.chip_address),
                    "invalid/duplicate S17 sensor ASIC address"
                );
            }
        }
        Ok(())
    }
}

/// The sole production owner of chain MMIO. The protocol uses this narrow seam
/// so queueing, commands and nonce correlation can be tested without MMIO.
struct UioChain(FpgaChain);

// `ChainIo`, `WorkLedger`, `framed_reply`, the register helpers, divisor
// discovery and the FIFO frame-space rule live in the dependency-free
// `wire` leaf module (mounted + re-exported by `s17_hybrid_mining.rs`) so
// the `tests/r05_*.rs` targets replay the exact production implementation.

impl ChainIo for UioChain {
    fn set_divisor(&mut self, value: u32) {
        self.0.set_baud(value);
    }
    fn divisor(&self) -> u32 {
        self.0.read_baud()
    }
    fn command(&mut self, bytes: &[u8]) {
        // s17io appends CRC5 and the 55AA preamble. The common FIFO uses
        // little-endian words, exactly as Bm1397Driver's command helpers.
        for bytes in bytes.chunks(4) {
            let mut word = [0; 4];
            word[..bytes.len()].copy_from_slice(bytes);
            self.0.write_cmd(u32::from_le_bytes(word));
        }
    }
    fn register_reply(&mut self) -> Option<[u8; 8]> {
        if !self.0.cmd_rx_has_data() {
            return None;
        }
        let first = self.0.read_cmd_response()?;
        let second = self.0.read_cmd_response()?;
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&first.to_le_bytes());
        bytes[4..].copy_from_slice(&second.to_le_bytes());
        Some(bytes)
    }
    fn work_full(&self) -> bool {
        !work_queue_has_complete_frame_space(
            self.0.read_work_tx_status(),
            self.0.read_work_tx_threshold(),
        )
    }
    fn write_work(&mut self, words: &[u32; 36]) -> Result<()> {
        ensure!(!self.work_full(), "S17 work FIFO full");
        self.0.write_work(words);
        Ok(())
    }
    fn nonce(&mut self) -> Option<[u32; 2]> {
        self.0.read_nonce().map(|(a, b)| [a, b])
    }
    fn flush_work(&mut self) {
        self.0.flush_work_tx();
        self.0.flush_work_rx();
    }
}

#[path = "s17_native_chain_init.rs"]
mod cold_chain;

#[cfg(all(test, feature = "sim-hal"))]
#[path = "s17_native_chain_integration_tests.rs"]
mod chain_integration;

struct NativeChain {
    profile: ChainProfile,
    measured_census_chips: Option<u16>,
    io: UioChain,
    ledger: WorkLedger,
    maximum_temperature: i16,
}

struct NativeHardware {
    profile: S17RuntimeProfile,
    i2c: I2cServiceHandle,
    psu_i2c: I2cServiceHandle,
    fan: FanController,
    gpio: GpioController,
    chains: Vec<NativeChain>,
    fabric: fabric::FabricIdentity,
}

/// The exact C49 three-chain reset DATA owner. No PIC reset or unrelated
/// GPIO bit is involved; the selected donor declares this bank all-output.
trait ChainResetIo {
    fn read_data(&self) -> u32;
    fn assert_all(&self);
    fn release_slot(&self, slot: u8);
}

impl ChainResetIo for GpioController {
    fn read_data(&self) -> u32 {
        self.read_output()
    }
    fn assert_all(&self) {
        self.enter_reset_all();
    }
    fn release_slot(&self, slot: u8) {
        self.exit_reset(slot);
    }
}

fn assert_chain_resets(io: &impl ChainResetIo) -> Result<()> {
    let before = io.read_data();
    io.assert_all();
    ensure!(
        io.read_data() == before & !7,
        "S17 reset assertion or unrelated GPIO preservation failed"
    );
    Ok(())
}

fn release_chain_reset(io: &impl ChainResetIo, slot: u8) -> Result<()> {
    ensure!(slot < 3, "invalid S17 physical reset slot");
    let before = io.read_data();
    let bit = 1u32 << slot;
    ensure!(
        before & bit == 0,
        "S17 chain was not held in reset before release"
    );
    io.release_slot(slot);
    ensure!(
        io.read_data() == before | bit,
        "S17 reset release or unrelated GPIO preservation failed"
    );
    Ok(())
}

fn uio_number(name: &str) -> Result<u8> {
    let mut matches = Vec::new();
    for entry in std::fs::read_dir("/sys/class/uio")? {
        let entry = entry?;
        if std::fs::read_to_string(entry.path().join("name"))?.trim() == name {
            matches.push(
                entry
                    .file_name()
                    .to_str()
                    .context("non UTF8 UIO name")?
                    .strip_prefix("uio")
                    .context("invalid UIO name")?
                    .parse::<u8>()?,
            );
        }
    }
    ensure!(
        matches.len() == 1,
        "expected one exact UIO role {name}, got {}",
        matches.len()
    );
    Ok(matches[0])
}

/// Active-low GPIO907 is established by stock S17 power_api.c, not the
/// incorrectly active-high generic BoardControl::psu_enable wrapper.
fn set_psu_gpio(enabled: bool) -> Result<()> {
    set_psu_gpio_at(Path::new(GPIO_ROOT), enabled)
}

fn set_psu_gpio_at(root: &Path, enabled: bool) -> Result<()> {
    let gpio = root.join("gpio907");
    if !gpio.exists() {
        std::fs::write(root.join("export"), b"907")?;
    }
    // Atomic initial output value avoids direction=out briefly enabling power.
    std::fs::write(
        gpio.join("direction"),
        if enabled {
            b"low".as_slice()
        } else {
            b"high".as_slice()
        },
    )?;
    let expected = if enabled { "0" } else { "1" };
    std::fs::write(gpio.join("value"), expected)?;
    ensure!(
        std::fs::read_to_string(gpio.join("value"))?.trim() == expected,
        "S17 GPIO907 readback mismatch"
    );
    Ok(())
}

fn apw9_transaction_steps(dac: u8) -> Vec<I2cTransactionStep> {
    // Stock sends every payload byte through register 0x11, on bus 1.
    // A single [register, entire frame] write changes that wire protocol.
    let mut steps = Vec::new();
    for byte in apw9_set_dac_frame(dac) {
        steps.push(I2cTransactionStep::Write(vec![S17_APW9_DAC_SUBADDR, byte]));
        steps.push(I2cTransactionStep::SleepMs(5));
    }
    steps.push(I2cTransactionStep::SleepMs(500));
    steps.extend((0..8).map(|_| I2cTransactionStep::Read(1)));
    steps
}

fn apw9_reply(bytes: &[u8], command: u8) -> Result<()> {
    ensure!(
        bytes.len() == 8 && bytes[..4] == [0x55, 0xaa, 6, command],
        "S17 APW9 reply framing/opcode mismatch"
    );
    let checksum: u16 = bytes[2..6].iter().map(|&v| u16::from(v)).sum();
    ensure!(
        bytes[6..] == checksum.to_le_bytes(),
        "S17 APW9 reply checksum mismatch"
    );
    Ok(())
}

impl NativeHardware {
    fn open(profile: S17RuntimeProfile, mut fabric: S17FabricIdentity) -> Result<Self> {
        let i2c = dcentrald_hal::i2c::spawn_i2c_service_no_register_touch_with_denylist(
            0,
            S17_EEPROM_WRITE_DENYLIST.to_vec(),
        )?;
        let psu_i2c = dcentrald_hal::i2c::spawn_i2c_service_no_register_touch_with_denylist(
            1,
            S17_EEPROM_WRITE_DENYLIST.to_vec(),
        )?;
        let (discovery, mut fan) =
            FanController::open_discovered_with_mode_policy(Am2FanModePolicy::Preserve)?;
        ensure!(
            discovery.variant == FanVariant::Am2Uio16,
            "S17 requires exact AM2 fan register layout"
        );
        fan.set_profile_cap(30);
        let gpio = GpioController::new_with_layout(GpioLayout::Am2)?;
        let mut chains = Vec::new();
        for profile in &profile.chains {
            let id = profile.slot + 1;
            let base = uio_number(&format!("chain{id}-common"))?;
            for (offset, role) in [(1, "cmd-rx"), (2, "work-rx"), (3, "work-tx")] {
                ensure!(
                    uio_number(&format!("chain{id}-{role}"))? == base + offset,
                    "noncontiguous S17 UIO group"
                );
            }
            // Exact admitted s17io payload: VERSION+0, BUILD+4, CTRL+8,
            // BAUD+0x10. The ABI is shared with modern generic format2;
            // do not reuse the old mistaken +0-as-CTRL interpretation.
            let io = UioChain(FpgaChain::open(id, base)?);
            fabric.observe_chain(io.0.read_version(), io.0.read_build_id())?;
            chains.push(NativeChain {
                measured_census_chips: None,
                profile: profile.clone(),
                io,
                ledger: WorkLedger::new(),
                maximum_temperature: 0,
            });
        }
        Ok(Self {
            profile,
            i2c,
            psu_i2c,
            fan,
            gpio,
            chains,
            fabric,
        })
    }

    fn pic(&self, slot: u8, command: u8, payload: &[u8], read_len: usize) -> Result<Vec<u8>> {
        let addr = s17_pic_i2c_addr(slot);
        let label = match command {
            0x16 => I2cMutationLabel::KeepAlive,
            0x10 | 0x15 => I2cMutationLabel::Energize,
            _ => I2cMutationLabel::QueryPrelude,
        };
        let mut steps = vec![
            I2cTransactionStep::WriteByteByByte(dspic_g2a_frame(command, payload)),
            I2cTransactionStep::SleepMs(500),
        ];
        // Stock 0x73678 clocks each response byte as its own I2C operation.
        steps.extend((0..read_len).map(|_| I2cTransactionStep::Read(1)));
        let result = self.i2c.transaction_mutating(label, addr, steps);
        match result {
            Ok(reads) => {
                let bytes: Vec<u8> = reads.into_iter().flatten().collect();
                ensure!(
                    bytes.len() == read_len,
                    "S17 PIC transaction omitted response"
                );
                Ok(bytes)
            }
            Err(error) => {
                // PIC parser flush after a NACK is serialized by the same bus
                // owner and cannot touch any protected EEPROM endpoint.
                let _ = self.i2c.transaction_mutating(
                    I2cMutationLabel::QueryPrelude,
                    addr,
                    vec![I2cTransactionStep::WriteByteByByte(vec![0; 16])],
                );
                Err(error.into())
            }
        }
    }

    fn heartbeat(&self) -> Result<()> {
        for chain in &self.chains {
            let reply = self.pic(chain.profile.slot, 0x16, &[], 6)?;
            let payload = framed_reply(&reply, 0x16)?;
            ensure!(
                payload.first() == Some(&1),
                "S17 PIC heartbeat not acknowledged"
            );
        }
        Ok(())
    }

    async fn initialize(&mut self, shutdown: &CancellationToken) -> Result<()> {
        set_psu_gpio(false)?;
        // Selected donor DT gpio@41210000: all-outputs=1, width=5,
        // DATA default=0x10. Bits0..2 are active-low chain resets and must
        // remain LOW across voltage programming before a checked release.
        assert_chain_resets(&self.gpio)?;
        let mut factory_records = Vec::new();
        // Read all exact project identities before the first voltage write.
        for index in 0..self.chains.len() {
            let chain = &self.chains[index];
            let raw = self.i2c.read_hashboard_eeprom_page_at(
                chain.profile.eeprom_address,
                Instant::now() + Duration::from_secs(2),
            )?;
            let second = self.i2c.read_hashboard_eeprom_page_at(
                chain.profile.eeprom_address,
                Instant::now() + Duration::from_secs(2),
            )?;
            ensure!(raw == second, "S17 EEPROM changed between protected reads");
            let start = chain.profile.eeprom_project_offset;
            let end = start + chain.profile.eeprom_project_bytes.len();
            ensure!(
                raw.get(start..end) == Some(chain.profile.eeprom_project_bytes.as_slice()),
                "S17 slot {} project EEPROM mismatch",
                chain.profile.slot
            );
            let version = self.pic(chain.profile.slot, 0x17, &[], 5)?;
            let second_version = self.pic(chain.profile.slot, 0x17, &[], 5)?;
            ensure!(
                version == second_version,
                "S17 PIC application changed between reads"
            );
            let application = framed_reply(&version, 0x17)?;
            ensure!(
                application.len() == 1 && !matches!(application[0], 0 | 0x86 | 0xcc | 0xff),
                "S17 PIC application invalid/degraded"
            );
            if let Some(expected) = chain.profile.pic_application {
                ensure!(application == [expected], "S17 PIC application mismatch");
            }
            tracing::info!(
                slot = chain.profile.slot,
                pic_application = application[0],
                "S17 native controller identity"
            );
            if self.profile.factory_defaults {
                let record = factory::decode(&self.profile.board_target, &raw)?;
                tracing::info!(
                    slot = chain.profile.slot,
                    fixture_version = record.fixture_version,
                    pcb = record.pcb,
                    bom = record.bom,
                    product = record.product_id,
                    sensor = record.sensor_model,
                    "S17 native protected factory identity"
                );
                for sensor in &mut self.chains[index].profile.sensors {
                    sensor.model = record.sensor_model;
                }
                factory_records.push(record);
            }
        }
        if self.profile.factory_defaults {
            let (mode, voltage, frequency) = factory::common_mode(&factory_records)?;
            self.profile.psu_voltage_cv = voltage;
            self.profile.frequency_mhz = self.profile.frequency_mhz.min(frequency);
            tracing::info!(
                mode,
                voltage_cv = voltage,
                frequency_mhz = self.profile.frequency_mhz,
                "S17 native factory operating profile selected"
            );
        }
        self.fan.set_speed(self.profile.fan_pwm);
        // Physical S17/T17 C49 wires one common PWM to all four fans.
        // +0x14 is a no-op on the single-PWM IP; requiring it to echo would
        // reject a correctly cooled C49 board. All four actual tachs remain
        // mandatory below (held RTL README:64..77 and 448..472).
        ensure!(
            self.fan.get_speed_pwm() == self.profile.fan_pwm,
            "S17 fan PWM readback mismatch"
        );
        for _ in 0..5 {
            ensure!(!shutdown.is_cancelled(), "S17 bringup cancelled");
            self.heartbeat()?;
        }
        // The five bytewise PIC rounds also allow the physical fans and
        // 500-ms tach observation windows to settle before this check.
        ensure!(
            self.fan.get_tach_snapshot().all_required_channels_moving(),
            "S17 required fan stopped before energize"
        );
        // The GPIO is prepared off before the command that can energize rails.
        set_psu_gpio(false)?;
        let dac = apw9_dac_for_bitmain_cv(u32::from(self.profile.psu_voltage_cv));
        let reads = self.psu_i2c.transaction_mutating(
            I2cMutationLabel::Energize,
            S17_APW9_I2C_ADDR,
            apw9_transaction_steps(dac),
        )?;
        apw9_reply(&reads.into_iter().flatten().collect::<Vec<_>>(), 0x83)?;
        for chain in &self.chains {
            // Production init_working_voltage -> set_to_voltage owns the
            // APW9 DAC; PIC 0x15 controls the board enable. No arbitrary PIC
            // voltage-code prerequisite is imported from the factory jig.
            let reply = self.pic(chain.profile.slot, 0x15, &[1], 2)?;
            ensure!(reply == [0x15, 1], "S17 PIC enable ACK mismatch");
        }
        set_psu_gpio(true)?;
        tokio::time::sleep(Duration::from_secs(1)).await;
        for index in 0..self.chains.len() {
            self.heartbeat()?;
            let chain = &mut self.chains[index];
            cold_chain::initialize_cold_chain(
                &mut chain.io,
                &self.gpio,
                &self.profile,
                &mut chain.profile,
                self.fabric.work_time(self.profile.frequency_mhz),
                shutdown,
            ).await?;
        }
        self.sample_temperatures().await?;
        Ok(())
    }

    async fn sample_temperatures(&mut self) -> Result<i16> {
        self.fabric.verify_clock_unchanged()?;
        ensure!(
            self.fan.get_tach_snapshot().all_required_channels_moving(),
            "S17 required fan stopped"
        );
        let mut maximum = i16::MIN;
        for chain in &mut self.chains {
            let mut chain_maximum = i16::MIN;
            for sensor in &chain.profile.sensors {
                let remote = sensor.model <= 2;
                let hi = dcentrald_common::bm1397_s17_bhb07601::sensor_i2c_hi(sensor.model);
                for register in [Some(0), remote.then_some(1)].into_iter().flatten() {
                    let value =
                        read_sensor_register(&mut chain.io, sensor.chip_address, hi, register)
                            .await?;
                    let temperature =
                        dcentrald_common::bm1397_s17_bhb07601::decode_sensor_temp_c(value);
                    ensure!(
                        (-20..=125).contains(&temperature),
                        "S17 temperature implausible"
                    );
                    ensure!(
                        temperature < self.profile.max_temperature_c,
                        "S17 thermal cutoff: {temperature} C"
                    );
                    maximum = maximum.max(temperature);
                    chain_maximum = chain_maximum.max(temperature);
                }
            }
            chain.maximum_temperature = chain_maximum;
        }
        Ok(maximum)
    }
}

async fn sensor_result(io: &mut impl ChainIo, address: u8) -> Result<u32> {
    for _ in 0..3 {
        let value = register_read(io, address, 0x1c).await?;
        if value & 0xc000_0000 == 0 {
            return Ok(value);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    bail!("S17 sensor I2C engine remained busy/error")
}

async fn read_sensor_register(
    io: &mut impl ChainIo,
    address: u8,
    hi: u32,
    register: u8,
) -> Result<u8> {
    register_write(
        io,
        Some(address),
        0x1c,
        hi | 0x0100_0000 | (u32::from(register) << 8),
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    let value = sensor_result(io, address).await?;
    ensure!(
        (value >> 8) as u8 == register,
        "S17 sensor register response mismatch"
    );
    Ok(value as u8)
}

async fn write_sensor_register(
    io: &mut impl ChainIo,
    address: u8,
    hi: u32,
    write_register: u8,
    read_register: u8,
    value: u8,
) -> Result<()> {
    register_write(
        io,
        Some(address),
        0x1c,
        hi | 0x0101_0000 | (u32::from(write_register) << 8) | u32::from(value),
    );
    tokio::time::sleep(Duration::from_millis(2)).await;
    sensor_result(io, address).await?;
    ensure!(
        read_sensor_register(io, address, hi, read_register).await? == value,
        "S17 sensor configuration readback mismatch"
    );
    Ok(())
}

async fn initialize_sensors(
    io: &mut impl ChainIo,
    sensors: &mut [SensorProfile],
    plus_family: bool,
) -> Result<()> {
    for sensor in sensors {
        // Preserve the actual observed baud fields when enabling ASIC I2C.
        let misc = register_read(io, sensor.chip_address, 0x18).await?;
        register_write(io, Some(sensor.chip_address), 0x18, (misc & !0x70) | 0x4030);
        {
            // Stock: S17 0xe7ac/0x12d7c; T17 0xea6c/0x13464;
            // S17+ 0x2ac14/0x30c50; T17+ 0xef38/0x156f0.
            // ASIC reg54 selects the local diode mux before the sensor ID read.
            register_write(io, Some(sensor.chip_address), 0x54, 0);
            ensure!(
                register_read(io, sensor.chip_address, 0x54).await? & 7 == 0,
                "S17-family sensor diode mux readback mismatch"
            );
            let id = read_sensor_register(io, sensor.chip_address, 0x0098_0000, 0xfe).await?;
            // Exact stock images identify these parts at register FE,
            // then set extended mode and the matching signed remote offset.
            // S17+ literals 0x85924/28 and 0x85930/34;
            // T17+ literals 0x80b08/0c and 0x80b20/24.
            let (model, offset) = match id {
                0x1a if plus_family => (1, 0xf8), // NCT218, -8 C
                0x55 => (2, 0xf5),                // TMP451, -11 C
                _ => bail!("unrecognized source-profile S17-family sensor device ID 0x{id:02x}"),
            };
            write_sensor_register(io, sensor.chip_address, 0x0098_0000, 9, 3, 4).await?;
            write_sensor_register(io, sensor.chip_address, 0x0098_0000, 0x11, 0x11, offset).await?;
            sensor.model = model;
        }
    }
    Ok(())
}

/// Constructible only after the sole hardware owner has stopped dispatch,
/// fenced the fabric and read back the physical active-low cutoff. It carries
/// the watchdog-issued deadline identity; it cannot authorize another run.
pub(crate) struct S17SafeOffEvidence {
    budget: TeardownBudgetView,
    gpio_off: bool,
    all_pic_off: bool,
    network_joined: bool,
    resets_asserted: bool,
}

impl S17SafeOffEvidence {
    pub(crate) fn completed(&self) -> bool {
        self.gpio_off && self.all_pic_off && self.network_joined && self.resets_asserted
    }
    pub(crate) fn same_teardown_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        self.budget.same_budget(authority)
    }

    #[cfg(test)]
    pub(crate) fn outcomes_for_test(
        budget: TeardownBudgetView,
        gpio_off: bool,
        all_pic_off: bool,
        network_joined: bool,
        resets_asserted: bool,
    ) -> Self {
        Self {
            budget,
            gpio_off,
            all_pic_off,
            network_joined,
            resets_asserted,
        }
    }
}

pub(super) async fn run(
    mut miner: S17HybridMiner,
    mut safety: S17HybridSafetyAdmission,
) -> Result<()> {
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(
            &safety.runtime_profile.board_target,
        );
    let mut hardware = match safety
        .runtime_fabric
        .take()
        .context("S17 fabric admission was already consumed")
        .and_then(|fabric| NativeHardware::open(safety.runtime_profile.clone(), fabric))
    {
        Ok(hardware) => hardware,
        Err(error) => {
            let _ = set_psu_gpio(false);
            let _ = safety
                .watchdog
                .suppress_feeds_terminally(format!("S17 hardware owner could not open: {error:#}"))
                .await;
            return Err(
                crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                    "s17-hybrid",
                    format!("{error:#}"),
                ),
            );
        }
    };
    // The management gate stays closed: this engine owns every frequency,
    // voltage and cooling write until API operations have exact profile binding.
    let init_result = if crate::firstlight_census::operation_requested() {
        match crate::firstlight_census::initialization_remaining() {
            Ok(remaining) => tokio::time::timeout(remaining, hardware.initialize(&miner.shutdown))
                .await
                .context("S17 firstlight exceeded its absolute init deadline")
                .and_then(|result| result),
            Err(error) => Err(error),
        }
    } else {
        hardware.initialize(&miner.shutdown).await
    };
    let mut router = None;
    let result = if init_result.is_ok() && crate::firstlight_census::requested() {
        let measured: Result<Vec<_>> = hardware
            .chains
            .iter()
            .map(|chain| {
                Ok((
                    chain.profile.slot,
                    0x1397,
                    chain
                        .measured_census_chips
                        .context("S17 census has no fresh address verification")?,
                ))
            })
            .collect();
        measured.and_then(|rows| {
            crate::firstlight_census::publish(&safety.runtime_profile.board_target, &rows)
        })
    } else if init_result.is_ok() {
        match safety.watchdog.enter_mining().await {
            Ok(()) => mining_loop(&mut hardware, &mut miner, &safety.liveness, &mut router).await,
            Err(error) => Err(error),
        }
    } else {
        init_result
    };

    // Publish the deadline synchronously. Neither watchdog acknowledgement nor
    // a deadline-issuance error may postpone the physical cutoff.
    let teardown_request = safety.watchdog.request_teardown_budget();
    // Stop physical power first, even if API drain/actor observation fails.
    let cutoff_started = Instant::now();
    let gpio_off = set_psu_gpio(false).is_ok();
    let resets_asserted = assert_chain_resets(&hardware.gpio).is_ok();
    let cutoff_finished = Instant::now();
    let fabric = hardware.i2c.latch_terminal_safe_off();
    let psu_fabric = hardware.psu_i2c.latch_terminal_safe_off();
    for chain in &mut hardware.chains {
        chain.io.flush_work();
        chain.ledger.invalidate();
    }
    let mut all_pic_off = true;
    for chain in &hardware.chains {
        all_pic_off &= hardware
            .i2c
            .disable_s17_dspic_voltage(s17_pic_i2c_addr(chain.profile.slot))
            .is_ok();
    }
    let network_joined = if let Some(task) = router {
        task.abort();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .is_ok()
    } else {
        true
    };
    let cleanup = async {
        let (budget, admission) = teardown_request?.into_parts();
        let view = budget.view();
        safety
            .watchdog
            .observe_teardown_admission(admission, &view)
            .await
            .map_err(anyhow::Error::msg)?;
        view.require_completed_at(TeardownStage::CutoffStart, cutoff_started)?;
        view.require_completed_at(TeardownStage::CutoffComplete, cutoff_finished)?;
        let api_drain = safety
            .hardware_mutation_owner
            .close_and_drain_until(view.deadline(TeardownStage::CleanupComplete))?;
        let api_commit = match safety
            .hardware_mutation_owner
            .revoke_commit_fence()
            .try_wait()
        {
            dcentrald_hal::platform::HardwareMutationCommitFenceTryWait::Fenced(receipt) => receipt,
            _ => bail!("S17 API final commit did not quiesce"),
        };
        view.require_completed_at(TeardownStage::CleanupComplete, Instant::now())?;
        let safe_off = S17SafeOffEvidence {
            budget: view,
            gpio_off,
            all_pic_off,
            network_joined,
            resets_asserted,
        };
        let authority = budget.begin_disarm_at(Instant::now())?;
        let manifest = S17WatchdogShutdownManifest::new(
            safety.watchdog_route_scope,
            api_drain,
            api_commit,
            fabric,
            psu_fabric,
            safe_off,
            authority,
        );
        WatchdogDisarmPermit::from_s17_manifest(manifest)
    }
    .await;
    match cleanup {
        Ok(permit) => {
            let closeout = safety
                .watchdog
                .disarm_and_join(permit, Duration::from_secs(2))
                .await?;
            match result {
                Ok(()) => crate::daemon::publish_orderly_software_closeout(
                    software_closeout_run,
                    &closeout,
                ),
                Err(error) => Err(terminal_safe_off_error(error, closeout)),
            }
        }
        Err(error) => {
            let _ = safety
                .watchdog
                .suppress_feeds_terminally(format!("S17 shutdown incomplete: {error:#}"))
                .await;
            Err(
                crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                    "s17-hybrid",
                    format!("{error:#}"),
                ),
            )
        }
    }
}

async fn mining_loop(
    hardware: &mut NativeHardware,
    miner: &mut S17HybridMiner,
    liveness: &SafetyLiveness,
    router: &mut Option<tokio::task::JoinHandle<()>>,
) -> Result<()> {
    let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<JobTemplate>(16);
    let (share_tx, share_rx) = tokio::sync::mpsc::channel::<ValidShare>(128);
    let (status_tx, mut status_rx) = tokio::sync::mpsc::channel::<StratumStatus>(128);
    // Four host-computed midstates; no BM1398/BM136x chip-side version rolling.
    let config = crate::config::build_stratum_config_with_enumerated_chips(
        &miner.config,
        crate::config::stratum_donation_config(&miner.config.donation),
        miner.config.mining.version_rolling,
        false,
        Some(
            hardware.chains.len() as u32
                * u32::from(s17_chips_per_chain(&hardware.profile.board_target).unwrap()),
        ),
    );
    let worker = config.pool1.worker.clone();
    *router = Some(tokio::spawn(
        dcentrald_stratum::StratumRouter::new(config).run(job_tx, share_rx, status_tx),
    ));
    let mut builder = WorkBuilder::new();
    let mut current: Option<JobTemplate> = None;
    let mut poll = tokio::time::interval(Duration::from_millis(2));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut safety_tick = tokio::time::interval(Duration::from_secs(2));
    safety_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let started = Instant::now();
    let mut accepted = 0;
    let mut rejected = 0;
    loop {
        tokio::select! {
            biased;
            _ = miner.shutdown.cancelled() => {
                let elapsed = started.elapsed().as_secs_f64().max(1.0);
                let ticket_gh = 256.0 * 4294967296.0 / 1e9;
                crate::firstlight_census::publish_work(
                    &hardware.profile.board_target, accepted, rejected,
                    hardware.chains.iter().map(|chain| chain.ledger.valid_tickets as f64 * ticket_gh / elapsed).sum(),
                    started.elapsed().as_secs(),
                    &hardware.chains.iter().map(|chain| f32::from(chain.maximum_temperature)).collect::<Vec<_>>(),
                    hardware.profile.fan_pwm,
                )?;
                return Ok(());
            },
            _ = safety_tick.tick() => {
                hardware.heartbeat()?;
                let maximum = hardware.sample_temperatures().await?;
                liveness.mark_progress();
                tracing::debug!(maximum, "S17 native thermal and heartbeat sample");
                let now=Instant::now();
                for chain in &mut hardware.chains {
                    while chain.ledger.ticket_window.front().is_some_and(|at| now.duration_since(*at)>Duration::from_secs(5)) {
                        chain.ledger.ticket_window.pop_front();
                    }
                    if current.is_some() {
                        if let Some(last)=chain.ledger.last_ticket.or(chain.ledger.first_dispatch) {
                            ensure!(now.duration_since(last)<Duration::from_secs(60),"S17 slot {} produced no validated difficulty-256 ticket for 60 seconds",chain.profile.slot);
                        }
                    }
                }
                if let Some(tx) = &miner.state_tx {
                    let elapsed=started.elapsed().as_secs_f64().max(1.0);
                    let ticket_gh=256.0*4294967296.0/1e9;
                    let tach=hardware.fan.get_tach_snapshot();
                    tx.send_modify(|state| {
                        state.accepted=accepted; state.rejected=rejected; state.uptime_s=started.elapsed().as_secs();
                        state.hashrate_ghs=hardware.chains.iter().map(|chain| chain.ledger.valid_tickets as f64*ticket_gh/elapsed).sum();
                        state.hashrate_5s_ghs=hardware.chains.iter().map(|chain| chain.ledger.ticket_window.len() as f64*ticket_gh/elapsed.min(5.0)).sum();
                        state.chains=hardware.chains.iter().map(|chain| dcentrald_api::ChainState {
                            id:chain.profile.slot+1,chips:s17_chips_per_chain(&hardware.profile.board_target).unwrap(),
                            frequency_mhz:hardware.profile.frequency_mhz,voltage_mv:hardware.profile.psu_voltage_cv*10,
                            temp_c:f32::from(chain.maximum_temperature),temp_source:Some(dcentrald_api::ChainTempSource::BOARD_SENSOR.into()),
                            hashrate_ghs:chain.ledger.valid_tickets as f64*ticket_gh/elapsed,errors:0,
                            status:if current.is_some() {"mining"} else {"waiting_for_pool"}.into(),
                        }).collect();
                        state.fans.pwm=hardware.profile.fan_pwm;
                        state.fans.rpm=tach.rpm_by_physical_fan.first().copied().flatten().unwrap_or(0);
                        state.fans.per_fan=tach.rpm_by_physical_fan.iter().enumerate().map(|(index,rpm)| dcentrald_api::PerFanReading {
                            id:index as u8,rpm:rpm.unwrap_or(0),pwm_percent:hardware.profile.fan_pwm,
                        }).collect();
                    });
                }
            }
            status = status_rx.recv() => match status {
                Some(StratumStatus::ShareAccepted { .. }) => accepted += 1,
                Some(StratumStatus::ShareRejected { .. }) => rejected += 1,
                Some(StratumStatus::DifficultyChanged(value)) => {
                    if let Some(tx)=&miner.state_tx {tx.send_modify(|state| state.pool.difficulty=value);}
                },
                Some(StratumStatus::StateChanged(state)) => {
                    if !matches!(state,dcentrald_stratum::types::StratumState::Mining|dcentrald_stratum::types::StratumState::Donating) {
                        current=None;
                        for chain in &mut hardware.chains {
                            chain.io.flush_work(); chain.ledger.invalidate();
                            chain.ledger.first_dispatch=None; chain.ledger.last_ticket=None;
                        }
                    }
                    if let Some(tx)=&miner.state_tx {tx.send_modify(|snapshot| snapshot.pool.status=format!("{state:?}").to_lowercase());}
                },
                Some(status) => tracing::debug!(?status,"S17 pool status"),
                None => bail!("S17 Stratum status owner exited"),
            },
            job = job_rx.recv() => {
                let job = job.context("S17 Stratum job owner exited")?;
                // Every new notify invalidates hardware work. This conservative
                // policy also prevents reused pool job IDs crossing sessions.
                for chain in &mut hardware.chains { chain.io.flush_work(); chain.ledger.invalidate(); }
                builder.set_version_mask(job.version_mask);
                current = Some(job);
            }
            _ = poll.tick() => {
                for chain in &mut hardware.chains {
                    for _ in 0..128 {
                        let Some(raw) = chain.io.nonce() else { break };
                        if let Some(share) = chain.ledger.validate(raw,&worker)? {
                            share_tx.try_send(share).context("S17 share queue unavailable")?;
                        }
                    }
                    if let Some(job) = &current {
                        if !chain.io.work_full() {
                            let work = builder.next_work(job)?;
                            chain.ledger.dispatch(&mut chain.io,work)?;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_stratum::work::MiningWork;
    use std::collections::VecDeque;

    #[test]
    fn every_native_s17_profile_refuses_degraded_or_non_application_pic_firmware() {
        for board in S17_HYBRID_BOARD_TARGETS {
            let profile = S17RuntimeProfile::builtin(board).expect("compiled exact S17 profile");
            // An unspecified expected byte still requires the live application
            // read in initialize; an explicit degraded byte cannot pass here.
            profile.validate(board).unwrap();
            for slot in 0..profile.chains.len() {
                for firmware in [0, 0x86, 0xcc, 0xff] {
                    let mut candidate = profile.clone();
                    candidate.chains[slot].pic_application = Some(firmware);
                    let error = candidate.validate(board).unwrap_err();
                    assert!(
                        error.to_string().contains("non-application/degraded S17 PIC firmware"),
                        "{board} slot {slot} firmware {firmware:#04x}: {error}"
                    );
                }
                let mut candidate = profile.clone();
                candidate.chains[slot].pic_application = Some(1);
                candidate.validate(board).unwrap();
            }
        }
    }

    #[test]
    fn s17_reset_lifecycle_releases_cold_chains_and_retains_terminal_low_without_power_bit_changes()
    {
        struct Registers {
            data: std::cell::Cell<u32>,
            ignore_writes: std::cell::Cell<bool>,
        }
        impl ChainResetIo for Registers {
            fn read_data(&self) -> u32 {
                self.data.get()
            }
            fn assert_all(&self) {
                if !self.ignore_writes.get() {
                    self.data.set(self.data.get() & !7);
                }
            }
            fn release_slot(&self, slot: u8) {
                if !self.ignore_writes.get() {
                    self.data.set(self.data.get() | (1 << slot));
                }
            }
        }
        let registers = Registers {
            data: std::cell::Cell::new(0xa5a5_0010),
            ignore_writes: std::cell::Cell::new(false),
        };
        assert_chain_resets(&registers).unwrap();
        for slot in 0..3 {
            release_chain_reset(&registers, slot).unwrap();
        }
        assert_eq!(registers.data.get(), 0xa5a5_0017);
        assert!(release_chain_reset(&registers, 0).is_err());
        assert!(release_chain_reset(&registers, 3).is_err());
        registers.ignore_writes.set(true);
        assert!(assert_chain_resets(&registers).is_err());
        registers.ignore_writes.set(false);
        assert_chain_resets(&registers).unwrap();
        assert_eq!(registers.data.get(), 0xa5a5_0010);
        registers.ignore_writes.set(true);
        assert!(release_chain_reset(&registers, 0).is_err());
    }

    #[derive(Default)]
    struct RecordingChain {
        divisor: u32,
        full: bool,
        fail_write: bool,
        writes: Vec<[u32; 36]>,
        commands: Vec<Vec<u8>>,
        replies: VecDeque<[u8; 8]>,
        enumerate_at: Option<u32>,
        enumerate_chips: u8,
        // Independent small ASIC/I2C register model for configuration tests.
        sensor_registers: Option<std::collections::HashMap<(u8, u8), u8>>,
        asic_registers: std::collections::HashMap<(u8, u8), u32>,
        bad_sensor_readback: bool,
    }
    impl ChainIo for RecordingChain {
        fn divisor(&self) -> u32 {
            self.divisor
        }
        fn set_divisor(&mut self, value: u32) {
            self.divisor = value;
        }
        fn command(&mut self, bytes: &[u8]) {
            self.commands.push(bytes.to_vec());
            if let Some(sensors) = &mut self.sensor_registers {
                let address = bytes[2];
                let register = bytes[3];
                if bytes[0] == 0x41 {
                    let mut value = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
                    if register == 0x1c {
                        let sensor_register = (value >> 8) as u8;
                        if value & (1 << 16) != 0 {
                            let read_register = if sensor_register == 9 {
                                3
                            } else {
                                sensor_register
                            };
                            sensors.insert((address, read_register), value as u8);
                        }
                        let read = sensors
                            .get(&(address, sensor_register))
                            .copied()
                            .unwrap_or(0);
                        value = (u32::from(sensor_register) << 8)
                            | u32::from(if self.bad_sensor_readback && sensor_register == 0x11 {
                                0
                            } else {
                                read
                            });
                    }
                    self.asic_registers.insert((address, register), value);
                } else if bytes[0] == 0x42 {
                    let value = self
                        .asic_registers
                        .get(&(address, register))
                        .copied()
                        .unwrap_or(0);
                    let mut reply = [0; 8];
                    reply[..4].copy_from_slice(&value.to_be_bytes());
                    reply[4] = address;
                    reply[5] = register;
                    self.replies.push_back(reply);
                }
            }
            if bytes == [0x52, 5, 0, 0] && self.enumerate_at == Some(self.divisor) {
                for _ in 0..self.enumerate_chips {
                    self.replies.push_back([0x13, 0x97, 0x18, 0, 0, 0, 0, 0]);
                }
            }
        }
        fn register_reply(&mut self) -> Option<[u8; 8]> {
            self.replies.pop_front()
        }
        fn work_full(&self) -> bool {
            self.full
        }
        fn write_work(&mut self, words: &[u32; 36]) -> Result<()> {
            if self.fail_write {
                bail!("injected FIFO write failure");
            }
            self.writes.push(*words);
            Ok(())
        }
        fn nonce(&mut self) -> Option<[u32; 2]> {
            None
        }
        fn flush_work(&mut self) {
            self.replies.clear();
        }
    }

    #[tokio::test]
    async fn s17_plus_sensor_initialization_applies_live_id_calibration_and_checks_readback() {
        for (id, model, offset) in [(0x1a, 1, 0xf8), (0x55, 2, 0xf5)] {
            let mut io = RecordingChain {
                sensor_registers: Some([((42, 0xfe), id)].into_iter().collect()),
                ..Default::default()
            };
            io.asic_registers.insert((42, 0x18), 0x1234_0070);
            let mut sensors = [SensorProfile {
                chip_address: 42,
                model: 7,
            }];
            initialize_sensors(&mut io, &mut sensors, true)
                .await
                .unwrap();
            assert_eq!(sensors[0].model, model);
            assert_eq!(io.asic_registers[&(42, 0x18)], 0x1234_4030);
            assert_eq!(io.asic_registers[&(42, 0x54)] & 7, 0);
            let regs = io.sensor_registers.as_ref().unwrap();
            assert_eq!(regs[&(42, 3)], 4);
            assert_eq!(regs[&(42, 0x11)], offset);
            // Commands are exact fixed production writes at device 0x98.
            assert!(io
                .commands
                .contains(&vec![0x41, 9, 42, 0x1c, 1, 0x99, 0x11, offset]));
            io.bad_sensor_readback = true;
            assert!(initialize_sensors(&mut io, &mut sensors, true)
                .await
                .is_err());
        }
        let mut io = RecordingChain {
            sensor_registers: Some([((42, 0xfe), 0xff)].into_iter().collect()),
            ..Default::default()
        };
        let mut sensors = [SensorProfile {
            chip_address: 42,
            model: 1,
        }];
        assert!(initialize_sensors(&mut io, &mut sensors, true)
            .await
            .is_err());
        assert!(!io.sensor_registers.unwrap().contains_key(&(42, 0x11)));
        // The Apr-2020 S17/T17 production routine has the same TMP451
        // offset/mux requirement; it admits ID55 and has no ID1a branch.
        let mut base = RecordingChain {
            sensor_registers: Some([((55, 0xfe), 0x55)].into_iter().collect()),
            ..Default::default()
        };
        let mut sensors = [SensorProfile {
            chip_address: 55,
            model: 1,
        }];
        initialize_sensors(&mut base, &mut sensors, false)
            .await
            .unwrap();
        assert_eq!(sensors[0].model, 2);
        assert_eq!(base.sensor_registers.as_ref().unwrap()[&(55, 0x11)], 0xf5);
        base.sensor_registers
            .as_mut()
            .unwrap()
            .insert((55, 0xfe), 0x1a);
        assert!(initialize_sensors(&mut base, &mut sensors, false)
            .await
            .is_err());
    }

    fn genesis_work() -> MiningWork {
        // Bitcoin block 0, an independent known SHA256d nonce vector.
        let merkle: [u8; 32] = [
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ];
        let header = dcentrald_stratum::v1::job::build_block_header(
            1, &[0; 32], &merkle, 1231006505, 0x1d00ffff, 2083236893,
        );
        let prefix: [u8; 64] = header[..64].try_into().unwrap();
        MiningWork {
            work_generation: dcentrald_stratum::work_domain::WorkGeneration { session: 1, job: 1 },
            midstates: vec![dcentrald_stratum::work::compute_midstate_from_prefix(
                &prefix,
            )],
            merkle4: merkle[28..].try_into().unwrap(),
            ntime: 1231006505,
            nbits: 0x1d00ffff,
            job_id: "genesis-fixture".into(),
            extranonce2: "00000000".into(),
            version: 1,
            version_mask: 0,
            share_target: dcentrald_stratum::work::difficulty_to_target(1.0),
            merkle_root: merkle,
            prev_block_hash: [0; 32],
        }
    }

    #[test]
    fn s17_native_dispatch_recovers_independent_bitcoin_nonce_and_submits_exact_share() {
        let mut io = RecordingChain::default();
        let mut ledger = WorkLedger::new();
        assert!(ledger.dispatch(&mut io, genesis_work()).unwrap());
        let share = ledger
            .validate([2083236893, 0], "tester.s17")
            .unwrap()
            .unwrap();
        assert_eq!(share.worker_name, "tester.s17");
        assert_eq!(share.nonce, "7c2bac1d");
        assert_eq!(share.ntime, "495fab29");
        assert_eq!(share.job_id, "genesis-fixture");
        assert_eq!(share.version, 1);
        assert!(share.version_bits.is_none());
        assert!(
            ledger
                .validate([2083236893, 0], "tester.s17")
                .unwrap()
                .is_none(),
            "duplicate nonce must not be submitted twice"
        );
        assert_eq!(io.writes[0][1], 0x1d00ffff);
        assert_eq!(io.writes[0][2], 1231006505);
        assert_eq!(io.writes[0].len(), 36);
    }

    #[test]
    fn s17_native_partial_write_backpressure_and_clean_job_cannot_authorize_stale_nonce() {
        let mut io = RecordingChain {
            full: true,
            ..Default::default()
        };
        let mut ledger = WorkLedger::new();
        assert!(!ledger.dispatch(&mut io, genesis_work()).unwrap());
        assert_eq!(ledger.next, 0);
        assert!(ledger.validate([2083236893, 0], "w").unwrap().is_none());
        io.full = false;
        io.fail_write = true;
        assert!(ledger.dispatch(&mut io, genesis_work()).is_err());
        assert!(ledger.validate([2083236893, 0], "w").unwrap().is_none());
        io.fail_write = false;
        ledger.dispatch(&mut io, genesis_work()).unwrap();
        ledger.invalidate();
        assert!(ledger.validate([2083236893, 0], "w").unwrap().is_none());
    }

    #[test]
    fn s17_native_real_builder_eight_midstates_fit_four_slot_fabric_and_pool_version() {
        let genesis = genesis_work();
        let job = JobTemplate {
            work_generation: genesis.work_generation,
            v1_work_domain: None,
            job_id: "rolled-fixture".into(),
            prev_block_hash: [0; 32],
            coinbase1: Vec::new(),
            coinbase2: Vec::new(),
            merkle_branches: Vec::new(),
            version: 0x2000_2000,
            nbits: genesis.nbits,
            ntime: genesis.ntime,
            clean_jobs: true,
            share_target: [0xff; 32],
            extranonce1: Vec::new(),
            extranonce2_size: 0,
            version_mask: 0x6000,
            merkle_root: genesis.merkle_root,
            pool_difficulty: 0.0,
        };
        let mut builder = WorkBuilder::new();
        builder.set_version_mask(job.version_mask);
        let work = builder.next_work(&job).unwrap();
        assert_eq!(
            work.midstates.len(),
            8,
            "exercise actual shared builder behavior"
        );
        let mut ledger = WorkLedger::new();
        let mut io = RecordingChain::default();
        ledger.dispatch(&mut io, work).unwrap();
        assert_eq!(io.writes[0].len(), 36);
        // Explicit expected versions include a base with masked bits set.
        // The permissive synthetic target isolates the pool wire contract;
        // the separate genesis test checks a real difficulty-one nonce.
        for (midstate, version) in [0x2000_2000u32, 0x2000_4000, 0x2000_6000, 0x2000_0000]
            .into_iter()
            .enumerate()
        {
            let share = ledger
                .validate([42, (midstate as u32) << 8], "w")
                .unwrap()
                .unwrap();
            let bits = u32::from_str_radix(share.version_bits.as_deref().unwrap(), 16).unwrap();
            let pool_reconstructed = (job.version & !job.version_mask) | (bits & job.version_mask);
            assert_eq!(share.version, version);
            assert_eq!(pool_reconstructed, version);
            let header = dcentrald_stratum::v1::job::build_block_header(
                version,
                &[0; 32],
                &job.merkle_root,
                job.ntime,
                job.nbits,
                42,
            );
            let midstate_bytes = dcentrald_stratum::work::compute_midstate_from_prefix(
                header[..64].try_into().unwrap(),
            );
            for index in 0..8 {
                assert_eq!(
                    io.writes[0][4 + midstate * 8 + index],
                    u32::from_be_bytes(
                        midstate_bytes[(7 - index) * 4..(8 - index) * 4]
                            .try_into()
                            .unwrap()
                    )
                );
            }
        }
    }

    #[test]
    fn s17_native_work_ids_and_validation_are_separate_for_each_chain() {
        let mut first = WorkLedger::new();
        let mut second = WorkLedger::new();
        let mut io = RecordingChain::default();
        first.dispatch(&mut io, genesis_work()).unwrap();
        let mut other = genesis_work();
        other.merkle_root[0] ^= 1;
        other.job_id = "other-chain".into();
        second.dispatch(&mut io, other).unwrap();
        assert!(first.validate([2083236893, 0], "w").unwrap().is_some());
        assert!(second.validate([2083236893, 0], "w").unwrap().is_none());
        assert!(second.validate([2083236894, 0], "w").unwrap().is_none());
    }

    #[test]
    fn s17_native_extended_work_id_survives_wire_wrap_and_fifo_depth() {
        let mut io = RecordingChain::default();
        let mut ledger = WorkLedger::new();
        for index in 0..65 {
            let mut work = genesis_work();
            work.job_id = format!("job-{index}");
            ledger.dispatch(&mut io, work).unwrap();
        }
        // FPGA restores ID high bits even though only seven wire bits travel
        // to the chip. Work IDs0,32,64 must retain different host metadata.
        for index in [0u32, 32, 64] {
            let share = ledger
                .validate([2083236893, (index << 2) << 8], "w")
                .unwrap()
                .unwrap();
            assert_eq!(share.job_id, format!("job-{index}"));
            assert_eq!(io.writes[index as usize][0], index << 2);
        }
        ledger.next = 16383;
        ledger.dispatch(&mut io, genesis_work()).unwrap();
        assert_eq!(io.writes.last().unwrap()[0], 0xfffc);
        assert_eq!(ledger.next, 0);
    }

    #[test]
    fn s17_native_fifo_reserves_a_complete_frame_before_any_write() {
        assert!(work_queue_has_complete_frame_space(4, 1848));
        assert!(work_queue_has_complete_frame_space(16, 1848));
        // !FULL alone says nothing about room for the remaining 35 words.
        assert!(!work_queue_has_complete_frame_space(0, 1848));
        assert!(!work_queue_has_complete_frame_space(8 | 16, 1848));
        assert!(!work_queue_has_complete_frame_space(16, 2048));
        assert!(!work_queue_has_complete_frame_space(16, 0));
    }

    #[test]
    fn s17_native_apw9_wire_plan_and_reply_have_stock_bus_protocol() {
        let steps = apw9_transaction_steps(0x9c);
        let writes: Vec<_> = steps
            .iter()
            .filter_map(|step| match step {
                I2cTransactionStep::Write(bytes) => Some(bytes.clone()),
                _ => None,
            })
            .collect();
        let expected: Vec<_> = [0x55, 0xaa, 6, 0x83, 0x9c, 0, 0x25, 1]
            .into_iter()
            .map(|byte| vec![0x11, byte])
            .collect();
        assert_eq!(writes, expected);
        assert_eq!(
            steps
                .iter()
                .filter(|step| matches!(step, I2cTransactionStep::Read(1)))
                .count(),
            8
        );
        assert!(apw9_reply(&[0x55, 0xaa, 6, 0x83, 0x9c, 0, 0x25, 1], 0x83).is_ok());
        assert!(apw9_reply(&[0x55, 0xaa, 6, 0x83, 0x9c, 0, 1, 0x25], 0x83).is_err());
        assert!(apw9_reply(&[0x55, 0xaa, 6, 0x83, 0x9c, 0, 0x25], 0x83).is_err());
    }

    #[test]
    fn s17_native_factory_defaults_need_no_external_voltage_or_sensor_file() {
        let profile = S17RuntimeProfile::builtin("am2-s17p").unwrap();
        assert!(profile.factory_defaults);
        assert_eq!(profile.frequency_mhz, 100);
        assert_eq!(
            profile.chains[0]
                .sensors
                .iter()
                .map(|sensor| sensor.chip_address)
                .collect::<Vec<_>>(),
            vec![55, 40, 180, 195]
        );
        for (board, part, addresses) in [
            ("am2-s17plus", "BHB07602", vec![42, 30, 162, 150]),
            ("am2-t17plus", "BHB07702", vec![55, 40, 175, 160]),
        ] {
            let plus = S17RuntimeProfile::builtin(board).unwrap();
            assert!(plus.factory_defaults);
            assert_eq!(plus.hashboard_part, part);
            assert_eq!(
                plus.chains[0]
                    .sensors
                    .iter()
                    .map(|sensor| sensor.chip_address)
                    .collect::<Vec<_>>(),
                addresses
            );
        }
        let t17 = S17RuntimeProfile::builtin("am2-t17").unwrap();
        assert_eq!(t17.hashboard_part, "BHB07701");
        assert_eq!(
            t17.chains[0]
                .sensors
                .iter()
                .map(|sensor| sensor.chip_address)
                .collect::<Vec<_>>(),
            vec![64, 48, 168, 184]
        );
    }

    #[tokio::test]
    async fn s17_native_divisor_discovery_requires_two_complete_read_only_enumerations() {
        let mut io = RecordingChain {
            divisor: 1,
            enumerate_at: Some(1),
            enumerate_chips: 48,
            ..Default::default()
        };
        assert_eq!(discover_divisor(&mut io, 48).await.unwrap(), 1);
        assert_eq!(io.commands, vec![vec![0x52, 5, 0, 0], vec![0x52, 5, 0, 0]]);
        let mut wrong = RecordingChain {
            divisor: 1,
            enumerate_at: Some(1),
            enumerate_chips: 49,
            ..Default::default()
        };
        assert!(discover_divisor(&mut wrong, 48).await.is_err());
    }

    #[test]
    fn s17_native_pic_checksum_and_correlated_reply_required() {
        assert_eq!(
            framed_reply(&[5, 0x17, 0x82, 0, 0x9e], 0x17).unwrap(),
            [0x82]
        );
        assert_eq!(
            framed_reply(&[6, 0x16, 1, 0, 0, 0x1d], 0x16).unwrap(),
            [1, 0]
        );
        assert!(framed_reply(&[5, 0x17, 0x82, 0, 0], 0x17).is_err());
        assert!(framed_reply(&[6, 0x16, 1, 0, 0, 0x1d], 0x17).is_err());
        assert!(framed_reply(&[0x16, 1], 0x16).is_err());
    }

    #[test]
    fn s17_native_physical_cutoff_is_active_low_and_requires_actual_io() {
        let root = std::env::temp_dir().join(format!(
            "s17-cutoff-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let gpio = root.join("gpio907");
        std::fs::create_dir_all(&gpio).unwrap();
        set_psu_gpio_at(&root, true).unwrap();
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "0");
        set_psu_gpio_at(&root, false).unwrap();
        assert_eq!(std::fs::read_to_string(gpio.join("value")).unwrap(), "1");
        assert_eq!(
            std::fs::read_to_string(gpio.join("direction")).unwrap(),
            "high"
        );
        std::fs::remove_file(gpio.join("value")).unwrap();
        std::fs::create_dir(gpio.join("value")).unwrap();
        assert!(
            set_psu_gpio_at(&root, false).is_err(),
            "failed physical write must not report successful cutoff"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}
