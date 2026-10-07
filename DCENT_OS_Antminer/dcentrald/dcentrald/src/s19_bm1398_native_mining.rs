// SPDX-License-Identifier: GPL-3.0-or-later
//! Native BM1398 mining (NBP1901, NBS1902, NBT1903, BHB28611 and BHB28701).
//! Per-bin profiles live in the `platform` submodule. Stock controller/
//! sensor dialects and modern FPGA transport evidence are retained in
//! campaign evidence/r07. No stock process is launched. One worker owns
//! PIC/APW/temperature I/O for the entire run.

use anyhow::{anyhow, bail, ensure, Context, Result};
use dcentrald_common::runtime_hardware_recipe::{PowerControlPolarity, RuntimeHardwareRecipe};
use dcentrald_common::s19_bm1398_runtime::{executor::*, Bm1398FpgaMidstateMode};
use dcentrald_hal::chain_backend::Bm1397PlusChainBackend;
use dcentrald_hal::fan::{Am2FanModePolicy, FanController, FanVariant};
use dcentrald_hal::fpga_chain::FpgaChain;
use dcentrald_hal::i2c::I2cServiceHandle;
#[cfg(test)]
use dcentrald_hal::i2c::I2cTransactionStep;
use dcentrald_hal::platform::am2_bm1398::fpga::{validate_fabric, Bm1398FpgaWorkConfig};
#[cfg(test)]
use dcentrald_hal::platform::am2_bm1398::nbp1901_temperature_steps as temperature_steps;
use dcentrald_hal::platform::am2_bm1398::{
    Am2Bm1398BoardKind, Am2Bm1398ChainIo, Am2Bm1398Custody, Am2Bm1398Io, Nbp1901PicService,
};
use dcentrald_hal::platform::HardwareMutationGateOwner;
use dcentrald_stratum::types::{JobTemplate, StratumStatus, ValidShare};
use dcentrald_stratum::work::{MiningWork, WorkBuilder};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use crate::config::DcentraldConfig;
#[path = "s19_bm1398_fabric_identity.rs"]
mod fabric_identity;
#[path = "s19_bm1398_platform.rs"]
pub(crate) mod platform;
use crate::runtime::safety_watchdog::{
    Bm1398WatchdogShutdownManifest, SafetyLiveness, SafetyWatchdogOwner, WatchdogDisarmPermit,
};
use crate::runtime::teardown_budget::{TeardownBudgetView, TeardownDisarmAuthority, TeardownStage};

#[derive(Debug)]
struct TerminalSafeOffError {
    source: anyhow::Error,
    _receipt: crate::runtime::safety_watchdog::WatchdogCloseoutReceipt,
}
impl std::fmt::Display for TerminalSafeOffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#}", self.source)
    }
}
impl std::error::Error for TerminalSafeOffError {}
pub(crate) fn is_terminal_safe_off_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<TerminalSafeOffError>().is_some())
}

/// Only this module can construct physical/actor completion evidence.
pub(crate) struct Bm1398SafeOffEvidence {
    budget: TeardownBudgetView,
    gpio_off: bool,
    all_pic_off: bool,
    actors_joined: bool,
}
impl Bm1398SafeOffEvidence {
    pub(crate) fn completed(&self) -> bool {
        self.gpio_off && self.all_pic_off && self.actors_joined
    }
    pub(crate) fn same_teardown_budget(&self, authority: &TeardownDisarmAuthority) -> bool {
        self.budget.same_budget(authority)
    }
}

/// JoinHandles detach on drop. Keep every API/router actor in an aborting
/// owner even when startup returns early or the enclosing future is cancelled.
struct OwnedActors {
    shutdown: CancellationToken,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}
impl OwnedActors {
    async fn stop_and_join(&mut self) -> bool {
        self.shutdown.cancel();
        for task in &self.tasks {
            task.abort();
        }
        let mut joined = true;
        for task in &mut self.tasks {
            joined &= tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .is_ok();
        }
        joined
    }
}
impl Drop for OwnedActors {
    fn drop(&mut self) {
        self.shutdown.cancel();
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn gpio_write_at(root: &std::path::Path, gpio: u32, high: bool) -> Result<()> {
    let pin = root.join(format!("gpio{gpio}"));
    if !pin.exists() {
        std::fs::write(root.join("export"), gpio.to_string())?;
    }
    // Atomic initial level avoids an output-direction transient.
    std::fs::write(pin.join("direction"), if high { "high" } else { "low" })?;
    let expected = if high { "1" } else { "0" };
    std::fs::write(pin.join("value"), expected)?;
    ensure!(
        std::fs::read_to_string(pin.join("value"))?.trim() == expected,
        "GPIO{gpio} readback mismatch"
    );
    Ok(())
}
fn gpio_write(gpio: u32, high: bool) -> Result<()> {
    gpio_write_at(std::path::Path::new("/sys/class/gpio"), gpio, high)
}
fn gpio_read(gpio: u32) -> Result<bool> {
    match std::fs::read_to_string(format!("/sys/class/gpio/gpio{gpio}/value"))?.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => bail!("GPIO{gpio} invalid input"),
    }
}

/// Retain the exact admitted wiring for this owner. A BM1398 chip identity
/// cannot establish the controller's electrical polarity.
#[derive(Debug)]
struct Bm1398PowerControl {
    polarity: PowerControlPolarity,
}

impl Bm1398PowerControl {
    fn capture(board_target: &str, recipe: Option<&RuntimeHardwareRecipe>) -> Result<Self> {
        let recipe = recipe.context("BM1398 power control requires an admitted hardware recipe")?;
        ensure!(
            recipe.board_target() == board_target,
            "BM1398 power control recipe belongs to another board target"
        );
        let polarity = recipe
            .gpio907_polarity()
            .context("BM1398 GPIO907 polarity is unproved for the exact hardware recipe")?;
        Ok(Self { polarity })
    }

    fn set_hash_power_at(&self, root: &std::path::Path, enabled: bool) -> Result<()> {
        require_bm1398_power_controller_at(root)?;
        let pin = root.join("gpio907");
        if !pin.exists() {
            std::fs::write(root.join("export"), "907")?;
        }
        ensure!(
            std::fs::read_to_string(pin.join("active_low"))?.trim() == "0",
            "BM1398 GPIO907 must expose raw levels (active_low=0)"
        );
        let off = self.polarity.off_level();
        gpio_write_at(root, 907, if enabled { !off } else { off })
    }

    fn set_hash_power(&self, enabled: bool) -> Result<()> {
        self.set_hash_power_at(std::path::Path::new("/sys/class/gpio"), enabled)
    }

    fn cut_power_checked(&self) -> Result<()> {
        self.set_hash_power(false)
    }

    fn require_off_level(&self, observed: bool) -> Result<()> {
        ensure!(
            observed == self.polarity.off_level(),
            "BM1398 power remains on"
        );
        Ok(())
    }
}

/// GPIO907 is PS bank line1 only with this exact observed Linux allocation.
/// A sibling controller or another kernel's numbering must never be driven.
fn require_bm1398_power_controller_at(root: &std::path::Path) -> Result<()> {
    let mut owners = 0;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_name().to_string_lossy().starts_with("gpiochip") {
            continue;
        }
        let path = entry.path();
        let base: u32 = std::fs::read_to_string(path.join("base"))?.trim().parse()?;
        let count: u32 = std::fs::read_to_string(path.join("ngpio"))?
            .trim()
            .parse()?;
        if base <= 907 && 907_u32.saturating_sub(base) < count {
            owners += 1;
            ensure!(
                base == 906 && count == 118,
                "BM1398 GPIO907 controller allocation differs from the stock PS bank"
            );
            let node = path.join("device/of_node");
            let compatible = std::fs::read(node.join("compatible"))?;
            ensure!(
                compatible
                    .split(|&b| b == 0)
                    .any(|s| s == b"xlnx,zynq-gpio-1.0"),
                "BM1398 GPIO907 is not the Zynq PS controller"
            );
            ensure!(
                std::fs::read(node.join("reg"))? == [0xe0, 0, 0xa0, 0, 0, 0, 0x10, 0],
                "BM1398 GPIO907 controller address differs from e000a000"
            );
        }
    }
    ensure!(
        owners == 1,
        "BM1398 GPIO907 requires exactly one observed PS bank owner"
    );
    Ok(())
}

fn uio_number(name: &str) -> Result<u8> {
    let mut matches = vec![];
    for entry in std::fs::read_dir("/sys/class/uio")? {
        let entry = entry?;
        if std::fs::read_to_string(entry.path().join("name"))?.trim() == name {
            matches.push(
                entry
                    .file_name()
                    .to_str()
                    .context("UIO name")?
                    .strip_prefix("uio")
                    .context("UIO index")?
                    .parse::<u8>()?,
            );
        }
    }
    ensure!(
        matches.len() == 1,
        "required unique UIO role {name} not found"
    );
    Ok(matches[0])
}

/// Commands and responses use the same FIFO opened by the runtime. Work
/// ownership remains in the executor; no second handle or raw serial driver.
struct CommandBackend {
    fifo: Arc<FpgaChain>,
    conversation: Mutex<()>,
}
impl CommandBackend {
    fn command(&self, bytes: &[u8]) -> dcentrald_hal::Result<()> {
        let _lock = self
            .conversation
            .lock()
            .map_err(|_| hal_error("command lock poisoned"))?;
        for chunk in bytes.chunks(4) {
            let mut word = [0; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            self.fifo.write_cmd(u32::from_le_bytes(word));
        }
        Ok(())
    }
    fn write_register(
        &self,
        address: Option<u8>,
        register: u8,
        value: u32,
    ) -> dcentrald_hal::Result<()> {
        let data = value.to_be_bytes();
        self.command(&[
            if address.is_some() { 0x41 } else { 0x51 },
            9,
            address.unwrap_or(0),
            register,
            data[0],
            data[1],
            data[2],
            data[3],
        ])
    }
}
fn hal_error(message: &str) -> dcentrald_hal::HalError {
    dcentrald_hal::HalError::Platform(message.into())
}
impl Bm1397PlusChainBackend for CommandBackend {
    #[cfg(feature = "sim-hal")]
    fn sim_owns_fpga(&self, fifo: &FpgaChain) -> bool {
        std::ptr::eq(self.fifo.as_ref(), fifo)
            && fifo.sim_chain_observer().is_ok()
            && [fifo.common.raw_fd(), fifo.cmd.raw_fd(), fifo.work_rx.raw_fd(), fifo.work_tx.raw_fd()]
                .iter().all(|fd| *fd == -1)
    }

    fn set_baud_rate(&self, baud: u32) -> dcentrald_hal::Result<()> {
        let divisor = match baud {
            115_200 => 108,
            dcentrald_common::s19_bm1398_runtime::BM1398_RUNTIME_WORK_BAUD => 7,
            _ => return Err(hal_error("unsupported BM1398 retained carrier baud")),
        };
        // The held modern setter uses100MHz/(8*(divisor+1)), independently
        // of the S9-only200MHz/16 helper. The exact donor and observed100MHz
        // FCLK are retained by FabricIdentity. Divisor7 is exact;108 keeps
        // the stock startup tolerance at115200.
        self.fifo.set_baud(divisor);
        if self.fifo.read_baud() != divisor {
            return Err(hal_error("NBP1901 baud readback mismatch"));
        }
        Ok(())
    }
    fn set_response_body_len(&self, length: usize) -> dcentrald_hal::Result<()> {
        if length != 7 {
            return Err(hal_error("BM1398 requires seven-byte body"));
        }
        Ok(())
    }
    fn send_get_address_bm1397plus(&self) -> dcentrald_hal::Result<()> {
        self.command(&[0x52, 5, 0, 0])
    }
    fn send_chain_inactive_bm1397plus(&self) -> dcentrald_hal::Result<()> {
        self.command(&[0x53, 5, 0, 0])
    }
    fn send_set_address_bm1397plus(&self, address: u8) -> dcentrald_hal::Result<()> {
        self.command(&[0x40, 5, address, 0])
    }
    fn send_write_reg_broadcast_bm1397plus(
        &self,
        reg: u8,
        value: u32,
    ) -> dcentrald_hal::Result<()> {
        self.write_register(None, reg, value)
    }
    fn send_write_reg_bm1397plus(
        &self,
        addr: u8,
        reg: u8,
        value: u32,
    ) -> dcentrald_hal::Result<()> {
        self.write_register(Some(addr), reg, value)
    }
    fn send_read_reg_bm1397plus(&self, addr: u8, reg: u8) -> dcentrald_hal::Result<()> {
        self.command(&[0x42, 5, addr, reg])
    }
    fn read_response_frame(&self, out: &mut [u8], timeout_ms: u64) -> dcentrald_hal::Result<usize> {
        if out.len() < 7 {
            return Err(hal_error("short BM1398 response buffer"));
        }
        let _lock = self
            .conversation
            .lock()
            .map_err(|_| hal_error("response lock poisoned"))?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms.min(30_000));
        loop {
            if let Some(first) = self.fifo.read_cmd_response() {
                let second_deadline = Instant::now() + Duration::from_millis(20);
                let second = loop {
                    if let Some(value) = self.fifo.read_cmd_response() {
                        break value;
                    }
                    if Instant::now() >= second_deadline {
                        return Err(hal_error("partial BM1398 FIFO response"));
                    }
                    std::thread::sleep(Duration::from_micros(100));
                };
                out[..4].copy_from_slice(&first.to_le_bytes());
                out[4..7].copy_from_slice(&second.to_le_bytes()[..3]);
                return Ok(7);
            }
            if Instant::now() >= deadline {
                return Ok(0);
            }
            std::thread::sleep(Duration::from_micros(100));
        }
    }
    fn read_all_responses(&self, timeout_ms: u64) -> dcentrald_hal::Result<Vec<Vec<u8>>> {
        let end = Instant::now() + Duration::from_millis(timeout_ms.min(30_000));
        let mut result = vec![];
        while Instant::now() < end {
            let mut body = [0; 7];
            if self.read_response_frame(&mut body, 1)? == 7 {
                result.push(body.to_vec());
            }
            if result.len() > 114 {
                return Err(hal_error("BM1398 response count exceeded geometry"));
            }
        }
        Ok(result)
    }
    fn send_work_frame(&self, _: &[u8]) -> dcentrald_hal::Result<()> {
        Err(hal_error("work belongs to native executor"))
    }
    fn poll_nonce_frame(&self, _: &mut [u8], _: u64) -> dcentrald_hal::Result<usize> {
        Err(hal_error("nonce belongs to native executor"))
    }
    fn chain_id(&self) -> u8 {
        self.fifo.chain_id
    }
    fn transport_label(&self) -> &'static str {
        "fpga-fifo-uio"
    }
}

fn decode_temperature(bytes: &[u8]) -> Result<f32> {
    ensure!(
        bytes.len() == 9 && bytes[..5] == [0x3b, 1, 7, 0x3c, 1],
        "NBP1901 PIC temperature acknowledgement mismatch"
    );
    let sum: u16 = bytes[2..7].iter().map(|v| u16::from(*v)).sum();
    ensure!(
        bytes[7..] == sum.to_be_bytes(),
        "NBP1901 PIC temperature checksum mismatch"
    );
    // LM75A is signed two's-complement, MSB first, 0.5 C in bit7.
    let raw = i16::from_be_bytes([bytes[5], bytes[6]]);
    ensure!(raw & 0x7f == 0, "NBP1901 LM75 reserved bits set");
    let value = f32::from(raw) / 256.0;
    ensure!(
        (-20.0..=125.0).contains(&value),
        "NBP1901 implausible temperature"
    );
    Ok(value)
}

struct ThermalSnapshot {
    sampled: Option<Instant>,
    maxima: BTreeMap<u8, f32>,
}
struct Custody {
    power_control: Bm1398PowerControl,
    i2c: I2cServiceHandle,
    pic: Nbp1901PicService,
    fabric: Mutex<fabric_identity::FabricIdentity>,
    board_control: dcentrald_hal::board_control::BoardControl,
    fan: Mutex<FanController>,
    slots: Vec<u8>,
    terminal: Mutex<bool>,
    thermal: tokio::sync::Mutex<ThermalSnapshot>,
    liveness: SafetyLiveness,
    shutdown: CancellationToken,
    pwm: u8,
    cutoff_c: f32,
    /// Bin label used in custody diagnostics ("NBP1901"/"NBS1902"/"NBT1903").
    /// The custody actions themselves are identical across the am2 BM1398
    /// family: every stock topol.conf row binds the same PIC1704 @ 0x20 +
    /// 4x LM75A, AWP12/APW12 @ 0x10 gpio 907 and four-fan C52 topology.
    label: &'static str,
}
impl Custody {
    async fn sample_health(&self) -> Result<()> {
        self.fabric
            .lock()
            .map_err(|_| anyhow!("fabric observation lock poisoned"))?
            .verify_unchanged()?;
        ensure!(
            !self.shutdown.is_cancelled(),
            "{} shutdown requested",
            self.label
        );
        ensure!(
            !*self
                .terminal
                .lock()
                .map_err(|_| anyhow!("power lock poisoned"))?,
            "{} terminal power cut",
            self.label
        );
        {
            ensure!(
                self.board_control.read_control_board_mode() & 0x1ff == 0x134,
                "{} stock board mode or two-PWM fan selection changed",
                self.label
            );
            let fan = self.fan.lock().map_err(|_| anyhow!("fan lock poisoned"))?;
            ensure!(
                fan.get_speed_pwm_channels() == (self.pwm, self.pwm),
                "{} PWM readback changed",
                self.label
            );
            ensure!(
                fan.get_tach_snapshot().all_required_channels_moving(),
                "{} fan stopped",
                self.label
            );
        }
        let mut thermal = self.thermal.lock().await;
        if thermal
            .sampled
            .is_some_and(|at| at.elapsed() < Duration::from_secs(1))
        {
            return Ok(());
        }
        let mut maxima = BTreeMap::new();
        for &slot in &self.slots {
            let mut maximum = -20.0_f32;
            for sensor in 0x48..=0x4b {
                let bytes = self
                    .pic
                    .read_temperature(slot, sensor)
                    .await
                    .map_err(anyhow::Error::msg)?;
                let value = decode_temperature(&bytes)?;
                ensure!(
                    value < self.cutoff_c,
                    "{} slot {slot} thermal cutoff: {value} C",
                    self.label
                );
                maximum = maximum.max(value);
            }
            maxima.insert(slot, maximum);
        }
        thermal.maxima = maxima;
        thermal.sampled = Some(Instant::now());
        self.liveness.mark_progress();
        Ok(())
    }
}
impl Am2Bm1398Custody for Custody {
    async fn start(&self, slots: &[u8]) -> std::result::Result<(), String> {
        async {
            ensure!(slots == self.slots, "{} custody slot mismatch", self.label);
            self.power_control.cut_power_checked()?;
            // Held modern runtime 0x2f6d40 checks board-control+0 bit8 then
            // ORs +4 bit8. Its error calls this UART mode switching; do not
            // invent a direct-UART/FIFO polarity from that string. Reproduce
            // the actual stock mutation. C52 low-byte selection is separately
            // established by the retained May21 AM2 four-fan capture.
            ensure!(
                self.board_control.read_board_id().0 & 0x100 != 0,
                "{} fabric lacks stock board UART-mode capability",
                self.label
            );
            self.board_control.enable_c52_fan_mode()?;
            self.board_control.set_control_board_mode_bit8()?;
            {
                let mut fan = self.fan.lock().map_err(|_| anyhow!("fan lock poisoned"))?;
                fan.set_speed(self.pwm);
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            // Query and confirm the thermal bridge dialect before using 3b/3c.
            for &slot in slots {
                let bytes = self
                    .pic
                    .read_version(slot)
                    .await
                    .map_err(anyhow::Error::msg)?;
                ensure!(
                    bytes == [5, 0x17, 0x89, 0, 0xa5],
                    "{} thermal bridge requires PIC89",
                    self.label
                );
            }
            self.sample_health().await
        }
        .await
        .map_err(|e| format!("{e:#}"))
    }
    async fn check_health(&self) -> std::result::Result<(), String> {
        self.sample_health().await.map_err(|e| format!("{e:#}"))
    }
    async fn hash_power(&self, enabled: bool) -> std::result::Result<(), String> {
        let terminal = self.terminal.lock().map_err(|_| "power lock poisoned")?;
        if enabled && *terminal {
            return Err(format!("{} energization permanently fenced", self.label));
        }
        self.power_control
            .set_hash_power(enabled)
            .map_err(|e| format!("{e:#}"))
    }
    async fn terminal_power_off(&self) -> std::result::Result<(), String> {
        let mut terminal = self.terminal.lock().map_err(|_| "power lock poisoned")?;
        *terminal = true;
        let cutoff = self.power_control.cut_power_checked();
        self.i2c.latch_terminal_safe_off();
        cutoff.map_err(|e| format!("{e:#}"))
    }
    async fn chain_reset(&self, slot: u8, asserted: bool) -> std::result::Result<(), String> {
        if !self.slots.contains(&slot) {
            return Err("reset slot not owned".into());
        }
        let terminal = self.terminal.lock().map_err(|_| "power lock poisoned")?;
        if !asserted && *terminal {
            return Err("reset release after terminal cutoff".into());
        }
        gpio_write(
            dcentrald_hal::board_control::AM2_RESET_GPIOS[usize::from(slot)],
            !asserted,
        )
        .map_err(|e| format!("{e:#}"))
    }
    async fn stop(&self) -> std::result::Result<(), String> {
        self.power_control
            .require_off_level(gpio_read(907).map_err(|e| format!("{e:#}"))?)
            .map_err(|e| format!("{}: {e:#}", self.label))?;
        Ok(()) // fan remains at its confirmed cooling duty after rail cutoff
    }
}

struct WorkLedger {
    slots: Vec<Option<MiningWork>>,
    next: u16,
    seen: HashSet<(u16, u8, u32)>,
    tickets: u64,
    recent: VecDeque<Instant>,
    first_dispatch: Option<Instant>,
    last_ticket: Option<Instant>,
    codec: Bm1398FpgaWorkConfig,
}
impl WorkLedger {
    fn new(codec: Bm1398FpgaWorkConfig) -> Self {
        Self {
            slots: vec![None; codec.host_work_id_slots() as usize],
            next: 0,
            seen: HashSet::new(),
            tickets: 0,
            recent: VecDeque::new(),
            first_dispatch: None,
            last_ticket: None,
            codec,
        }
    }
    fn invalidate(&mut self) {
        self.slots.fill(None);
        self.seen.clear();
        self.first_dispatch = None;
        self.last_ticket = None;
    }
    fn prepare(&mut self, work: &MiningWork) -> Result<Vec<u32>> {
        let count = 1_usize << self.codec.midstate_log2();
        // WorkBuilder may produce eight host midstates; the four-midstate
        // FIFO deliberately consumes the corresponding first four versions.
        ensure!(
            !work.midstates.is_empty() && work.midstates.len() <= 8,
            "BM1398 work midstate count"
        );
        let midstates: Vec<[u8; 32]> = (0..count)
            .map(|i| work.midstates[if i < work.midstates.len() { i } else { 0 }])
            .collect();
        self.slots[usize::from(self.next)] = None;
        self.codec
            .encode_work(self.next, work.nbits, work.ntime, work.merkle4, &midstates)
            .map_err(anyhow::Error::msg)
    }
    fn commit(&mut self, work: MiningWork) {
        self.seen.retain(|(id, _, _)| *id != self.next);
        self.slots[usize::from(self.next)] = Some(work);
        self.next = ((u32::from(self.next) + 1) % self.codec.host_work_id_slots()) as u16;
        self.first_dispatch.get_or_insert_with(Instant::now);
    }
    fn validate(&mut self, raw: (u32, u32), worker: &str) -> Result<Option<ValidShare>> {
        let extended = ((raw.1 >> 8) & 0xffff) as u16;
        let index = (extended & ((1 << self.codec.midstate_log2()) - 1)) as u8;
        let slot = extended >> self.codec.midstate_log2();
        let Some(Some(work)) = self.slots.get(usize::from(slot)) else {
            return Ok(None);
        };
        let midstate = if usize::from(index) < work.midstates.len() {
            usize::from(index)
        } else {
            0
        };
        let mut version = work.version;
        for _ in 0..midstate {
            let bits = dcentrald_stratum::work::increment_bitmask_pub(
                version & work.version_mask,
                work.version_mask,
            );
            version = (version & !work.version_mask) | bits;
        }
        let header = dcentrald_stratum::v1::job::build_block_header(
            version,
            &work.prev_block_hash,
            &work.merkle_root,
            work.ntime,
            work.nbits,
            raw.0,
        );
        let ticket = dcentrald_stratum::work::validate_full_header(
            &header,
            &dcentrald_stratum::work::difficulty_to_target(1.0),
        );
        let pool = dcentrald_stratum::work::validate_full_header(&header, &work.share_target);
        if (!ticket && !pool) || !self.seen.insert((slot, index, raw.0)) {
            return Ok(None);
        }
        if ticket {
            self.tickets += 1;
            self.last_ticket = Some(Instant::now());
            self.recent.push_back(Instant::now());
        }
        if !pool {
            return Ok(None);
        }
        Ok(Some(ValidShare {
            work_generation: work.work_generation,
            worker_name: worker.into(),
            job_id: work.job_id.clone(),
            extranonce2: work.extranonce2.clone(),
            ntime: format!("{:08x}", work.ntime),
            nonce: format!("{:08x}", raw.0),
            version_bits: dcentrald_stratum::work::bip310_version_bits(version, work.version_mask),
            version,
            achieved_difficulty: None,
        }))
    }
}

/// Watchdog route label per family member (diagnostic identity only; the
/// route scope itself is the generic BM1398 claim).
fn platform_route(platform: platform::Bm1398Platform) -> &'static str {
    match platform {
        platform::Bm1398Platform::S19Pro => "nbp1901-native",
        platform::Bm1398Platform::S19Classic => "nbs1902-native",
        platform::Bm1398Platform::T19 => "nbt1903-native",
        platform::Bm1398Platform::S19a => "bhb28611-native",
        platform::Bm1398Platform::S19Plus => "bhb28701-native",
    }
}

/// Stock topol.conf board name used in custody diagnostics.
fn platform_stock_name(platform: platform::Bm1398Platform) -> &'static str {
    match platform {
        platform::Bm1398Platform::S19Pro => "NBP1901",
        platform::Bm1398Platform::S19Classic => "NBS1902",
        platform::Bm1398Platform::T19 => "NBT1903",
        platform::Bm1398Platform::S19a => "BHB28611",
        platform::Bm1398Platform::S19Plus => "BHB28701",
    }
}

fn selected_native_slots(present: [bool; 4]) -> Result<Vec<u8>> {
    // The retained PIC/EEPROM owner supports slots0..2. Stock chain_num=4
    // names software capacity, not permission to ignore an extra board or
    // invent a fourth electrical owner.
    ensure!(
        !present[3],
        "BM1398 fourth connector is populated but has no retained electrical owner"
    );
    let slots: Vec<_> = present[..3]
        .iter()
        .enumerate()
        .filter_map(|(slot, &present)| present.then_some(slot as u8))
        .collect();
    ensure!(!slots.is_empty(), "BM1398 reports no connected hashboards");
    Ok(slots)
}

pub(crate) async fn run(
    config: DcentraldConfig,
    shutdown: CancellationToken,
    state_tx: Option<watch::Sender<dcentrald_api::MinerState>>,
    admission: crate::SerialRuntimeDispatchAdmission,
) -> Result<()> {
    // Exact am2-s19pro/am2-s19/am2-t19/am2-s19a board target
    // with exact BM1398 dispatch identity, resolved to one bin profile. The
    // per-bin guards below (board_target file, factory/EEPROM join, stock
    // ladder, fabric identity) carry the hardware-identity burden.
    let platform =
        platform::Bm1398Platform::from_admission(admission.board_target(), admission.identity())
            .map_err(anyhow::Error::msg)?;
    // Refuse unknown polarity and a conflicting GPIO controller before GPIO,
    // I2C, UIO or fan construction. The recipe contains parameters only;
    // signed dispatch admission and physical EEPROM identity remain required.
    let power_control = Bm1398PowerControl::capture(
        platform.board_target(),
        dcentrald_common::runtime_hardware_recipe::installed(),
    )?;
    require_bm1398_power_controller_at(std::path::Path::new("/sys/class/gpio"))?;
    let software_closeout_run =
        dcentrald_common::mutation_disposition::capture_software_closeout_run(
            platform.board_target(),
        );
    let route = platform_route(platform);
    tracing::info!(%platform, %route, "BM1398 native family runtime admitted");
    ensure!(
        std::fs::read_to_string("/etc/dcentos/board_target")?.trim() == platform.board_target(),
        "{platform} image identity changed"
    );
    let (frequency_mhz, voltage_cv) = platform
        .resolve_operating_point(config.mining.frequency_mhz, config.mining.voltage_mv)
        .map_err(anyhow::Error::msg)?;
    let pwm = config.thermal.fan_max_pwm.min(30);
    ensure!(pwm > 0, "{platform} requires cooling duty");
    let i2c = dcentrald_hal::i2c::spawn_i2c_service_no_register_touch_with_denylist(
        0,
        (0x50..=0x57).collect(),
    )?;
    let mut present = [false; 4];
    for (slot, value) in present.iter_mut().enumerate() {
        *value = gpio_read(dcentrald_hal::board_control::AM2_PLUG_DETECT_GPIOS[slot])?;
    }
    let slots = selected_native_slots(present)?;
    let mut handles = BTreeMap::new();
    let mut transport = BTreeMap::new();
    let mut fabric_identity = fabric_identity::FabricIdentity::open()?;
    for &slot in &slots {
        let physical = slot + 1;
        let base = uio_number(&format!("chain{physical}-common"))?;
        for (offset, role) in [(1, "cmd-rx"), (2, "work-rx"), (3, "work-tx")] {
            ensure!(
                uio_number(&format!("chain{physical}-{role}"))? == base + offset,
                "{platform} UIO group mismatch"
            );
        }
        let fifo = Arc::new(FpgaChain::open(slot, base)?);
        let fabric = validate_fabric(&fifo).map_err(anyhow::Error::msg)?;
        fabric_identity.observe_build(fabric.build_timestamp)?;
        tracing::info!(slot, ?platform, ?fabric, "observed FIFO fabric");
        handles.insert(slot, fifo.clone());
        transport.insert(
            slot,
            Am2Bm1398ChainIo {
                commands: Arc::new(CommandBackend {
                    fifo: fifo.clone(),
                    conversation: Mutex::new(()),
                }),
                fifo,
            },
        );
    }
    let (fan_discovery, mut fan) =
        FanController::open_discovered_with_mode_policy(Am2FanModePolicy::Preserve)?;
    ensure!(
        fan_discovery.variant == FanVariant::Am2Uio16,
        "{platform} requires AM2 fan ABI"
    );
    fan.set_profile_cap(pwm);
    let mutation_owner = HardwareMutationGateOwner::new_pending();
    let state_tx = state_tx.unwrap_or_else(|| {
        watch::channel(dcentrald_api::MinerState::empty(
            dcentrald_api::OperatingMode::Standard,
        ))
        .0
    });
    let api_shutdown = shutdown.child_token();
    let api = crate::runtime::api::spawn_proxy_mode_api_with_state_and_hardware_mutation_gate(
        config.clone(),
        dcentrald_api::RuntimeHealthMode::Native,
        None,
        Some(state_tx.subscribe()),
        mutation_owner.gate(),
        api_shutdown.clone(),
    )
    .await?;
    let mut actors = OwnedActors {
        shutdown: api_shutdown,
        tasks: vec![api.0, api.1],
    };
    let liveness = SafetyLiveness::default();
    let pic = Nbp1901PicService::new(i2c.clone()).map_err(anyhow::Error::msg)?;
    let board_kind = match platform {
        platform::Bm1398Platform::S19Pro => Am2Bm1398BoardKind::Nbp1901,
        platform::Bm1398Platform::S19Classic => Am2Bm1398BoardKind::Nbs1902,
        platform::Bm1398Platform::T19 => Am2Bm1398BoardKind::Nbt1903,
        platform::Bm1398Platform::S19a => Am2Bm1398BoardKind::Bhb28611,
        platform::Bm1398Platform::S19Plus => Am2Bm1398BoardKind::Bhb28701,
    };
    let custody = Arc::new(Custody {
        power_control,
        i2c: i2c.clone(),
        pic: pic.clone(),
        fabric: Mutex::new(fabric_identity),
        board_control: dcentrald_hal::board_control::BoardControl::open(uio_number(
            "board-control",
        )?)?,
        fan: Mutex::new(fan),
        slots: slots.clone(),
        terminal: Mutex::new(false),
        thermal: tokio::sync::Mutex::new(ThermalSnapshot {
            sampled: None,
            maxima: BTreeMap::new(),
        }),
        liveness: liveness.clone(),
        shutdown: shutdown.clone(),
        pwm,
        cutoff_c: f32::from(config.thermal.dangerous_temp_c.min(80)),
        label: platform_stock_name(platform),
    });
    let enumeration = dcentrald_common::serial_chain_proof::PacedEnumerationPolicy::new(
        Duration::from_millis(5),
        Duration::from_millis(10),
        Duration::from_millis(2000),
        1,
    )
    .map_err(anyhow::Error::msg)?;
    let runtime_config = Bm1398RuntimeConfig {
        plan: platform.desk_plan(enumeration, Bm1398FpgaMidstateMode::Four),
        active_chains: slots.clone(),
        frequency_mhz,
        voltage_cv,
    };
    let codec =
        Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Four, runtime_config.work_interval())
            .map_err(anyhow::Error::msg)?;
    let io = Am2Bm1398Io::from_system_for_board(pic, transport, custody.clone(), board_kind)
        .await
        .map_err(anyhow::Error::msg)?;
    let mut runtime = Bm1398Runtime::new(platform.board_target(), runtime_config, io)
        .map_err(anyhow::Error::msg)?;
    let (mut watchdog, armed) = SafetyWatchdogOwner::start_before_energizing(
        &config.watchdog,
        Duration::from_secs(180),
        Duration::from_secs(2),
        liveness.clone(),
    )
    .await?;
    armed.require_armed(route)?;
    let route_scope = watchdog.claim_bm1398_route_scope()?;
    let result = match runtime.start().await {
        Ok(()) => match watchdog.enter_mining().await {
            Ok(()) => {
                mining_loop(
                    &config,
                    &shutdown,
                    &state_tx,
                    &custody,
                    &handles,
                    &mut runtime,
                    codec,
                    frequency_mhz,
                    voltage_cv,
                    platform.chips_per_chain(),
                    &mut actors,
                )
                .await
            }
            Err(error) => Err(error),
        },
        Err(error) => Err(error.into()),
    };
    // Budget publication and physical cut precede all asynchronous cleanup.
    let teardown_request = watchdog.request_teardown_budget();
    let cutoff_started = Instant::now();
    let gpio_off = custody.terminal_power_off().await.is_ok();
    let cutoff_finished = Instant::now();
    let fabric = i2c.latch_terminal_safe_off();
    let stopped = runtime.shutdown().await;
    let all_pic_off = stopped.is_ok();
    for fifo in handles.values() {
        fifo.flush_work_tx();
        fifo.flush_work_rx();
    }
    let actors_joined = actors.stop_and_join().await;
    let cleanup = async {
        let (budget, teardown_admission) = teardown_request?.into_parts();
        let view = budget.view();
        watchdog
            .observe_teardown_admission(teardown_admission, &view)
            .await
            .map_err(anyhow::Error::msg)?;
        view.require_completed_at(TeardownStage::CutoffStart, cutoff_started)?;
        view.require_completed_at(TeardownStage::CutoffComplete, cutoff_finished)?;
        let api_drain =
            mutation_owner.close_and_drain_until(view.deadline(TeardownStage::CleanupComplete))?;
        let api_commit = match mutation_owner.revoke_commit_fence().try_wait() {
            dcentrald_hal::platform::HardwareMutationCommitFenceTryWait::Fenced(receipt) => receipt,
            _ => bail!("NBP1901 API final commit did not quiesce"),
        };
        view.require_completed_at(TeardownStage::CleanupComplete, Instant::now())?;
        let safe_off = Bm1398SafeOffEvidence {
            budget: view,
            gpio_off,
            all_pic_off,
            actors_joined,
        };
        let authority = budget.begin_disarm_at(Instant::now())?;
        WatchdogDisarmPermit::from_bm1398_manifest(Bm1398WatchdogShutdownManifest::new(
            route_scope,
            api_drain,
            api_commit,
            fabric,
            safe_off,
            authority,
        ))
    }
    .await;
    match cleanup {
        Ok(permit) => {
            let receipt = watchdog
                .disarm_and_join(permit, Duration::from_secs(2))
                .await?;
            match result {
                Ok(()) => crate::daemon::publish_orderly_software_closeout(
                    software_closeout_run,
                    &receipt,
                ),
                Err(source) => Err(anyhow::Error::new(TerminalSafeOffError {
                    source,
                    _receipt: receipt,
                })),
            }
        }
        Err(error) => {
            let _ = watchdog
                .suppress_feeds_terminally(format!("{route} shutdown incomplete: {error:#}"))
                .await;
            Err(
                crate::runtime::safety_watchdog::watchdog_reset_pending_error(
                    route,
                    format!("{error:#}"),
                ),
            )
        }
    }
}

/// Commit attribution only after the retained transport accepted the entire
/// frame. Replays exercise this same owner boundary as the hardware loop.
async fn dispatch_work<I: Bm1398RuntimeIo>(
    ledger: &mut WorkLedger,
    runtime: &mut Bm1398Runtime<I>,
    slot: u8,
    work: MiningWork,
) -> Result<()> {
    let words = ledger.prepare(&work)?;
    runtime.submit_work(slot, &words).await?;
    ledger.commit(work);
    Ok(())
}

fn publish_nonce(
    ledger: &mut WorkLedger,
    raw: (u32, u32),
    worker: &str,
    shares: &tokio::sync::mpsc::Sender<ValidShare>,
) -> Result<()> {
    if let Some(share) = ledger.validate(raw, worker)? {
        shares
            .try_send(share)
            .context("BM1398 share queue unavailable")?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn mining_loop(
    config: &DcentraldConfig,
    shutdown: &CancellationToken,
    state: &watch::Sender<dcentrald_api::MinerState>,
    custody: &Arc<Custody>,
    handles: &BTreeMap<u8, Arc<FpgaChain>>,
    runtime: &mut Bm1398Runtime<Am2Bm1398Io<Custody>>,
    codec: Bm1398FpgaWorkConfig,
    frequency: u16,
    voltage: u16,
    chips: u16,
    actors: &mut OwnedActors,
) -> Result<()> {
    let label = custody.label;
    let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<JobTemplate>(16);
    let (share_tx, share_rx) = tokio::sync::mpsc::channel::<ValidShare>(128);
    let (status_tx, mut status_rx) = tokio::sync::mpsc::channel::<StratumStatus>(128);
    let pool_config = crate::config::build_stratum_config_with_enumerated_chips(
        config,
        crate::config::stratum_donation_config(&config.donation),
        config.mining.version_rolling,
        false,
        Some(handles.len() as u32 * u32::from(chips)),
    );
    let worker = pool_config.pool1.worker.clone();
    actors.tasks.push(tokio::spawn(
        dcentrald_stratum::StratumRouter::new(pool_config).run(job_tx, share_rx, status_tx),
    ));
    let mut ledgers: BTreeMap<u8, WorkLedger> = handles
        .keys()
        .map(|&slot| (slot, WorkLedger::new(codec)))
        .collect();
    let mut builder = WorkBuilder::new();
    let mut job: Option<JobTemplate> = None;
    let mut poll = tokio::time::interval(Duration::from_millis(2));
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut publish = tokio::time::interval(Duration::from_secs(2));
    publish.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let started = Instant::now();
    loop {
        tokio::select! {
            biased;
            _=shutdown.cancelled()=>return Ok(()),
            status=status_rx.recv()=>match status {
                Some(StratumStatus::ShareAccepted{..})=>state.send_modify(|s|s.accepted+=1),
                Some(StratumStatus::ShareRejected{..})=>state.send_modify(|s|s.rejected+=1),
                Some(StratumStatus::DifficultyChanged(d))=>state.send_modify(|s|s.pool.difficulty=d),
                Some(StratumStatus::StateChanged(status))=>{
                    state.send_modify(|s|s.pool.status=format!("{status:?}").to_lowercase());
                    if !matches!(status,dcentrald_stratum::types::StratumState::Mining|dcentrald_stratum::types::StratumState::Donating){
                        job=None;for (&slot,ledger) in &mut ledgers{handles[&slot].flush_work_tx();handles[&slot].flush_work_rx();ledger.invalidate();}
                    }
                },
                Some(status)=>tracing::debug!(?status,"{label} pool status"),
                None=>bail!("{label} Stratum status task exited"),
            },
            next=job_rx.recv()=>{
                let next=next.with_context(||format!("{label} Stratum job task exited"))?;
                for (&slot,ledger) in &mut ledgers{handles[&slot].flush_work_tx();handles[&slot].flush_work_rx();ledger.invalidate();}
                builder.set_version_mask(next.version_mask);job=Some(next);
            },
            _=poll.tick()=>{
                for (&slot,ledger) in &mut ledgers {
                    for _ in 0..128 {
                        let Some(raw)=runtime.transport().poll_nonce(slot).await.map_err(anyhow::Error::msg)? else{break};
                        publish_nonce(ledger,raw,&worker,&share_tx)?;
                    }
                    if let Some(template)=&job {
                        if codec.can_enqueue(&handles[&slot]).map_err(anyhow::Error::msg)?{
                            let work=builder.next_work(template)?;
                            dispatch_work(ledger,runtime,slot,work).await?;
                        }
                    }
                }
            },
            _=publish.tick()=>{
                custody.sample_health().await?;
                let maxima=custody.thermal.lock().await.maxima.clone();
                let fan=custody.fan.lock().map_err(|_|anyhow!("fan lock poisoned"))?.get_tach_snapshot();
                let elapsed=started.elapsed().as_secs_f64().max(1.0);
                let now=Instant::now();
                for (&slot,ledger) in &mut ledgers {
                    while ledger.recent.front().is_some_and(|at|now.duration_since(*at)>Duration::from_secs(5)){ledger.recent.pop_front();}
                    if job.is_some(){if let Some(last)=ledger.last_ticket.or(ledger.first_dispatch){ensure!(last.elapsed()<Duration::from_secs(60),"{label} slot {slot} has no verified tickets for60s");}}
                }
                state.send_modify(|s|{
                    s.uptime_s=started.elapsed().as_secs();
                    s.hashrate_ghs=ledgers.values().map(|l|l.tickets as f64*4.294967296/elapsed).sum();
                    s.hashrate_5s_ghs=ledgers.values().map(|l|l.recent.len() as f64*4.294967296/elapsed.min(5.0)).sum();
                    s.chains=ledgers.iter().map(|(&slot,l)|dcentrald_api::ChainState{id:(slot as u8)+1,chips:chips as u8,frequency_mhz:frequency,
                        voltage_mv:voltage*10,temp_c:maxima[&slot],temp_source:Some(dcentrald_api::ChainTempSource::BOARD_SENSOR.into()),
                        hashrate_ghs:l.tickets as f64*4.294967296/elapsed,errors:0,status:if job.is_some(){"mining"}else{"waiting_for_pool"}.into()}).collect();
                    s.fans.pwm=custody.pwm;s.fans.rpm=fan.rpm_by_physical_fan.first().copied().flatten().unwrap_or(0);
                    s.fans.per_fan=fan.rpm_by_physical_fan.iter().enumerate().map(|(i,rpm)|dcentrald_api::PerFanReading{id:i as u8,rpm:rpm.unwrap_or(0),pwm_percent:custody.pwm}).collect();
                });
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "sim-hal")]
    include!("s19_bm1398_adapter_pool_tests.rs");
    use dcentrald_common::{serial_chain_proof::PacedEnumerationPolicy, TransportOp};

    #[test]
    fn connector_census_never_silently_ignores_an_unowned_board() {
        for mask in 0_u8..16 {
            let present = std::array::from_fn(|slot| mask & (1 << slot) != 0);
            let selected = selected_native_slots(present);
            assert_eq!(selected.is_ok(), mask != 0 && mask & 8 == 0);
            if let Ok(slots) = selected {
                assert_eq!(slots.len(), mask.count_ones() as usize);
                assert!(slots.iter().all(|&slot| present[usize::from(slot)]));
            }
        }
    }

    #[test]
    fn every_native_baked_default_is_idle_first_and_uses_its_own_stock_point() {
        use platform::Bm1398Platform as P;
        for (platform, raw) in [
            (
                P::S19Pro,
                include_str!("../../configs/dcentrald_s19pro_am2_baked_default.toml"),
            ),
            (
                P::S19Classic,
                include_str!("../../configs/dcentrald_s19_am2_baked_default.toml"),
            ),
            (
                P::T19,
                include_str!("../../configs/dcentrald_t19_am2_baked_default.toml"),
            ),
            (
                P::S19a,
                include_str!("../../configs/dcentrald_s19a_am2_baked_default.toml"),
            ),
            (
                P::S19Plus,
                include_str!("../../configs/dcentrald_s19plus_am2_baked_default.toml"),
            ),
        ] {
            let config: DcentraldConfig = toml::from_str(raw).unwrap();
            config.validate().unwrap();
            assert!(!config.mining.enabled);
            assert!(!config.autotuner.enabled);
            assert!(!config.hash_on_disconnect.enabled);
            assert_eq!(config.mining.serial_chip_type.as_deref(), Some("BM1398"));
            assert_eq!(
                config.mining.serial_chip_count,
                Some(platform.chips_per_chain() as u8)
            );
            assert_eq!(
                platform
                    .resolve_operating_point(config.mining.frequency_mhz, config.mining.voltage_mv)
                    .unwrap(),
                platform.default_operating_point()
            );
            assert!(config.thermal.fan_max_pwm > 0 && config.thermal.fan_max_pwm <= 30);
            assert!(config.watchdog.enabled);
            assert!(config.thermal.supervisor.enabled);
        }
    }

    struct OwnerReplayIo {
        model: dcentrald_common::s19_bm1398_runtime::Bm1398HybridModel,
        observed_names: Mutex<Vec<Option<String>>>,
        events: Vec<Bm1398RuntimeAction>,
        fail_work: std::sync::atomic::AtomicBool,
        misc_control: BTreeMap<u8, u32>,
        fail_register_read: std::sync::atomic::AtomicUsize,
        register_reads: usize,
    }

    impl Bm1398RuntimeIo for OwnerReplayIo {
        async fn execute(
            &mut self,
            action: &Bm1398RuntimeAction,
        ) -> std::result::Result<Bm1398RuntimeReply, String> {
            self.events.push(action.clone());
            use Bm1398RuntimeAction as A;
            use Bm1398RuntimeReply as R;
            match action {
                A::VerifyFactoryIdentity { chain } => Ok(R::FactoryIdentity {
                    stock_board_name: self.observed_names.lock().unwrap()[usize::from(*chain)]
                        .clone(),
                    serial: format!("synthetic-slot-{chain}"),
                }),
                A::ReadChipAddresses { .. } => Ok(R::ChipAddresses(
                    (0..self.model.chips_per_chain())
                        .map(|chip| (chip as u8 * self.model.address_interval(), 0x1398))
                        .collect(),
                )),
                A::ReadMiscControl { chain } => {
                    self.register_reads += 1;
                    if self
                        .fail_register_read
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == self.register_reads
                    {
                        return Ok(R::Complete); // Missing or malformed register response.
                    }
                    Ok(R::RegisterValue(
                        *self.misc_control.get(chain).unwrap_or(&0x0000_7a31),
                    ))
                }
                A::Asic {
                    chain,
                    operation: TransportOp::SendWriteRegBroadcastBm1397Plus { reg: 0x18, value },
                } => {
                    self.misc_control.insert(*chain, *value);
                    Ok(R::Complete)
                }
                A::I2c(exchange) => {
                    let bytes = match exchange.endpoint {
                        Bm1398FramedEndpoint::Pic { .. } => match exchange.request[3] {
                            0x17 => vec![5, 0x17, 0x89, 0, 0xa5],
                            0x15 => vec![0x15, 1],
                            0x16 => vec![6, 0x16, 1, 0, 0, 0],
                            _ => return Err("unexpected PIC request".into()),
                        },
                        Bm1398FramedEndpoint::Apw12 => {
                            let command = exchange.request[3];
                            let value = if command == 2 { 0x71 } else { 0 };
                            let checksum = 6_u16 + u16::from(command) + u16::from(value);
                            vec![
                                0x55,
                                0xaa,
                                6,
                                command,
                                value,
                                0,
                                checksum as u8,
                                (checksum >> 8) as u8,
                            ]
                        }
                    };
                    Ok(R::Bytes(bytes))
                }
                A::Work { .. } if self.fail_work.load(std::sync::atomic::Ordering::Relaxed) => {
                    Err("injected whole-frame transport failure".into())
                }
                _ => Ok(R::Complete),
            }
        }
    }

    fn owner_replay(platform: platform::Bm1398Platform) -> Bm1398Runtime<OwnerReplayIo> {
        let (frequency_mhz, voltage_cv) = platform.default_operating_point();
        let model = platform.model();
        let plan = platform.desk_plan(
            PacedEnumerationPolicy::new(
                Duration::from_millis(1),
                Duration::from_millis(1),
                Duration::from_millis(10),
                2,
            )
            .unwrap(),
            Bm1398FpgaMidstateMode::Four,
        );
        Bm1398Runtime::new(
            platform.board_target(),
            Bm1398RuntimeConfig {
                plan,
                active_chains: vec![0, 1, 2],
                frequency_mhz,
                voltage_cv,
            },
            OwnerReplayIo {
                model,
                observed_names: Mutex::new(vec![Some(model.stock_board_names()[0].into()); 3]),
                events: vec![],
                fail_work: std::sync::atomic::AtomicBool::new(false),
                misc_control: BTreeMap::new(),
                fail_register_read: std::sync::atomic::AtomicUsize::new(0),
                register_reads: 0,
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn every_stock_profile_runs_actual_work_nonce_and_submit_owners() {
        // Synthetic hardware replies, independently-known Bitcoin genesis
        // nonce. No claim that these are physical EEPROM or wire captures.
        for platform in platform::Bm1398Platform::ALL {
            let mut runtime = owner_replay(platform);
            runtime.start().await.unwrap();
            let mut ledger = ledger();
            let (shares, mut received) = tokio::sync::mpsc::channel(4);
            dispatch_work(&mut ledger, &mut runtime, 0, genesis_work())
                .await
                .unwrap();
            publish_nonce(&mut ledger, (2083236893, 0), "owner.worker", &shares).unwrap();
            let share = received.try_recv().unwrap();
            assert_eq!(share.worker_name, "owner.worker");
            assert_eq!(share.nonce, "7c2bac1d");
            assert_eq!(share.job_id, "nbp1901-genesis");
            publish_nonce(&mut ledger, (2083236893, 0), "owner.worker", &shares).unwrap();
            assert!(received.try_recv().is_err(), "duplicates never resubmit");
            let trace = &runtime.transport().events;
            for chain in 0..3 {
                let baud = trace
                    .iter()
                    .position(|action| {
                        matches!(action, Bm1398RuntimeAction::Asic {
                    chain: slot, operation: TransportOp::SetBaudRate { baud: 1_562_500 }
                } if *slot == chain)
                    })
                    .unwrap();
                assert_eq!(trace[baud - 1], Bm1398RuntimeAction::DelayMs(50));
                assert!(
                    trace[..baud - 2].iter().any(|action| matches!(action,
                        Bm1398RuntimeAction::ConfigureWork { chain: slot, .. } if *slot == chain
                    )),
                    "carrier setup must precede the ASIC/host baud transition"
                );
                assert!(!trace[baud + 1..].iter().any(|action| matches!(action,
                    Bm1398RuntimeAction::ConfigureWork { chain: slot, .. } if *slot == chain
                )));
                assert_eq!(
                    trace[baud - 2],
                    Bm1398RuntimeAction::Asic {
                        chain,
                        operation: TransportOp::SendWriteRegBroadcastBm1397Plus {
                            reg: 0x18,
                            value: 0x6131
                        },
                    }
                );
                assert_eq!(
                    trace[baud + 1],
                    Bm1398RuntimeAction::ReadMiscControl { chain }
                );
            }
            assert_eq!(
                trace
                    .iter()
                    .filter(|a| matches!(
                        a,
                        Bm1398RuntimeAction::Asic {
                            operation: TransportOp::SendSetAddressBm1397Plus { .. },
                            ..
                        }
                    ))
                    .count(),
                usize::from(platform.chips_per_chain()) * 3
            );
            assert!(trace.iter().any(
                |a| matches!(a, Bm1398RuntimeAction::Work { words, .. } if words.len() == 36)
            ));
            let stopped_at = runtime.transport().events.len();
            runtime.shutdown().await.unwrap();
            assert_eq!(
                runtime.transport().events[stopped_at],
                Bm1398RuntimeAction::TerminalPowerOff
            );
        }
    }

    #[tokio::test]
    async fn failed_baud_observation_or_readback_cuts_power_before_work() {
        for platform in platform::Bm1398Platform::ALL {
            for failed_read in 1..=6 {
                let mut runtime = owner_replay(platform);
                runtime
                    .transport()
                    .fail_register_read
                    .store(failed_read, std::sync::atomic::Ordering::Relaxed);
                assert!(runtime.start().await.is_err());
                let trace = &runtime.transport().events;
                assert!(trace
                    .iter()
                    .any(|a| matches!(a, Bm1398RuntimeAction::TerminalPowerOff)));
                assert!(!trace
                    .iter()
                    .any(|a| matches!(a, Bm1398RuntimeAction::Work { .. })));
                let cut = trace
                    .iter()
                    .position(|a| matches!(a, Bm1398RuntimeAction::TerminalPowerOff))
                    .unwrap();
                assert!(trace[cut + 1..]
                    .iter()
                    .all(|a| !matches!(a, Bm1398RuntimeAction::HashPower { enabled: true })));
            }
        }
    }

    #[tokio::test]
    async fn mixed_and_unnamed_identity_refuse_before_any_energization() {
        for platform in platform::Bm1398Platform::ALL {
            let mut wrong_names = vec![None, Some("BHB42601")];
            wrong_names.extend(
                platform::Bm1398Platform::ALL
                    .into_iter()
                    .filter(|sibling| *sibling != platform)
                    .map(|sibling| Some(sibling.stock_board_names()[0])),
            );
            for name in wrong_names {
                for bad_slot in 0..3 {
                    let mut runtime = owner_replay(platform);
                    runtime.transport().observed_names.lock().unwrap()[bad_slot] =
                        name.map(str::to_owned);
                    assert!(runtime.start().await.is_err());
                    assert!(!runtime.transport().events.iter().any(|a| matches!(a,
                        Bm1398RuntimeAction::HashPower { enabled: true }
                    ) || matches!(a, Bm1398RuntimeAction::I2c(e)
                        if (e.endpoint == Bm1398FramedEndpoint::Apw12 && e.request[3] == 0x83)
                        || (e.endpoint != Bm1398FramedEndpoint::Apw12 && e.request[3] == 0x15 && e.request[4] == 1)
                    )), "{platform} slot {bad_slot} must refuse before rail/PIC enable");
                }
            }
        }
    }

    #[tokio::test]
    async fn failed_work_write_and_invalidated_job_cannot_publish_a_share() {
        let mut runtime = owner_replay(platform::Bm1398Platform::S19a);
        runtime.start().await.unwrap();
        runtime
            .transport()
            .fail_work
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let mut ledger = ledger();
        assert!(dispatch_work(&mut ledger, &mut runtime, 0, genesis_work())
            .await
            .is_err());
        let (shares, mut received) = tokio::sync::mpsc::channel(4);
        publish_nonce(&mut ledger, (2083236893, 0), "owner.worker", &shares).unwrap();
        assert!(received.try_recv().is_err());
        assert_eq!(ledger.next, 0);
        ledger.invalidate();
        publish_nonce(&mut ledger, (2083236893, 0), "owner.worker", &shares).unwrap();
        assert!(received.try_recv().is_err());
    }

    #[test]
    fn bm1398_power_refuses_missing_unknown_and_sibling_recipes() {
        use dcentrald_common::runtime_hardware_recipe::HardwareRecipeProfile;
        assert!(Bm1398PowerControl::capture("am2-s19pro", None).is_err());
        let recipe = RuntimeHardwareRecipe::resolve(
            dcentrald_common::BoardDesc::lookup("am2-s19pro").unwrap(),
            "Zynq am2",
            "serial",
            HardwareRecipeProfile::BoardDefault,
        )
        .unwrap();
        assert_eq!(
            Bm1398PowerControl::capture("am2-s19pro", Some(&recipe))
                .unwrap()
                .polarity,
            PowerControlPolarity::ActiveLow
        );
        let unknown = RuntimeHardwareRecipe::resolve(
            dcentrald_common::BoardDesc::lookup("am2-s19j").unwrap(),
            "Zynq am2",
            "serial",
            HardwareRecipeProfile::BoardDefault,
        )
        .unwrap();
        assert!(Bm1398PowerControl::capture("am2-s19j", Some(&unknown))
            .unwrap_err()
            .to_string()
            .contains("polarity is unproved"));
        let sibling = RuntimeHardwareRecipe::resolve(
            dcentrald_common::BoardDesc::lookup("am2-s17p").unwrap(),
            "Zynq am2",
            "s17-hybrid",
            HardwareRecipeProfile::BoardDefault,
        )
        .unwrap();
        assert!(sibling.gpio907_polarity().is_some());
        assert!(Bm1398PowerControl::capture("am2-s19pro", Some(&sibling))
            .unwrap_err()
            .to_string()
            .contains("another board target"));
    }

    #[tokio::test]
    async fn native_bm1398_refuses_unproved_power_before_system_hardware_access() {
        let board = dcentrald_common::BoardDesc::lookup("am2-s19pro").unwrap();
        let identity = dcentrald_common::AsicProtocolIdentity::Bm1398;
        let admission = crate::SerialRuntimeDispatchAdmission {
            board_target: board.board_target,
            asic_protocol: board.admit_asic_protocol(Some(identity), identity).unwrap(),
        };
        let config = toml::from_str(include_str!(
            "../../configs/dcentrald_s19pro_am2_baked_default.toml"
        ))
        .unwrap();
        let error = run(config, CancellationToken::new(), None, admission)
            .await
            .unwrap_err();
        assert!(error.to_string().starts_with("BM1398 "), "{error:#}");
        assert!(
            error.to_string().contains("recipe") || error.to_string().contains("polarity"),
            "startup must refuse the recipe before reading image markers or opening hardware: {error:#}"
        );
    }

    #[test]
    fn retained_gpio_polarity_controls_power_and_off_readback() {
        struct Scratch(std::path::PathBuf);
        impl Drop for Scratch {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let root = Scratch(std::env::temp_dir().join(format!(
            "dcent-bm1398-polarity-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(),
        )));
        std::fs::create_dir(&root.0).unwrap();
        let pin = root.0.join("gpio907");
        std::fs::create_dir(&pin).unwrap();
        std::fs::write(pin.join("active_low"), "0").unwrap();
        let chip = root.0.join("gpiochip906");
        let node = chip.join("device/of_node");
        std::fs::create_dir_all(&node).unwrap();
        std::fs::write(chip.join("base"), "906").unwrap();
        std::fs::write(chip.join("ngpio"), "118").unwrap();
        std::fs::write(node.join("compatible"), b"xlnx,zynq-gpio-1.0\0").unwrap();
        std::fs::write(node.join("reg"), [0xe0, 0, 0xa0, 0, 0, 0, 0x10, 0]).unwrap();
        // Synthetic wiring exercises both electrical conventions through the
        // actual owner writer; it does not assign either to a production row.
        for (polarity, off_value, on_value) in [
            (PowerControlPolarity::ActiveLow, "1", "0"),
            (PowerControlPolarity::ActiveHigh, "0", "1"),
        ] {
            let power = Bm1398PowerControl { polarity };
            for enabled in [false, true, false] {
                power.set_hash_power_at(&root.0, enabled).unwrap();
                let expected = if enabled { on_value } else { off_value };
                let observed = std::fs::read_to_string(pin.join("value")).unwrap();
                assert_eq!(observed, expected);
                assert_eq!(
                    std::fs::read_to_string(pin.join("direction")).unwrap(),
                    if expected == "1" { "high" } else { "low" }
                );
                assert_eq!(power.require_off_level(observed == "1").is_ok(), !enabled);
            }
        }
        let power = Bm1398PowerControl {
            polarity: PowerControlPolarity::ActiveLow,
        };
        for (file, wrong) in [
            (chip.join("base"), b"905".to_vec()),
            (chip.join("ngpio"), b"117".to_vec()),
            (node.join("compatible"), b"xlnx,xps-gpio-1.00.a\0".to_vec()),
            (node.join("reg"), vec![0x41, 0x21, 0, 0, 0, 0, 0x10, 0]),
            (pin.join("active_low"), b"1".to_vec()),
        ] {
            let saved = std::fs::read(&file).unwrap();
            std::fs::write(&file, wrong).unwrap();
            std::fs::write(pin.join("value"), "undriven").unwrap();
            std::fs::write(pin.join("direction"), "in").unwrap();
            assert!(power.set_hash_power_at(&root.0, true).is_err());
            assert_eq!(
                std::fs::read_to_string(pin.join("value")).unwrap(),
                "undriven"
            );
            assert_eq!(
                std::fs::read_to_string(pin.join("direction")).unwrap(),
                "in"
            );
            std::fs::write(file, saved).unwrap();
        }
    }

    fn genesis_work() -> MiningWork {
        let merkle = [
            0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76,
            0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
            0x4b, 0x1e, 0x5e, 0x4a,
        ];
        let header = dcentrald_stratum::v1::job::build_block_header(
            1, &[0; 32], &merkle, 1231006505, 0x1d00ffff, 2083236893,
        );
        MiningWork {
            work_generation: dcentrald_stratum::work_domain::WorkGeneration { session: 1, job: 1 },
            midstates: vec![dcentrald_stratum::work::compute_midstate_from_prefix(
                &header[..64].try_into().unwrap(),
            )],
            merkle4: merkle[28..].try_into().unwrap(),
            ntime: 1231006505,
            nbits: 0x1d00ffff,
            job_id: "nbp1901-genesis".into(),
            extranonce2: "00000000".into(),
            version: 1,
            version_mask: 0,
            share_target: dcentrald_stratum::work::difficulty_to_target(1.0),
            merkle_root: merkle,
            prev_block_hash: [0; 32],
        }
    }
    fn ledger() -> WorkLedger {
        WorkLedger::new(
            Bm1398FpgaWorkConfig::new(Bm1398FpgaMidstateMode::Four, Duration::from_millis(4))
                .unwrap(),
        )
    }

    #[test]
    fn native_bm1398_work_to_independent_nonce_and_exact_share() {
        let mut ledger = ledger();
        // Exercise the part of the real FPGA ID space rejected by the former
        // eight-bit decoder, with an independent Bitcoin winning nonce.
        ledger.next = 0x1234;
        let work = genesis_work();
        let words = ledger.prepare(&work).unwrap();
        assert_eq!(words.len(), 36);
        assert_eq!(&words[..4], &[0x48d0, 0x1d00ffff, 0x495fab29, 0x4a5e1e4b]);
        assert_eq!(
            &words[4..12],
            &[
                0x4719f91b, 0x96b18736, 0x4f0103c8, 0xc3c8d8e9, 0x1e59caa8, 0x90ccac7d, 0x6358bff0,
                0xbc909a33
            ]
        );
        ledger.commit(work);
        let raw = (2083236893, 0x48d0 << 8);
        let share = ledger.validate(raw, "tester.nbp1901").unwrap().unwrap();
        assert_eq!(share.nonce, "7c2bac1d");
        assert_eq!(share.ntime, "495fab29");
        assert_eq!(share.job_id, "nbp1901-genesis");
        assert_eq!(share.worker_name, "tester.nbp1901");
        assert_eq!(ledger.tickets, 1);
        assert!(ledger.validate(raw, "tester.nbp1901").unwrap().is_none());
        ledger.invalidate();
        assert!(ledger.validate(raw, "tester.nbp1901").unwrap().is_none());
    }

    #[test]
    fn failed_physical_write_never_commits_old_work_or_accepts_invalid_nonce() {
        let mut ledger = ledger();
        let work = genesis_work();
        ledger.prepare(&work).unwrap();
        ledger.commit(work.clone());
        assert!(ledger.validate((0, 0), "tester").unwrap().is_none());
        ledger.next = 0;
        ledger.prepare(&work).unwrap(); // transport fails: caller never commits
        assert!(ledger
            .validate((2083236893, 0), "tester")
            .unwrap()
            .is_none());
    }

    #[test]
    fn eight_builder_midstates_use_four_prefix_and_bip310_masked_bits() {
        let mut ledger = ledger();
        let mut work = genesis_work();
        work.midstates = vec![work.midstates[0]; 8];
        work.version = 0x2001;
        work.version_mask = 0x2000;
        work.share_target = [0xff; 32];
        assert_eq!(ledger.prepare(&work).unwrap().len(), 36);
        ledger.commit(work);
        let share = ledger.validate((2083236893, 0), "tester").unwrap().unwrap();
        assert_eq!(share.version_bits.as_deref(), Some("00002000"));
        assert_eq!(share.version, 0x2001);
    }

    #[test]
    fn stock_pic_thermal_plan_and_signed_temperature_are_independent_of_factory_bus() {
        let steps = temperature_steps(0x48).unwrap();
        assert!(
            matches!(&steps[0],I2cTransactionStep::WriteByteByByte(v) if v==&[0x55,0xaa,6,0x3b,0x48,0,0,0x89])
        );
        assert!(
            matches!(&steps[5],I2cTransactionStep::WriteByteByByte(v) if v==&[0x55,0xaa,6,0x3c,0x48,2,0,0x8c])
        );
        let mut bytes = vec![0x3b, 1, 7, 0x3c, 1, 0x19, 0x80, 0, 0];
        let sum: u16 = bytes[2..7].iter().map(|v| u16::from(*v)).sum();
        bytes[7..].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(decode_temperature(&bytes).unwrap(), 25.5);
        bytes[5] = 0xf6;
        bytes[6] = 0x80;
        let sum: u16 = bytes[2..7].iter().map(|v| u16::from(*v)).sum();
        bytes[7..].copy_from_slice(&sum.to_be_bytes());
        assert_eq!(decode_temperature(&bytes).unwrap(), -9.5);
        bytes[8] ^= 1;
        assert!(decode_temperature(&bytes).is_err());
        assert!(temperature_steps(0x50).is_err());
    }
}
