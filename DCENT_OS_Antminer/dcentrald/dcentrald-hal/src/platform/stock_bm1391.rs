//! Native S15/T15 December-2019 flat FPGA transport at 0x40000000.
//!
//! Original S15 39bf8..39cbc / 8a3e8 and T15 39bf8..39cbc / 8a308
//! serialize thirteen TW words: one at +40, twelve at +44. The C43 BM1393
//! and Braiins mappings are distinct. Source and machine-code replay receipts:
//!
//!
//! This owner supplies the actual work/return transport. Runtime admission,
//! initialization, power/thermal custody and image production are composed
//! separately; an FPGA version by itself never establishes an ASIC identity.

use crate::i2c::I2cRawFabricLease;
use dcentrald_common::bm1391_stock_return::{
    decode_bm1391_stock_fpga_return, Bm1391StockFpgaReturn,
};
use dcentrald_fabric_lease::topology::STOCK_S9_FPGA_IIC;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

pub const PHYSICAL_BASE: u64 = 0x4000_0000;
pub const BITSTREAM_SHA256: &str =
    "75e0b98b73822da3e195bb8ebd9235dfa3fb98c658838fe01c7accbe6a581dcd";
const MAP_BYTES: usize = 4096;
const REGISTER_BYTES: u32 = 0x160;
const VERSION: u32 = 0;
const PRESENCE: u32 = 8;
const WORK_SPACE: u32 = 0x0c;
const RETURN0: u32 = 0x10;
const RETURN1: u32 = 0x14;
const RETURN_COUNT: u32 = 0x18;
const TW_FIRST: u32 = 0x40;
const TW_NEXT: u32 = 0x44;
const COMMAND_CONTROL: u32 = 0xc0;
const COMMAND_BUFFER: u32 = 0xc4;

#[path = "stock_bm1391_census.rs"]
mod census;
#[path = "stock_bm1391_management.rs"]
mod management;
#[path = "stock_bm1391_pic.rs"]
mod pic;
pub use census::Census;
pub use pic::{PicApplication, PicOffReport};
#[path = "stock_bm1391_power.rs"]
mod power;
pub use power::{CommandedVoltage, FanTachSample, FanTachSnapshot, QuietFanSetting};
#[path = "stock_bm1391_thermal.rs"]
mod thermal;
pub use thermal::{
    BoardTemperature, PreservedThermalNonce, ThermalApplication, ThermalOutcome, ThermalSensor,
};
#[path = "stock_bm1391_clock.rs"]
mod clock;
pub use clock::PllSetting;
#[path = "stock_bm1391_controls.rs"]
mod controls;
#[path = "stock_bm1391_cores.rs"]
mod cores;
pub use controls::StartupBaud;
#[path = "stock_bm1391_startup_observation.rs"]
mod startup_observation;
pub use startup_observation::{StartupBaudReport, StartupObservation};
#[path = "stock_bm1391_dma.rs"]
mod dma;
pub use dma::DmaReservation;
#[path = "stock_bm1391_engine.rs"]
mod engine;
pub use engine::{ColdEngineObservation, EngineStopReport};
#[path = "stock_bm1391_gpio.rs"]
mod gpio;
pub use gpio::{park_source_line, ParkedSourceLine, PowerLine, PowerLineOffObservation};
#[path = "stock_bm1391_closeout.rs"]
mod closeout;
pub use closeout::TerminalControlsReceipt;

#[cfg(feature = "sim-hal")]
#[path = "stock_bm1391_simulation.rs"]
pub mod simulation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Model {
    S15,
    T15,
}
impl Model {
    pub const fn board_target(self) -> &'static str {
        match self {
            Self::S15 => "am1-s15",
            Self::T15 => "am1-t15",
        }
    }
    /// Original all-chain setup writes interval 3 (S15 439b4) or 4
    /// (T15 439d4). The address window includes more slots than actual chips.
    pub const fn address_interval(self) -> u8 {
        match self {
            Self::S15 => 3,
            Self::T15 => 4,
        }
    }
    pub const fn expected_chips(self) -> u8 {
        match self {
            Self::S15 => 72,
            Self::T15 => 60,
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FabricReceipt {
    schema: u8,
    boot_id: String,
    board_target: String,
    bitstream_sha256: String,
    load_completed: bool,
    prog_done: bool,
}

fn private_identity(path: &str) -> Result<String, String> {
    use std::io::Read;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("{path}: {e}"))?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    if !info.is_file() || info.uid() != 0 || info.mode() & 0o022 != 0 || info.len() > 4096 {
        return Err(format!("{path}: unsafe or oversized identity"));
    }
    let mut text = String::new();
    file.by_ref()
        .take(4097)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() > 4096 {
        return Err("BM1391 identity grew during read".into());
    }
    Ok(text)
}

/// A boot-produced identity is checked before mapping; the reserved raw
/// management-fabric lease stays alive until the final mapping reference drops.
pub struct NativeMmio {
    backing: MmioBacking,
    model: Model,
    dma: DmaReservation,
    transport_claimed: AtomicBool,
}
enum MmioBacking {
    Physical {
        pointer: usize,
        _file: File,
        lease: I2cRawFabricLease,
    },
    #[cfg(feature = "sim-hal")]
    Simulated(Arc<dyn Registers>),
}
// SAFETY: Arc retains mapping lifetime; bounded aligned volatile accesses are
// serialized by the transport's ASIC or management lane for each compound action.
unsafe impl Send for NativeMmio {}
// SAFETY: shared mapping accesses are volatile; compound sequences require the
// same retained transport lane and the fabric lease checks the creator process.
unsafe impl Sync for NativeMmio {}

impl NativeMmio {
    async fn open(model: Model) -> Result<Arc<Self>, String> {
        tokio::task::spawn_blocking(move || {
            let receipt: FabricReceipt =
                serde_json::from_str(&private_identity("/run/dcentos/bm1391-fabric.json")?)
                    .map_err(|e| format!("BM1391 fabric receipt: {e}"))?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|e| e.to_string())?;
            let pin = private_identity("/etc/dcentos/bm1391-bitstream.sha256")?;
            let target = private_identity("/etc/dcentos/board_target")?;
            if receipt.schema != 1
                || receipt.boot_id != boot.trim()
                || receipt.board_target != model.board_target()
                || target.trim() != model.board_target()
                || receipt.bitstream_sha256 != BITSTREAM_SHA256
                || pin.trim() != BITSTREAM_SHA256
                || !receipt.load_completed
                || !receipt.prog_done
            {
                return Err("BM1391 exact fabric/target/current-boot binding is missing".into());
            }
            let dma =
                DmaReservation::observe_kernel_tree(std::path::Path::new("/proc/device-tree"))?;
            // This is the same physical management portal ownership domain as
            // the stock Zynq FPGA IIC path, regardless of its differing AXI base.
            let lease =
                I2cRawFabricLease::reserve_bitbang(STOCK_S9_FPGA_IIC).map_err(|e| e.to_string())?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_SYNC | libc::O_CLOEXEC)
                .open("/dev/mem")
                .map_err(|e| e.to_string())?;
            // SAFETY: fixed page-aligned original physical window, exactly one
            // retained mapping with matching length in Drop.
            let pointer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    MAP_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    PHYSICAL_BASE as libc::off_t,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let owner = Arc::new(Self {
                backing: MmioBacking::Physical {
                    pointer: pointer as usize,
                    _file: file,
                    lease,
                },
                model,
                dma,
                transport_claimed: AtomicBool::new(false),
            });
            if owner.read(VERSION)? & 0xffff != 0xc501 {
                return Err("BM1391 mapped carrier version is not C501".into());
            }
            Ok(owner)
        })
        .await
        .map_err(|e| format!("BM1391 mapping worker: {e}"))?
    }
}
impl Drop for NativeMmio {
    fn drop(&mut self) {
        #[allow(irrefutable_let_patterns)]
        let MmioBacking::Physical { pointer, .. } = &self.backing
        else {
            return;
        };
        // SAFETY: the uniquely retained mapping is unmapped after its last Arc.
        unsafe {
            libc::munmap(*pointer as *mut libc::c_void, MAP_BYTES);
        }
    }
}

pub trait Registers: Send + Sync + 'static {
    /// Validate retained process ownership without depending on the FPGA being
    /// responsive. Independent GPIO cutoff must survive a fabric read failure.
    fn validate_owner(&self) -> Result<(), String> {
        Ok(())
    }
    /// A real mapping must allow only one transport to own its transaction
    /// lanes. The default is for independent scripted register implementations.
    fn claim_transport(&self) -> Result<(), String> {
        Ok(())
    }
    fn model(&self) -> Option<Model> {
        None
    }
    fn read(&self, offset: u32) -> Result<u32, String>;
    fn write(&self, offset: u32, value: u32) -> Result<(), String>;
}
impl Registers for NativeMmio {
    fn validate_owner(&self) -> Result<(), String> {
        match &self.backing {
            MmioBacking::Physical { lease, .. } => {
                lease.validate_current_process().map_err(|e| e.to_string())
            }
            #[cfg(feature = "sim-hal")]
            MmioBacking::Simulated(registers) => registers.validate_owner(),
        }
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.validate_owner()?;
        claim_mapping_transport(&self.transport_claimed)
    }
    fn model(&self) -> Option<Model> {
        Some(self.model)
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        self.validate_owner()?;
        if offset & 3 != 0 || offset >= REGISTER_BYTES {
            return Err("BM1391 register outside original mapped window".into());
        }
        match &self.backing {
            MmioBacking::Physical { pointer, .. } => {
                // SAFETY: checked aligned address inside the retained mapping.
                Ok(unsafe { std::ptr::read_volatile((*pointer + offset as usize) as *const u32) })
            }
            #[cfg(feature = "sim-hal")]
            MmioBacking::Simulated(registers) => registers.read(offset),
        }
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.validate_owner()?;
        if offset & 3 != 0 || offset == VERSION || offset >= REGISTER_BYTES {
            return Err("BM1391 write outside original writable window".into());
        }
        match &self.backing {
            MmioBacking::Physical { pointer, .. } => {
                // SAFETY: checked aligned address inside the retained mapping;
                // owning transport serializes the complete transaction.
                unsafe {
                    std::ptr::write_volatile((*pointer + offset as usize) as *mut u32, value);
                }
            }
            #[cfg(feature = "sim-hal")]
            MmioBacking::Simulated(registers) => registers.write(offset, value)?,
        }
        std::sync::atomic::fence(Ordering::SeqCst);
        Ok(())
    }
}

fn claim_mapping_transport(claimed: &AtomicBool) -> Result<(), String> {
    claimed
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map(|_| ())
        .map_err(|_| "BM1391 mapping already has a retained transport owner".into())
}

/// Complete original direct-TW work, including the full fifteen-bit work ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Work {
    chain: u8,
    id: u16,
    words: [u32; 13],
}
impl Work {
    pub fn from_wire_parts(
        chain: u8,
        id: u16,
        tail: [u8; 12],
        midstate: [u8; 32],
    ) -> Result<Self, String> {
        if chain > 15 || id > 0x7fff {
            return Err("BM1391 work chain or fifteen-bit ID is out of range".into());
        }
        let mut words = [0; 13];
        words[0] = 0x0180_0000 | (u32::from(chain) << 16);
        words[1] = u32::from(id);
        for (word, bytes) in words[2..]
            .iter_mut()
            .zip(tail.chunks_exact(4).chain(midstate.chunks_exact(4)))
        {
            *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        Ok(Self { chain, id, words })
    }

    /// The original stock-pattern SHA256 oracle independently identifies a
    /// reversed WORD order, preserving byte order inside each word, for both
    /// the midstate and the three header-tail words on this direct-TW route.
    pub fn from_sha256_words(
        chain: u8,
        id: u16,
        midstate: [u32; 8],
        tail: [u32; 3],
    ) -> Result<Self, String> {
        let mut wire_state = [0; 32];
        let mut wire_tail = [0; 12];
        for (bytes, word) in wire_state
            .chunks_exact_mut(4)
            .zip(midstate.into_iter().rev())
        {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        for (bytes, word) in wire_tail.chunks_exact_mut(4).zip(tail.into_iter().rev()) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        Self::from_wire_parts(chain, id, wire_tail, wire_state)
    }
    pub fn chain(&self) -> u8 {
        self.chain
    }
    pub fn id(&self) -> u16 {
        self.id
    }
}

pub struct Transport<R: Registers> {
    registers: Arc<R>,
    chains: Vec<u8>,
    terminal: AtomicBool,
    lane: Mutex<()>,
    // The independent +30 management controller must remain serviceable while
    // ASIC addressing/core delays retain the +c0 command/+40 work lane. Both
    // lanes share this one mapping and its one physical management-fabric lease.
    management_lane: Mutex<()>,
    // +84 PWM and +04 tach are independent of the long +30 PIC transaction.
    // Retain their own single-writer lane so health remains observable during
    // the complete enable/heartbeat sequence without widening its deadlines.
    fan_lane: Mutex<()>,
    pic_claimed: AtomicBool,
    // One thermal service retains custody of all nonce records popped while
    // reading sensor replies from the shared ASIC return FIFO.
    thermal_claimed: AtomicBool,
    // Startup read custody is permanently unique, including unexpected nonces
    // retained after a cancelled worker in the declared no-work epoch.
    startup_observation_claimed: AtomicBool,
    power_line_claimed: AtomicBool,
    // Permanent uncertainty after an incomplete management transaction. Terminal
    // PIC off must not overwrite a still-running +30 operation or partial frame.
    management_fault: AtomicBool,
}

/// The failure latch must become visible before a waiting ASIC operation can
/// acquire the lane. Drop runs before Rust releases this guard's mutex field,
/// including unwinding through an unexpected backend panic.
struct AsicTransaction<'a, R: Registers> {
    owner: &'a Transport<R>,
    _lane: MutexGuard<'a, ()>,
    completed: bool,
}
impl<R: Registers> Drop for AsicTransaction<'_, R> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.latch_terminal();
        }
    }
}

/// Cancelling an async caller must also revoke its detached blocking worker.
/// Workers retain the transport and check its latch before later operations.
struct AsyncCancellation<R: Registers> {
    owner: Arc<Transport<R>>,
    completed: bool,
}
impl<R: Registers> AsyncCancellation<R> {
    fn new(owner: Arc<Transport<R>>) -> Self {
        Self {
            owner,
            completed: false,
        }
    }
    fn complete(&mut self) {
        self.completed = true;
    }
}
impl<R: Registers> Drop for AsyncCancellation<R> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.latch_terminal();
        }
    }
}

impl Transport<NativeMmio> {
    /// Construct the only public native mapping owner. Raw MMIO is never
    /// returned to a caller that could bypass the retained transaction lanes.
    pub async fn open(model: Model, chains: Vec<u8>) -> Result<Arc<Self>, String> {
        Self::new(NativeMmio::open(model).await?, chains)
    }
    /// Derive the retained nonempty population from the exact live presence
    /// register. The constructor rechecks it before returning this owner.
    pub async fn open_observed(model: Model) -> Result<Arc<Self>, String> {
        let registers = NativeMmio::open(model).await?;
        let presence = registers.read(PRESENCE)?;
        let chains = (0..3)
            .filter(|chain| presence & (1 << chain) != 0)
            .collect();
        Self::new(registers, chains)
    }
    pub fn reserved_dma(&self) -> DmaReservation {
        self.registers.dma
    }
}

impl<R: Registers> Transport<R> {
    pub fn new(registers: Arc<R>, chains: Vec<u8>) -> Result<Arc<Self>, String> {
        if chains.is_empty()
            || chains.iter().any(|c| *c > 2)
            || chains.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err("BM1391 requires ordered distinct physical chain slots0..2".into());
        }
        // Claim before even version/presence access. A failed observation does
        // not make this same mapping available to a second independent owner.
        registers.claim_transport()?;
        if registers.read(VERSION)? & 0xffff != 0xc501 {
            return Err("BM1391 requires the exact stock C501 register layout".into());
        }
        let present = registers.read(PRESENCE)?;
        if chains.iter().any(|chain| present & (1 << chain) == 0) {
            return Err("BM1391 selected chain is absent".into());
        }
        Ok(Self::from_claimed_mapping(registers, chains, false))
    }

    /// Only the private source-parking factory uses this already-terminal
    /// mapping. No nonempty board inventory or normal admission is created.
    fn new_parked(registers: Arc<R>) -> Result<Arc<Self>, String> {
        registers.claim_transport()?;
        registers.validate_owner()?;
        if registers.read(VERSION)? & 0xffff != 0xc501 {
            return Err("BM1391 source park requires the exact C501 mapping".into());
        }
        Ok(Self::from_claimed_mapping(registers, Vec::new(), true))
    }

    fn from_claimed_mapping(registers: Arc<R>, chains: Vec<u8>, terminal: bool) -> Arc<Self> {
        Arc::new(Self {
            registers,
            chains,
            terminal: AtomicBool::new(terminal),
            lane: Mutex::new(()),
            management_lane: Mutex::new(()),
            fan_lane: Mutex::new(()),
            pic_claimed: AtomicBool::new(false),
            thermal_claimed: AtomicBool::new(false),
            startup_observation_claimed: AtomicBool::new(false),
            power_line_claimed: AtomicBool::new(false),
            management_fault: AtomicBool::new(false),
        })
    }
    pub fn terminal(&self) -> bool {
        self.terminal.load(Ordering::SeqCst)
    }
    pub fn selected_chains(&self) -> &[u8] {
        &self.chains
    }
    pub fn latch_terminal(&self) {
        self.terminal.store(true, Ordering::SeqCst);
    }
    fn lock_until(&self, deadline: Instant) -> Result<MutexGuard<'_, ()>, String> {
        Self::lock_lane_until(&self.lane, deadline)
    }
    fn begin_asic_transaction(&self, deadline: Instant) -> Result<AsicTransaction<'_, R>, String> {
        let lane = self.lock_until(deadline).map_err(|error| {
            self.latch_terminal();
            error
        })?;
        Ok(AsicTransaction {
            owner: self,
            _lane: lane,
            completed: false,
        })
    }
    fn with_asic_lane<T>(
        &self,
        deadline: Instant,
        operation: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let mut transaction = self.begin_asic_transaction(deadline)?;
        let result = operation();
        transaction.completed = result.is_ok();
        result
    }
    fn lock_management_until(&self, deadline: Instant) -> Result<MutexGuard<'_, ()>, String> {
        Self::lock_lane_until(&self.management_lane, deadline)
    }
    fn lock_fan_until(&self, deadline: Instant) -> Result<MutexGuard<'_, ()>, String> {
        Self::lock_lane_until(&self.fan_lane, deadline)
    }
    fn lock_lane_until(lane: &Mutex<()>, deadline: Instant) -> Result<MutexGuard<'_, ()>, String> {
        loop {
            match lane.try_lock() {
                Ok(lane) => return Ok(lane),
                Err(TryLockError::Poisoned(_)) => {
                    return Err("BM1391 transaction lane poisoned".into())
                }
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(TryLockError::WouldBlock) => {
                    return Err("BM1391 transaction lane timed out".into())
                }
            }
        }
    }
    fn active(&self, deadline: Instant) -> Result<(), String> {
        if self.terminal() || Instant::now() >= deadline {
            return Err("BM1391 transaction is terminal or expired".into());
        }
        Ok(())
    }

    /// No retry follows a partial FIFO frame. Any transport error permanently
    /// stops new work until the runtime owner finishes its terminal cut.
    pub fn publish_work(&self, work: &Work, deadline: Instant) -> Result<(), String> {
        if !self.chains.contains(&work.chain) {
            return Err("BM1391 work is outside the retained population".into());
        }
        self.with_asic_lane(deadline, || {
            loop {
                self.active(deadline)?;
                if self.registers.read(WORK_SPACE)? & (1 << work.chain) != 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            self.active(deadline)?;
            for (index, word) in work.words.iter().copied().enumerate() {
                self.registers
                    .write(if index == 0 { TW_FIRST } else { TW_NEXT }, word)?;
            }
            Ok(())
        })
    }

    /// Read the original per-chain work-space mask without publishing work.
    /// One runtime producer can defer a complete population until every chain
    /// has capacity; the subsequent publisher still checks each actual frame.
    pub fn selected_work_ready(&self, deadline: Instant) -> Result<bool, String> {
        self.with_asic_lane(deadline, || {
            self.active(deadline)?;
            let selected = self
                .chains
                .iter()
                .fold(0u32, |mask, chain| mask | (1 << chain));
            Ok(self.registers.read(WORK_SPACE)? & selected == selected)
        })
    }

    pub fn read_return(&self, deadline: Instant) -> Result<Option<Bm1391StockFpgaReturn>, String> {
        self.with_asic_lane(deadline, || self.read_return_locked(deadline))
    }

    fn read_return_locked(
        &self,
        deadline: Instant,
    ) -> Result<Option<Bm1391StockFpgaReturn>, String> {
        self.active(deadline)?;
        if self.registers.read(RETURN_COUNT)? & 0x1ff == 0 {
            return Ok(None);
        }
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&self.registers.read(RETURN0)?.to_le_bytes());
        bytes[4..].copy_from_slice(&self.registers.read(RETURN1)?.to_le_bytes());
        let record = decode_bm1391_stock_fpga_return(&bytes).map_err(|e| format!("{e:?}"))?;
        let chain = match record {
            Bm1391StockFpgaReturn::Nonce(nonce) => nonce.chain_slot,
            Bm1391StockFpgaReturn::Register(register) => register.chain_slot,
        };
        if !self.chains.contains(&chain) {
            return Err("BM1391 return is outside the retained population".into());
        }
        Ok(Some(record))
    }

    /// Original 7c5e8/7c5b0 ASIC register writer. Register14 alone reverses
    /// the bits inside each payload byte through the stock bit-swap table.
    /// Its FIFO packet and CRC5 are independently replayed for both releases.
    pub fn write_register(
        &self,
        chain: u8,
        address: u8,
        broadcast: bool,
        register: u8,
        value: u32,
        deadline: Instant,
    ) -> Result<(), String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 command is outside the retained population".into());
        }
        self.publish_command(
            chain,
            &Self::register_frame(address, broadcast, register, value),
            deadline,
        )
    }

    fn register_frame(address: u8, broadcast: bool, register: u8, value: u32) -> [u8; 12] {
        let mut frame = [0; 12];
        frame[..4].copy_from_slice(&[if broadcast { 0x51 } else { 0x41 }, 9, address, register]);
        let mut payload = value.to_be_bytes();
        if register == 0x14 {
            payload = payload.map(u8::reverse_bits);
        }
        frame[4..8].copy_from_slice(&payload);
        frame[8] = dcentrald_common::s9se_vil::crc5_bits(&frame[..8], 64);
        frame
    }

    /// Original VIL chain-inactive: S15 7b390, T15 7b358, mode flag B4E30=1.
    /// This changes ASIC addressing state; it is not a physical power cut.
    pub fn chain_inactive(&self, chain: u8, deadline: Instant) -> Result<(), String> {
        self.short_command(chain, 0x53, 0, 0, deadline)
    }

    /// Original VIL address command: S15 7b688, T15 7b650. The stock working
    /// configuration subsequently writes the address register after 2ms.
    pub fn assign_address(&self, chain: u8, address: u8, deadline: Instant) -> Result<(), String> {
        self.short_command(chain, 0x40, address, 0, deadline)
    }

    /// Original read request: S15 7c938 / T15 7c900. This only transmits the
    /// request. The runtime owner must correlate fresh FIFO register replies;
    /// successful command completion alone never proves an ASIC observation.
    pub fn request_register(
        &self,
        chain: u8,
        address: u8,
        broadcast: bool,
        register: u8,
        deadline: Instant,
    ) -> Result<(), String> {
        self.short_command(
            chain,
            if broadcast { 0x52 } else { 0x42 },
            address,
            register,
            deadline,
        )
    }

    /// Original S15 7b8b4 / T15 7b87c uses 1393 in this payload even on these
    /// BM1391 releases. Preserve the executed bytes; do not substitute a model
    /// label for this register value. This is not a chip-identity observation.
    pub fn write_address_register(
        &self,
        chain: u8,
        address: u8,
        deadline: Instant,
    ) -> Result<(), String> {
        self.write_register(
            chain,
            0,
            false,
            0,
            0x1393_0000 | u32::from(address),
            deadline,
        )
    }

    fn short_command(
        &self,
        chain: u8,
        command: u8,
        address: u8,
        register: u8,
        deadline: Instant,
    ) -> Result<(), String> {
        self.publish_command(
            chain,
            &Self::short_frame(command, address, register),
            deadline,
        )
    }

    fn short_frame(command: u8, address: u8, register: u8) -> [u8; 12] {
        let mut frame = [0; 12];
        frame[..4].copy_from_slice(&[command, 5, address, register]);
        frame[4] = dcentrald_common::s9se_vil::crc5_bits(&frame[..4], 32);
        frame
    }

    fn publish_command(
        &self,
        chain: u8,
        frame: &[u8; 12],
        deadline: Instant,
    ) -> Result<(), String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 command is outside the retained population".into());
        }
        self.with_asic_lane(deadline, || {
            self.publish_command_locked(chain, frame, deadline)?;
            Ok(())
        })
    }

    // Caller retains the transaction lane across this complete publication.
    fn publish_command_locked(
        &self,
        chain: u8,
        frame: &[u8; 12],
        deadline: Instant,
    ) -> Result<(), String> {
        let previous = loop {
            self.active(deadline)?;
            let current = self.registers.read(COMMAND_CONTROL)?;
            if current & 0x8000_0000 == 0 {
                break current;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        self.active(deadline)?;
        for (index, bytes) in frame.chunks_exact(4).enumerate() {
            self.registers.write(
                COMMAND_BUFFER + index as u32 * 4,
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            )?;
        }
        self.registers.write(
            COMMAND_CONTROL,
            (previous & 0xfff0_ffff) | 0x8080_0000 | (u32::from(chain) << 16),
        )?;
        loop {
            if self.registers.read(COMMAND_CONTROL)? & 0x8000_0000 == 0 {
                break;
            }
            if Instant::now() >= deadline {
                return Err("BM1391 ASIC command completion timed out".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }

    /// Complete original per-chain working configuration, off the async
    /// executor. One transaction lane covers commands AND settling delays,
    /// so work or another register request cannot interleave with addressing.
    pub async fn configure_addresses(
        self: &Arc<Self>,
        model: Model,
        chain: u8,
        deadline: Instant,
    ) -> Result<(), String> {
        let mut cancellation = AsyncCancellation::new(self.clone());
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.configure_addresses_with_delay(model, chain, deadline, |milliseconds| {
                let until = Instant::now() + Duration::from_millis(milliseconds);
                loop {
                    owner.active(deadline)?;
                    let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                        return Ok(());
                    };
                    std::thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            })
        })
        .await
        .map_err(|e| format!("BM1391 address worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        cancellation.complete();
        result?
    }

    fn configure_addresses_with_delay(
        &self,
        model: Model,
        chain: u8,
        deadline: Instant,
        mut delay: impl FnMut(u64) -> Result<(), String>,
    ) -> Result<(), String> {
        if !self.chains.contains(&chain) {
            return Err("BM1391 address sequence is outside the retained population".into());
        }
        self.with_asic_lane(deadline, || {
            for _ in 0..3 {
                self.publish_command_locked(chain, &Self::short_frame(0x53, 0, 0), deadline)?;
                delay(30)?;
                self.active(deadline)?;
            }
            let step = u16::from(model.address_interval());
            // Match original integer division: 85 slots for S15, 64 for T15.
            // This does not claim that every addressed slot contains a chip.
            for slot in 0..(256 / step) {
                let address = (slot * step) as u8;
                self.publish_command_locked(chain, &Self::short_frame(0x40, address, 0), deadline)?;
                delay(2)?;
                self.active(deadline)?;
                self.publish_command_locked(
                    chain,
                    &Self::register_frame(0, false, 0, 0x1393_0000 | u32::from(address)),
                    deadline,
                )?;
                delay(50)?;
                self.active(deadline)?;
            }
            Ok(())
        })
    }

    /// This is a transport barrier only. It never establishes physical power
    /// removal and cannot be used to disarm the runtime watchdog by itself.
    pub fn terminal_drain(&self, deadline: Instant) -> Result<(), String> {
        self.latch_terminal();
        let _lane = self.lock_until(deadline)?;
        let _management = self.lock_management_until(deadline)?;
        let _fan = self.lock_fan_until(deadline)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "stock_bm1391_tests.rs"]
mod tests;
