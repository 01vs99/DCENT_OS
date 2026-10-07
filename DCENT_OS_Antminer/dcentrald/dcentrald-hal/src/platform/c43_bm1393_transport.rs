//! Retained C43 native raw-TW transport. No stock kernel module or DMA buffer.
//!
//! Source anchors are in campaign evidence/r03/s9k-stock-instructions.txt:
//! set_iic45320, zynq_set_iic453e8, set_reset_hashboard457d0,
//! set_PWM1981a, get_nonce_and_register222da, set_TW4717c, plus independent
//! S9 SE work execution53be4/76970. All blocking transactions retain their
//! owner and lane through cancellation, response validation and parser flush.

use crate::i2c::I2cRawFabricLease;
use dcentrald_common::bm1393_native::{Bm1393FactoryProfile, Bm1393PicCommand};
use dcentrald_common::s9se_fpga as reg;
use dcentrald_common::s9se_nonce::{classify_return_record, S9SeFifoRecord};
use dcentrald_common::{s9se_regs, s9se_temp, s9se_vil};
use dcentrald_fabric_lease::topology::STOCK_S9_FPGA_IIC;
use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const C43_BITSTREAM_SHA256: &str =
    "1681558e124de9a3721bf4fe4b885ba9a122d2a9f2a4d7e0f560824d95cdd6cc";
const PHYSICAL_BASE: libc::off_t = 0x43c0_0000;
const MAP_BYTES: usize = 4096;

#[path = "c43_bm1393_boot.rs"]
mod boot;
pub use boot::{park_boot_source, C43BootParked};

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct FabricReceipt {
    schema: u8,
    boot_id: String,
    bitstream_sha256: String,
    load_completed: bool,
    prog_done: bool,
}

fn root_owned_text(path: &str) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| format!("{path}: {e}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 4096
    {
        return Err(format!("{path} is not a bounded root-owned identity file"));
    }
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

/// Only constructor for real MMIO verifies a boot-produced receipt and exact
/// image-owned source hash before opening the physical register window.
pub struct C43NativeMmio {
    pointer: usize,
    _file: File,
    lease: I2cRawFabricLease,
}
// SAFETY: mapping lifetime is retained by Arc. Every access is aligned,
// bounds checked and volatile; compound operations use the transport lanes.
unsafe impl Send for C43NativeMmio {}
// SAFETY: disjoint hardware lanes may access the mapping concurrently; each
// compound FIFO/IIC/management transaction is serialized by its own mutex.
unsafe impl Sync for C43NativeMmio {}

impl C43NativeMmio {
    pub async fn open() -> Result<Arc<Self>, String> {
        tokio::task::spawn_blocking(|| {
            let receipt: FabricReceipt =
                serde_json::from_str(&root_owned_text("/run/dcentos/c43-fabric.json")?)
                    .map_err(|e| format!("C43 boot receipt: {e}"))?;
            let current_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|e| e.to_string())?;
            let pin = root_owned_text("/etc/dcentos/c43-bitstream.sha256")?;
            if receipt.schema != 1
                || receipt.boot_id != current_boot.trim()
                || !receipt.load_completed
                || !receipt.prog_done
                || receipt.bitstream_sha256 != C43_BITSTREAM_SHA256
                || pin.trim() != C43_BITSTREAM_SHA256
            {
                return Err(
                    "C43 loaded fabric does not match this boot and exact admitted source".into(),
                );
            }
            let lease =
                I2cRawFabricLease::reserve_bitbang(STOCK_S9_FPGA_IIC).map_err(|e| e.to_string())?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_SYNC | libc::O_CLOEXEC)
                .open("/dev/mem")
                .map_err(|e| e.to_string())?;
            // SAFETY: page-aligned physical base and page length; the retained
            // file and owner outlive all aligned accesses and exactly one unmap.
            let pointer = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    MAP_BYTES,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    PHYSICAL_BASE,
                )
            };
            if pointer == libc::MAP_FAILED {
                return Err(std::io::Error::last_os_error().to_string());
            }
            let owner = Arc::new(Self {
                pointer: pointer as usize,
                _file: file,
                lease,
            });
            if owner.read(0)? & 0xffff != u32::from(reg::HARDWARE_VERSION_VALUE) {
                return Err("C43 hardware version readback is not stock C501".into());
            }
            Ok(owner)
        })
        .await
        .map_err(|e| format!("C43 mapping worker: {e}"))?
    }
}
impl Drop for C43NativeMmio {
    fn drop(&mut self) {
        // SAFETY: this uniquely-owned mapping is unmapped only after its last Arc.
        unsafe {
            libc::munmap(self.pointer as *mut libc::c_void, MAP_BYTES);
        }
    }
}

/// Narrow register backend used by the retained transport and recording tests.
pub trait C43Registers: Send + Sync + 'static {
    fn read(&self, offset: u32) -> Result<u32, String>;
    fn write(&self, offset: u32, value: u32) -> Result<(), String>;
}
impl C43Registers for C43NativeMmio {
    fn read(&self, offset: u32) -> Result<u32, String> {
        self.lease
            .validate_current_process()
            .map_err(|e| e.to_string())?;
        if offset & 3 != 0 || offset >= 0x160 {
            return Err("C43 register outside retained window".into());
        }
        // SAFETY: aligned bounded register inside retained mapped page.
        Ok(unsafe { std::ptr::read_volatile((self.pointer + offset as usize) as *const u32) })
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.lease
            .validate_current_process()
            .map_err(|e| e.to_string())?;
        if offset & 3 != 0 || offset >= 0x160 || offset == 0 {
            return Err("C43 write outside writable retained window".into());
        }
        // SAFETY: aligned bounded register inside retained mapped page. The
        // outer transaction lane prevents interleaved command/FIFO sequences.
        unsafe {
            std::ptr::write_volatile((self.pointer + offset as usize) as *mut u32, value);
        }
        std::sync::atomic::fence(Ordering::SeqCst);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct C43TemperatureSnapshot {
    pub chain: u8,
    pub readings: Vec<(u8, f32, f32)>,
    pub sampled: Instant,
}

struct ConfiguredSensor {
    chip: u8,
    device: u8,
}

/// One chain was fenced, drained, reset and acknowledged fixed PIC OFF by
/// this retained owner. This is not a whole-owner terminal/disarm receipt.
#[derive(Debug)]
pub struct C43ChainIsolationReceipt {
    owner_id: u64,
    chain: u8,
}

/// Non-cloneable terminal barrier issued only by the retained hardware owner.
pub struct C43TerminalBarrierReceipt {
    owner_id: u64,
    drained: bool,
    _mapping: Arc<dyn C43Registers>,
}
impl C43TerminalBarrierReceipt {
    pub fn completed(&self) -> bool {
        self.drained
    }
}

pub struct C43PowerOffReceipt {
    owner_id: u64,
    chains: Vec<(u8, bool, bool)>,
}
impl C43PowerOffReceipt {
    pub fn completed(&self) -> bool {
        !self.chains.is_empty() && self.chains.iter().all(|(_, reset, pic)| *reset && *pic)
    }
    pub fn same_owner(&self, barrier: &C43TerminalBarrierReceipt) -> bool {
        self.owner_id == barrier.owner_id
    }
    pub fn chain_outcomes(&self) -> &[(u8, bool, bool)] {
        &self.chains
    }
}

pub struct C43CutReceipt {
    barrier: C43TerminalBarrierReceipt,
    power: C43PowerOffReceipt,
    errors: Vec<String>,
}
impl C43CutReceipt {
    pub fn completed(&self) -> bool {
        self.barrier.completed() && self.power.completed() && self.errors.is_empty()
    }
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
    pub fn into_parts(self) -> (C43TerminalBarrierReceipt, C43PowerOffReceipt) {
        (self.barrier, self.power)
    }
}

pub struct C43Transport<R: C43Registers> {
    owner_id: u64,
    registers: Arc<R>,
    chains: Vec<u8>,
    iic: Mutex<()>,
    command_fifo: Mutex<()>,
    management: Mutex<()>,
    pending_nonces: Mutex<VecDeque<[u32; 2]>>,
    sensors: Mutex<Vec<(u8, Vec<ConfiguredSensor>)>>,
    terminal: AtomicBool,
    fenced_chains: AtomicU16,
    isolated_chains: AtomicU16,
    isolation: Mutex<()>,
}

impl<R: C43Registers> C43Transport<R> {
    pub fn new(registers: Arc<R>, chains: Vec<u8>) -> Result<Arc<Self>, String> {
        if chains.is_empty()
            || chains.len() > 3
            || chains.iter().any(|c| *c > 15)
            || chains.windows(2).any(|w| w[0] >= w[1])
            || chains
                .iter()
                .enumerate()
                .any(|(i, c)| chains[..i].iter().any(|p| p & 7 == c & 7))
        {
            return Err(
                "C43 chain selection is empty, unordered or aliases a PIC/EEPROM address".into(),
            );
        }
        let present = registers.read(reg::HASH_ON_PLUG.byte_offset)?;
        if chains
            .iter()
            .any(|c| !reg::hash_on_plug_populated(present, *c))
        {
            return Err("C43 selected chain is absent".into());
        }
        static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
        let owner_id = NEXT_OWNER
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| v.checked_add(1))
            .map_err(|_| "C43 owner allocation exhausted")?;
        Ok(Arc::new(Self {
            owner_id,
            registers,
            chains,
            iic: Mutex::new(()),
            command_fifo: Mutex::new(()),
            management: Mutex::new(()),
            pending_nonces: Mutex::new(VecDeque::new()),
            sensors: Mutex::new(Vec::new()),
            terminal: AtomicBool::new(false),
            fenced_chains: AtomicU16::new(0),
            isolated_chains: AtomicU16::new(0),
            isolation: Mutex::new(()),
        }))
    }
    pub fn chains(&self) -> &[u8] {
        &self.chains
    }
    pub fn active_chains(&self) -> Vec<u8> {
        let isolated = self.isolated_chains.load(Ordering::SeqCst);
        self.chains
            .iter()
            .copied()
            .filter(|c| isolated & (1 << c) == 0)
            .collect()
    }
    pub fn chain_is_fenced(&self, chain: u8) -> bool {
        chain > 15 || self.fenced_chains.load(Ordering::SeqCst) & (1 << chain) != 0
    }
    fn active_chain(&self, chain: u8) -> Result<(), String> {
        self.active()?;
        self.chain(chain)?;
        if self.chain_is_fenced(chain) {
            Err(format!("C43 chain{chain} is permanently fenced"))
        } else {
            Ok(())
        }
    }
    /// Fence first, then retain both the owner and command lane through the
    /// physical reset/readback and complete PIC-off exchange. Failed proof
    /// escalates to the existing global terminal path; it never removes a
    /// chain from cooling/heartbeat requirements or weakens final closeout.
    pub async fn isolate_chain(
        self: &Arc<Self>,
        chain: u8,
    ) -> Result<C43ChainIsolationReceipt, String> {
        self.chain(chain)?;
        self.fenced_chains.fetch_or(1 << chain, Ordering::SeqCst);
        let result = self
            .blocking(move |owner| {
                let result = (|| {
                    let _isolation = owner
                        .isolation
                        .lock()
                        .map_err(|_| "C43 isolation lane poisoned")?;
                    if owner.isolated_chains.load(Ordering::SeqCst) & (1 << chain) == 0 {
                        let _command = owner
                            .command_fifo
                            .lock()
                            .map_err(|_| "C43 command drain poisoned")?;
                        owner.reset_inner(chain, true)?;
                        owner.pic_exchange_inner(chain, Bm1393PicCommand::Enable(false))?;
                        owner.isolated_chains.fetch_or(1 << chain, Ordering::SeqCst);
                    }
                    Ok(C43ChainIsolationReceipt {
                        owner_id: owner.owner_id,
                        chain,
                    })
                })();
                // This closure outlives cancellation of its async caller.
                if result.is_err() {
                    owner.latch_terminal();
                }
                result
            })
            .await;
        if result.is_err() {
            self.latch_terminal();
        }
        result
    }
    pub fn accepts_isolation(&self, receipt: &C43ChainIsolationReceipt) -> bool {
        !self.terminal()
            && receipt.owner_id == self.owner_id
            && self.isolated_chains.load(Ordering::SeqCst) & (1 << receipt.chain) != 0
    }
    fn read_register(&self, offset: u32) -> Result<u32, String> {
        let result = self.registers.read(offset);
        if result.is_err() {
            self.latch_terminal();
        }
        result
    }
    fn write_register(&self, offset: u32, word: u32) -> Result<(), String> {
        let result = self.registers.write(offset, word);
        if result.is_err() {
            self.latch_terminal();
        }
        result
    }
    pub fn terminal(&self) -> bool {
        self.terminal.load(Ordering::SeqCst)
    }
    pub fn latch_terminal(&self) {
        self.terminal.store(true, Ordering::SeqCst);
    }
    /// Permanently fence new energizing work, wait for in-flight commands,
    /// assert every selected reset and obtain every fixed PIC off ACK. Errors
    /// are retained; an incomplete receipt cannot authorize watchdog disarm.
    pub async fn terminal_cut(self: &Arc<Self>) -> C43CutReceipt {
        self.latch_terminal();
        let mut errors = Vec::new();
        let drained = self
            .blocking(|owner| {
                let _command = owner
                    .command_fifo
                    .lock()
                    .map_err(|_| "C43 command drain poisoned")?;
                let _iic = owner.iic.lock().map_err(|_| "C43 IIC drain poisoned")?;
                Ok(())
            })
            .await;
        let barrier_drained = drained.is_ok();
        if let Err(error) = drained {
            errors.push(error);
        }
        let mut chains = Vec::new();
        for &chain in &self.chains {
            let reset = self.reset(chain, true).await;
            let pic = self.pic(chain, Bm1393PicCommand::Enable(false)).await;
            chains.push((chain, reset.is_ok(), pic.is_ok()));
            if let Err(error) = reset {
                errors.push(error);
            }
            if let Err(error) = pic {
                errors.push(error);
            }
        }
        C43CutReceipt {
            barrier: C43TerminalBarrierReceipt {
                owner_id: self.owner_id,
                drained: barrier_drained,
                _mapping: self.registers.clone(),
            },
            power: C43PowerOffReceipt {
                owner_id: self.owner_id,
                chains,
            },
            errors,
        }
    }
    fn chain(&self, chain: u8) -> Result<(), String> {
        if self.chains.contains(&chain) {
            Ok(())
        } else {
            Err("C43 chain is outside retained population".into())
        }
    }
    fn active(&self) -> Result<(), String> {
        if self.terminal() {
            Err("C43 owner is terminal".into())
        } else {
            Ok(())
        }
    }
    async fn blocking<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&Self) -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let owner = Arc::clone(self);
        tokio::task::spawn_blocking(move || operation(&owner))
            .await
            .map_err(|e| format!("C43 retained worker: {e}"))?
    }
    fn wait(
        &self,
        offset: u32,
        deadline: Instant,
        predicate: impl Fn(u32) -> bool,
    ) -> Result<u32, String> {
        loop {
            let value = self.read_register(offset)?;
            if predicate(value) {
                return Ok(value);
            }
            if Instant::now() >= deadline {
                if offset == reg::BC_WRITE_COMMAND.byte_offset {
                    // This command engine is shared by every chain. Its
                    // unfinished frame cannot be quarantined as one board.
                    self.latch_terminal();
                }
                return Err(format!("C43 register{offset:#x} timed out ({value:#x})"));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn iic_byte(&self, command: u32, deadline: Instant) -> Result<u8, String> {
        self.write_register(
            reg::IIC_COMMAND.byte_offset,
            reg::iic_command_store_word(command),
        )?;
        // Original set_iic waits for signed-negative (bit31 complete). No
        // invented bit30 ACK interpretation; framed reply validates the PIC.
        Ok(self.wait(reg::IIC_COMMAND.byte_offset, deadline, |v| {
            v & 0x8000_0000 != 0
        })? as u8)
    }
    pub async fn read_factory(self: &Arc<Self>, chain: u8) -> Result<Box<[u8; 256]>, String> {
        self.chain(chain)?;
        self.blocking(move |owner| {
            let _lane = owner.iic.lock().map_err(|_| "C43 IIC lane poisoned")?;
            owner.active()?;
            let mut bytes = Box::new([0; 256]);
            let deadline = Instant::now() + Duration::from_secs(5);
            for (offset, value) in bytes.iter_mut().enumerate() {
                // Fixed AT24 register read. No EEPROM data-writing operation
                // exists in this service, including the failure path.
                *value = owner.iic_byte(
                    reg::pack_zynq_iic(0x50 | (chain & 7), 0, true, true, offset as u8, 0),
                    deadline,
                )?;
            }
            Ok(bytes)
        })
        .await
    }
    fn pic_exchange_inner(&self, chain: u8, command: Bm1393PicCommand) -> Result<Vec<u8>, String> {
        let _lane = self.iic.lock().map_err(|_| "C43 IIC lane poisoned")?;
        if command != Bm1393PicCommand::Enable(false) {
            self.active_chain(chain)?;
        }
        let (frame, response_len) = command.wire()?;
        let address = 0x20 | (chain & 7);
        let deadline = Instant::now() + Duration::from_secs(3);
        let exchange = (|| {
            for byte in frame {
                self.iic_byte(
                    reg::pack_zynq_iic(address, 0, false, false, 0, byte),
                    deadline,
                )?;
            }
            // send_pic_cmd@70292..70296 encodes550000 microseconds exactly.
            std::thread::sleep(Duration::from_micros(550_000));
            let mut response = Vec::with_capacity(response_len);
            for _ in 0..response_len {
                response.push(
                    self.iic_byte(reg::pack_zynq_iic(address, 0, true, false, 0, 0), deadline)?,
                );
            }
            command.validate(&response)?;
            Ok(response)
        })();
        if exchange.is_err() {
            // Preserve this lane across failure/cancellation and flush every
            // PIC error, including NACK represented by timeout or bad ACK.
            let flush_deadline = Instant::now() + Duration::from_millis(500);
            for _ in 0..16 {
                let _ = self.iic_byte(
                    reg::pack_zynq_iic(address, 0, false, false, 0, 0),
                    flush_deadline,
                );
            }
        }
        exchange
    }
    pub async fn pic(
        self: &Arc<Self>,
        chain: u8,
        command: Bm1393PicCommand,
    ) -> Result<Vec<u8>, String> {
        self.chain(chain)?;
        self.blocking(move |owner| owner.pic_exchange_inner(chain, command))
            .await
    }
    pub async fn reset(self: &Arc<Self>, chain: u8, asserted: bool) -> Result<(), String> {
        self.chain(chain)?;
        self.blocking(move |owner| owner.reset_inner(chain, asserted))
            .await
    }
    fn reset_inner(&self, chain: u8, asserted: bool) -> Result<(), String> {
        let _lane = self
            .management
            .lock()
            .map_err(|_| "C43 management lane poisoned")?;
        if !asserted {
            self.active_chain(chain)?;
        }
        let previous = self.read_register(reg::RESET_HASHBOARD.byte_offset)?;
        let value =
            reg::apply_hashboard_reset(previous, chain, asserted).map_err(|e| format!("{e:?}"))?;
        self.write_register(reg::RESET_HASHBOARD.byte_offset, value)?;
        if self.read_register(reg::RESET_HASHBOARD.byte_offset)? & (1 << chain)
            != value & (1 << chain)
        {
            return Err("C43 reset readback mismatch".into());
        }
        Ok(())
    }
    pub async fn fan(self: &Arc<Self>, percent: u8) -> Result<Vec<(u8, u32)>, String> {
        if !(5..=30).contains(&percent) {
            return Err("C43 fan command exceeds home ceiling".into());
        }
        self.blocking(move |owner| {
            let _lane = owner
                .management
                .lock()
                .map_err(|_| "C43 management lane poisoned")?;
            // set_PWM1981a: high=floor(50*pct/100), low=floor(50*(100-pct)/100).
            let word = ((u32::from(percent) / 2) << 16) | ((100 - u32::from(percent)) / 2);
            owner.write_register(reg::FAN_CONTROL.byte_offset, word)?;
            if owner.read_register(reg::FAN_CONTROL.byte_offset)? != word {
                return Err("C43 fan PWM readback mismatch".into());
            }
            let mut tach = Vec::new();
            for _ in 0..16 {
                let sample = owner.read_register(reg::FAN_SPEED.byte_offset)?;
                let id = ((sample >> 8) & 7) as u8;
                let rpm = (sample & 255) * 120;
                if !tach.iter().any(|(seen, _)| *seen == id) {
                    tach.push((id, rpm));
                }
            }
            Ok(tach)
        })
        .await
    }
    fn asic_inner(&self, chain: u8, bytes: &[u8]) -> Result<(), String> {
        self.active_chain(chain)?;
        if !matches!(bytes.len(), 5 | 9)
            || usize::from(bytes[1]) != bytes.len()
            || s9se_vil::crc5_bits(&bytes[..bytes.len() - 1], ((bytes.len() - 1) * 8) as u32)
                != bytes[bytes.len() - 1]
        {
            return Err("C43 ASIC command is not a complete CRC5 VIL frame".into());
        }
        let previous = self.wait(
            reg::BC_WRITE_COMMAND.byte_offset,
            Instant::now() + Duration::from_millis(250),
            |v| v & reg::BC_WRITE_BUSY_BIT == 0,
        )?;
        let mut padded = [0; 12];
        padded[..bytes.len()].copy_from_slice(bytes);
        for (i, chunk) in padded.chunks_exact(4).enumerate() {
            self.write_register(
                reg::BC_COMMAND_BUFFER0.byte_offset + i as u32 * 4,
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]),
            )?;
        }
        self.write_register(
            reg::BC_WRITE_COMMAND.byte_offset,
            reg::pack_bc_write_command(previous, chain).map_err(|e| format!("{e:?}"))?,
        )?;
        self.wait(
            reg::BC_WRITE_COMMAND.byte_offset,
            Instant::now() + Duration::from_millis(250),
            |v| v & reg::BC_WRITE_BUSY_BIT == 0,
        )?;
        Ok(())
    }
    pub async fn asic(self: &Arc<Self>, chain: u8, bytes: Vec<u8>) -> Result<(), String> {
        self.chain(chain)?;
        self.blocking(move |owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            owner.asic_inner(chain, &bytes)
        })
        .await
    }
    pub async fn configure(self: &Arc<Self>) -> Result<(), String> {
        self.blocking(|owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            owner.active()?;
            // raw scan-frequency sender uses0x8100, retains unrelated DHASH
            // fields. It does not consume nonce2/job DMA or touch RAM addresses.
            let previous = owner.read_register(reg::DHASH_ACC_CONTROL.byte_offset)?;
            owner.write_register(
                reg::DHASH_ACC_CONTROL.byte_offset,
                previous & 0xffff_70df | 0x8100,
            )?;
            owner.write_register(reg::HASH_COUNTING_NUMBER.byte_offset, 0)?;
            let previous = owner.read_register(reg::BC_WRITE_COMMAND.byte_offset)?;
            owner.write_register(
                reg::BC_WRITE_COMMAND.byte_offset,
                reg::pack_bc_write_baud(previous, 26),
            )?;
            Ok(())
        })
        .await
    }
    pub async fn set_baud(self: &Arc<Self>, divisor: u8) -> Result<(), String> {
        if !matches!(divisor, 1 | 26) {
            return Err("C43 baud is outside the stock startup ladder".into());
        }
        self.blocking(move |owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            owner.active()?;
            let previous = owner.wait(
                reg::BC_WRITE_COMMAND.byte_offset,
                Instant::now() + Duration::from_millis(250),
                |v| v & reg::BC_WRITE_BUSY_BIT == 0,
            )?;
            owner.write_register(
                reg::BC_WRITE_COMMAND.byte_offset,
                reg::pack_bc_write_baud(previous, divisor),
            )
        })
        .await
    }
    pub async fn timeout(self: &Arc<Self>, word: u32) -> Result<(), String> {
        if word & !0x8001_ffff != 0 || word & 0x8000_0000 == 0 {
            return Err("invalid C43 enabled timeout word".into());
        }
        self.blocking(move |owner| {
            owner.active()?;
            owner.write_register(reg::TIME_OUT_CONTROL.byte_offset, word)
        })
        .await
    }
    pub async fn work(self: &Arc<Self>, chain: u8, words: [u32; 13]) -> Result<(), String> {
        self.chain(chain)?;
        let real = 0x0180_0000 | (u32::from(chain) << 16);
        let dummy = dcentrald_common::s9se_init::open_core_tw0(chain);
        if words[0] != real && !(words[0] == dummy && words[1..].iter().all(|w| *w == 0)) {
            return Err("C43 work header does not bind the selected chain".into());
        }
        if words[0] == real && words[1] >= 32768 {
            return Err("C43 work ID exceeds returned15-bit field".into());
        }
        self.blocking(move |owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            owner.active_chain(chain)?;
            owner.wait(
                reg::BUFFER_SPACE.byte_offset,
                Instant::now() + Duration::from_millis(250),
                |v| v & (1 << chain) != 0,
            )?;
            owner.active_chain(chain)?;
            owner.write_register(reg::TW_WRITE.byte_offset, words[0])?;
            for &word in &words[1..] {
                owner.write_register(reg::TW_WRITE_CONT.byte_offset, word)?;
            }
            Ok(())
        })
        .await
    }
    /// One bounded, nonblocking round-robin visit to the existing raw-TW
    /// buffers. A full chain does not hold the shared lane while others are
    /// writable. Per-chain successes are a prefix so unaccepted work can stay
    /// queued with its original ID. Thirteen-word frames never interleave.
    pub async fn try_work_batch(
        self: &Arc<Self>,
        items: Vec<(u8, [u32; 13])>,
    ) -> Result<Vec<bool>, String> {
        if items.is_empty() || items.len() > dcentrald_common::bm1393_native::BM1393_MAX_WORK_BATCH
        {
            return Err("C43 work batch is empty or exceeds bound".into());
        }
        for (chain, words) in &items {
            self.chain(*chain)?;
            if words[0] != (0x0180_0000 | (u32::from(*chain) << 16)) || words[1] >= 32768 {
                return Err("C43 batch requires exact real-work chain and15-bit ID".into());
            }
        }
        self.blocking(move |owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            let mut blocked = 0u16;
            let mut accepted = Vec::with_capacity(items.len());
            for (chain, words) in items {
                owner.active()?;
                let bit = 1u16 << chain;
                if blocked & bit != 0 || owner.chain_is_fenced(chain) {
                    accepted.push(false);
                    continue;
                }
                if owner.read_register(reg::BUFFER_SPACE.byte_offset)? & u32::from(bit) == 0 {
                    blocked |= bit;
                    accepted.push(false);
                    continue;
                }
                // An isolation fence may have appeared while reading capacity.
                // Its cut waits for this retained lane before it can complete.
                if owner.chain_is_fenced(chain) {
                    accepted.push(false);
                    continue;
                }
                let written = (|| {
                    owner.write_register(reg::TW_WRITE.byte_offset, words[0])?;
                    for word in &words[1..] {
                        owner.write_register(reg::TW_WRITE_CONT.byte_offset, *word)?;
                    }
                    Ok::<(), String>(())
                })();
                if let Err(error) = written {
                    // Partial framing is a shared FIFO failure. Never pretend
                    // the remaining chains can safely continue after it.
                    owner.latch_terminal();
                    return Err(error);
                }
                accepted.push(true);
            }
            Ok(accepted)
        })
        .await
    }
    fn fifo_pair(&self) -> Result<Option<[u32; 2]>, String> {
        if self.read_register(reg::NONCE_NUMBER_IN_FIFO.byte_offset)? & 0x1ff == 0 {
            return Ok(None);
        }
        Ok(Some([
            self.read_register(reg::RETURN_NONCE0.byte_offset)?,
            self.read_register(reg::RETURN_NONCE1.byte_offset)?,
        ]))
    }
    fn retain_nonce(&self, pair: [u32; 2]) -> Result<(), String> {
        if matches!(classify_return_record(pair[0], pair[1]), Some(S9SeFifoRecord::Nonce { chain, .. }) if self.chains.contains(&chain))
        {
            let mut pending = self
                .pending_nonces
                .lock()
                .map_err(|_| "C43 return queue poisoned")?;
            if pending.len() >= 2048 {
                return Err("C43 pending nonce queue overflow".into());
            }
            pending.push_back(pair);
        }
        Ok(())
    }
    fn register_inner(&self, chain: u8, chip: u8, register: u8) -> Result<u32, String> {
        // Drain stale records before the command while retaining unrelated work.
        for _ in 0..512 {
            match self.fifo_pair()? {
                Some(pair) => self.retain_nonce(pair)?,
                None => break,
            }
        }
        self.asic_inner(chain, &s9se_regs::pack_read_vil(chip, register, false))?;
        let deadline = Instant::now() + Duration::from_millis(150);
        loop {
            if let Some(pair) = self.fifo_pair()? {
                match classify_return_record(pair[0], pair[1]) {
                    Some(S9SeFifoRecord::Register {
                        chain: c,
                        chip: a,
                        reg: r,
                        crc_error: false,
                        value,
                        ..
                    }) if c == chain && a == chip && r == register => return Ok(value),
                    _ => self.retain_nonce(pair)?,
                }
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "C43 correlated register timeout chain{chain} chip{chip:#x} reg{register:#x}"
                ));
            }
        }
    }
    pub async fn coverage(self: &Arc<Self>, chain: u8) -> Result<Vec<(u8, u16)>, String> {
        self.chain(chain)?;
        self.blocking(move |owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            owner.active()?;
            let previous = owner.read_register(reg::NONCE_FIFO_INTERRUPT.byte_offset)?;
            owner.write_register(reg::NONCE_FIFO_INTERRUPT.byte_offset, previous | 0x10000)?;
            owner.asic_inner(chain, &s9se_regs::pack_read_vil(0, 0, true))?;
            let mut responses = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if let Some(pair) = owner.fifo_pair()? {
                    match classify_return_record(pair[0], pair[1]) {
                        Some(S9SeFifoRecord::Register {
                            chain: c,
                            chip,
                            reg: 0,
                            crc_error: false,
                            value,
                            ..
                        }) if c == chain => responses.push((chip, (value >> 16) as u16)),
                        _ => owner.retain_nonce(pair)?,
                    }
                    if responses.len() > 60 {
                        return Err("C43 coverage has excess or duplicate responders".into());
                    }
                } else {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            Ok(responses)
        })
        .await
    }
    pub async fn returns(self: &Arc<Self>, maximum: u16) -> Result<Vec<[u32; 2]>, String> {
        if maximum == 0 || maximum > 128 {
            return Err("C43 return batch outside bound".into());
        }
        self.blocking(move |owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            owner.active()?;
            let mut result = Vec::new();
            let mut pending = owner
                .pending_nonces
                .lock()
                .map_err(|_| "C43 return queue poisoned")?;
            while result.len() < usize::from(maximum) {
                if let Some(pair) = pending.pop_front() {
                    result.push(pair);
                } else if let Some(pair) = owner.fifo_pair()? {
                    result.push(pair);
                } else {
                    break;
                }
            }
            Ok(result)
        })
        .await
    }
    /// Retire all prior return records before a new discovery generation. The
    /// same command/FIFO lane also owns temperature replies, so no other reader
    /// can race this bounded hardware and software drain.
    pub async fn flush_returns(self: &Arc<Self>) -> Result<(), String> {
        self.blocking(|owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            owner.active()?;
            owner
                .pending_nonces
                .lock()
                .map_err(|_| "C43 return queue poisoned")?
                .clear();
            let value = owner.read_register(reg::NONCE_FIFO_INTERRUPT.byte_offset)?;
            owner.write_register(reg::NONCE_FIFO_INTERRUPT.byte_offset, value | 0x10000)?;
            for _ in 0..512 {
                if owner.fifo_pair()?.is_none() {
                    return Ok(());
                }
            }
            Err("C43 FIFO did not drain within its physical depth".into())
        })
        .await
    }
    fn sensor_register(
        &self,
        chain: u8,
        chip: u8,
        device: u8,
        register: u8,
        write: Option<u8>,
    ) -> Result<u8, String> {
        for _ in 0..2 {
            self.register_inner(chain, chip, 0x1c)?;
            self.asic_inner(
                chain,
                &s9se_temp::pack_read_temp_vil(
                    chip,
                    device,
                    register,
                    write.unwrap_or(0),
                    write.is_some(),
                ),
            )?;
            std::thread::sleep(Duration::from_millis(1));
            let value = self.register_inner(chain, chip, 0x1c)?;
            if (value >> 8) as u8 == register
                && write.is_none_or(|expected| value as u8 == expected)
            {
                return Ok(value as u8);
            }
        }
        Err("C43 sensor register did not correlate or acknowledge".into())
    }
    pub async fn configure_temperature(
        self: &Arc<Self>,
        chain: u8,
        profile: Bm1393FactoryProfile,
    ) -> Result<C43TemperatureSnapshot, String> {
        self.chain(chain)?;
        self.blocking(move |owner| {
            let _lane = owner
                .command_fifo
                .lock()
                .map_err(|_| "C43 command lane poisoned")?;
            let mut sensors = Vec::new();
            for site in profile.sites() {
                owner.asic_inner(
                    chain,
                    &s9se_vil::pack_set_config_single(
                        site.chip_addr,
                        0x18,
                        s9se_regs::misc_with_i2c(
                            s9se_regs::misc_with_baud(
                                s9se_regs::MISC_CONTROL_DEFAULT,
                                (owner.read_register(reg::BC_WRITE_COMMAND.byte_offset)? & 0x1f)
                                    as u8,
                            )
                            .map_err(|_| "C43 active baud is not a MISC divisor")?,
                        ),
                    ),
                )?;
                let mut device = None;
                for candidate in [profile.preferred_sensor_device(), 0x98, 0x9a, 0x9c] {
                    if let Ok(0x1a | 0x55 | 0x41) =
                        owner.sensor_register(chain, site.chip_addr, candidate, 0xfe, None)
                    {
                        device = Some(candidate);
                        break;
                    }
                }
                let device = device.ok_or("C43 factory sensor manufacturer not observed")?;
                owner.sensor_register(chain, site.chip_addr, device, 9, Some(4))?;
                owner.sensor_register(
                    chain,
                    site.chip_addr,
                    device,
                    0x11,
                    Some(site.offset as u8),
                )?;
                sensors.push(ConfiguredSensor {
                    chip: site.chip_addr,
                    device,
                });
            }
            let sample = owner.sample_inner(chain, &sensors)?;
            let mut all = owner
                .sensors
                .lock()
                .map_err(|_| "C43 sensor registry poisoned")?;
            if all.iter().any(|(c, _)| *c == chain) {
                return Err("C43 sensors already configured for chain".into());
            }
            all.push((chain, sensors));
            Ok(sample)
        })
        .await
    }
    fn sample_inner(
        &self,
        chain: u8,
        sensors: &[ConfiguredSensor],
    ) -> Result<C43TemperatureSnapshot, String> {
        let mut readings = Vec::new();
        for sensor in sensors {
            let local =
                f32::from(self.sensor_register(chain, sensor.chip, sensor.device, 0, None)?) - 64.0;
            let remote =
                f32::from(self.sensor_register(chain, sensor.chip, sensor.device, 1, None)?) - 64.0;
            if !(-40.0..=110.0).contains(&local) || !(-40.0..=125.0).contains(&remote) {
                return Err("C43 temperature outside plausible extended range".into());
            }
            readings.push((sensor.chip, local, remote));
        }
        if readings.is_empty() {
            return Err("C43 temperature sites empty".into());
        }
        Ok(C43TemperatureSnapshot {
            chain,
            readings,
            sampled: Instant::now(),
        })
    }
    pub async fn temperatures(self: &Arc<Self>) -> Result<Vec<C43TemperatureSnapshot>, String> {
        let samples = self
            .blocking(|owner| {
                let _lane = owner
                    .command_fifo
                    .lock()
                    .map_err(|_| "C43 command lane poisoned")?;
                owner.active()?;
                let all = owner
                    .sensors
                    .lock()
                    .map_err(|_| "C43 sensor registry poisoned")?;
                Ok(all
                    .iter()
                    // A fence alone cannot exempt a board from thermal custody.
                    // If a concurrent cut is still pending, sampling fails into
                    // isolate_chain below and joins its checked completion.
                    .filter(|(chain, _)| {
                        owner.isolated_chains.load(Ordering::SeqCst) & (1 << chain) == 0
                    })
                    .map(|(chain, sensors)| (*chain, owner.sample_inner(*chain, sensors)))
                    .collect::<Vec<_>>())
            })
            .await?;
        let mut temperatures = Vec::new();
        for (chain, sample) in samples {
            match sample {
                Ok(value) => temperatures.push(value),
                Err(error) => {
                    let proof = self.isolate_chain(chain).await?;
                    if !self.accepts_isolation(&proof) {
                        self.latch_terminal();
                        return Err("C43 sensor isolation owner mismatch".into());
                    }
                    tracing::error!(chain, %error, "C43 sensor fault: chain reset and powered off");
                }
            }
        }
        Ok(temperatures)
    }
}

#[cfg(test)]
#[path = "c43_bm1393_transport_tests.rs"]
mod tests;
