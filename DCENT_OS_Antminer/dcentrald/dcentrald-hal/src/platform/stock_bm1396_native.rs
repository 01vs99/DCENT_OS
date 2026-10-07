//! Exact boot/current-kernel binding and retained uncached MMIO/DMA mappings.
//! Held-kernel phys_mem_access_prot c0114778 and full helper-chain replay:
//! evidence/r06/native-devmem-mapping-v1.md (60 original function calls).
use super::*;
use crate::i2c::I2cRawFabricLease;
use dcentrald_fabric_lease::topology::STOCK_S9_FPGA_IIC;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const AXI_MAP_BYTES: usize = 0x2000; // Original requested 0x1200, rounded pages.
const DMA_NODE: &str = "reserved-memory/bm1396-dma@f000000";
const KERNEL_RELEASE: &str = "4.6.0-xilinx-g20b57cf-dirty";

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

fn protected(path: &Path, maximum: usize, uid: u32) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("BM1396 {}: {e}", path.display()))?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    if !info.is_file()
        || info.uid() != uid
        || info.mode() & 0o022 != 0
        || info.len() > maximum as u64
    {
        return Err(format!(
            "BM1396 {} is unprotected or oversized",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > maximum {
        return Err("BM1396 protected input exceeded bound while reading".into());
    }
    Ok(bytes)
}

fn protected_text(path: &str) -> Result<String, String> {
    String::from_utf8(protected(Path::new(path), 4096, 0)?).map_err(|e| e.to_string())
}

fn validate_receipt(
    receipt: &FabricReceipt,
    boot: &str,
    target: &str,
    pin: &str,
    model: Model,
) -> Result<(), String> {
    // Strict UUID shape prevents an empty/malformed pseudo-current-boot value.
    let boot = boot.trim();
    if boot.len() != 36
        || !boot.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
        || receipt.schema != 1
        || receipt.boot_id != boot
        || receipt.board_target != board_target(model)
        || target.trim() != board_target(model)
        || receipt.bitstream_sha256 != BITSTREAM_SHA256
        || pin.trim() != BITSTREAM_SHA256
        || !receipt.load_completed
        || !receipt.prog_done
    {
        return Err(
            "BM1396 exact payload/model/current-boot programming binding is missing".into(),
        );
    }
    Ok(())
}

fn validate_dma_tree(root: &Path, uid: u32) -> Result<(), String> {
    let read = |name: &str, maximum| protected(&root.join(name), maximum, uid);
    for name in [
        "#address-cells",
        "#size-cells",
        "reserved-memory/#address-cells",
        "reserved-memory/#size-cells",
    ] {
        if read(name, 4)? != 1u32.to_be_bytes() {
            return Err("BM1396 DMA address/size cell mismatch".into());
        }
    }
    if read("memory@0/reg", 8)? != [0, 0, 0, 0, 0x10, 0, 0, 0]
        || !read("reserved-memory/ranges", 0)?.is_empty()
        || read(&format!("{DMA_NODE}/reg"), 8)? != [0x0f, 0, 0, 0, 1, 0, 0, 0]
        || read(&format!("{DMA_NODE}/compatible"), 64)? != b"dcent,bm1396-stock-fpga-dma\0"
        || !read(&format!("{DMA_NODE}/no-map"), 0)?.is_empty()
    {
        return Err("BM1396 exact 256 MiB / 16 MiB no-map DMA profile is missing".into());
    }
    for name in ["status", "reusable"] {
        match std::fs::symlink_metadata(root.join(DMA_NODE).join(name)) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
            _ => return Err("BM1396 DMA reservation must be enabled and non-reusable".into()),
        }
    }
    // A second reservation must not alias the FPGA-owned memory. Dynamic
    // reservations cannot be resolved here and are not silently accepted.
    for child in std::fs::read_dir(root.join("reserved-memory")).map_err(|e| e.to_string())? {
        let child = child.map_err(|e| e.to_string())?;
        let info = child.file_type().map_err(|e| e.to_string())?;
        if info.is_symlink() {
            return Err("BM1396 reserved-memory contains a symlink".into());
        }
        if !info.is_dir() || child.file_name() == "bm1396-dma@f000000" {
            continue;
        }
        let reg = protected(&child.path().join("reg"), 4096, uid)?;
        if reg.is_empty() || reg.len() % 8 != 0 {
            return Err("BM1396 peer reservation has unresolved range".into());
        }
        for pair in reg.chunks_exact(8) {
            let start = u32::from_be_bytes(pair[..4].try_into().expect("four bytes")) as u64;
            let length = u32::from_be_bytes(pair[4..].try_into().expect("four bytes")) as u64;
            if length == 0
                || (start < u64::from(DMA_BASE) + DMA_BYTES as u64
                    && start + length > u64::from(DMA_BASE))
            {
                return Err("BM1396 peer reservation overlaps DMA or is empty".into());
            }
        }
    }
    Ok(())
}

fn validate_iomem(text: &str) -> Result<(), String> {
    let mut visible_ram_end = None;
    for line in text.lines() {
        let Some((range, label)) = line.split_once(':') else {
            continue;
        };
        if label.trim() != "System RAM" {
            continue;
        }
        let (start, end) = range
            .trim()
            .split_once('-')
            .ok_or("BM1396 malformed System RAM range")?;
        let start = u64::from_str_radix(start, 16).map_err(|e| e.to_string())?;
        let end = u64::from_str_radix(end, 16).map_err(|e| e.to_string())?;
        if end < start
            || (start < u64::from(DMA_BASE) + DMA_BYTES as u64 && end >= u64::from(DMA_BASE))
        {
            return Err("BM1396 DMA overlaps live System RAM".into());
        }
        visible_ram_end = Some(visible_ram_end.unwrap_or(0).max(end));
    }
    if visible_ram_end != Some(u64::from(DMA_BASE) - 1) {
        return Err(
            "BM1396 live System RAM map is missing, redacted or differs from exact no-map profile"
                .into(),
        );
    }
    Ok(())
}

fn validate_kernel(release: &str, config: &[u8]) -> Result<(), String> {
    if release.trim() != KERNEL_RELEASE {
        return Err("BM1396 running kernel differs from retained mapping profile".into());
    }
    let config = std::str::from_utf8(config).map_err(|e| e.to_string())?;
    for required in [
        "CONFIG_MMU=y",
        "CONFIG_ARCH_ZYNQ=y",
        "CONFIG_CPU_V7=y",
        "CONFIG_HAVE_ARCH_PFN_VALID=y",
        "CONFIG_ARM_DMA_MEM_BUFFERABLE=y",
        "# CONFIG_ARM_LPAE is not set",
    ] {
        if config.lines().filter(|line| *line == required).count() != 1 {
            return Err(format!(
                "BM1396 kernel mapping configuration missing {required}"
            ));
        }
    }
    if config.lines().any(|line| line == "CONFIG_ARM_LPAE=y") {
        return Err("BM1396 LPAE mapper is not the pinned kernel path".into());
    }
    Ok(())
}

struct Mapping {
    pointer: usize,
    bytes: usize,
}
// SAFETY: mapping lifetime is retained by its owner; all exposed accesses are
// checked volatile operations, and compound operations use the transport lanes.
unsafe impl Send for Mapping {}
// SAFETY: volatile memory access is permitted under the same retained owner;
// no ordinary Rust references to device/DMA memory are ever created.
unsafe impl Sync for Mapping {}
impl Mapping {
    fn new(file: &File, physical: u32, bytes: usize) -> Result<Self, String> {
        // SAFETY: checked fixed page-aligned physical regions, matching Drop
        // length; the native factory establishes uncached/non-RAM mapping first.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                file.as_raw_fd(),
                physical as libc::off_t,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self {
            pointer: pointer as usize,
            bytes,
        })
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this exact mapping/length was created once in Mapping::new,
        // and no references outlive its final retained NativeMmio owner.
        unsafe {
            libc::munmap(self.pointer as *mut libc::c_void, self.bytes);
        }
    }
}

pub struct NativeMmio {
    axi: Mapping,
    dma: Mapping,
    model: Model,
    claimed: AtomicBool,
    _file: File,
    lease: I2cRawFabricLease,
}

impl NativeMmio {
    pub(super) async fn open(model: Model) -> Result<Arc<Self>, String> {
        tokio::task::spawn_blocking(move || {
            let receipt: FabricReceipt =
                serde_json::from_str(&protected_text("/run/dcentos/bm1396-fabric.json")?)
                    .map_err(|e| e.to_string())?;
            validate_receipt(
                &receipt,
                &std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                    .map_err(|e| e.to_string())?,
                &protected_text("/etc/dcentos/board_target")?,
                &protected_text("/etc/dcentos/bm1396-bitstream.sha256")?,
                model,
            )?;
            validate_dma_tree(Path::new("/proc/device-tree"), 0)?;
            let mut config = Vec::new();
            flate2::read::GzDecoder::new(
                &protected(Path::new("/proc/config.gz"), 1024 * 1024, 0)?[..],
            )
            .take(2 * 1024 * 1024 + 1)
            .read_to_end(&mut config)
            .map_err(|e| e.to_string())?;
            if config.len() > 2 * 1024 * 1024 {
                return Err("BM1396 kernel config exceeds bound".into());
            }
            validate_kernel(
                &std::fs::read_to_string("/proc/sys/kernel/osrelease")
                    .map_err(|e| e.to_string())?,
                &config,
            )?;
            validate_iomem(
                &String::from_utf8(protected(Path::new("/proc/iomem"), 1024 * 1024, 0)?)
                    .map_err(|e| e.to_string())?,
            )?;
            let modules = std::fs::read_to_string("/proc/modules").map_err(|e| e.to_string())?;
            if modules.lines().any(|line| {
                matches!(
                    line.split_whitespace().next(),
                    Some("bitmain_axi" | "fpga_mem")
                )
            }) {
                return Err(
                    "BM1396 stock raw mapper module conflicts with native ownership".into(),
                );
            }
            let lease =
                I2cRawFabricLease::reserve_bitbang(STOCK_S9_FPGA_IIC).map_err(|e| e.to_string())?;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_SYNC | libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open("/dev/mem")
                .map_err(|e| e.to_string())?;
            let axi = Mapping::new(&file, PHYSICAL_BASE, AXI_MAP_BYTES)?;
            let dma = Mapping::new(&file, DMA_BASE, DMA_BYTES)?;
            Ok(Arc::new(Self {
                axi,
                dma,
                model,
                claimed: AtomicBool::new(false),
                _file: file,
                lease,
            }))
        })
        .await
        .map_err(|e| format!("BM1396 native mapping worker: {e}"))?
    }

    fn bounds(&self, offset: u32) -> Result<usize, String> {
        self.validate_owner()?;
        if offset & 3 != 0 || offset >= REGISTER_BYTES {
            return Err("BM1396 register outside original 0x1200 aperture".into());
        }
        Ok(self.axi.pointer + offset as usize)
    }
    fn dma_bounds(&self, offset: usize, length: usize) -> Result<usize, String> {
        self.validate_owner()?;
        if offset
            .checked_add(length)
            .map_or(true, |end| end > DMA_BYTES)
        {
            return Err("BM1396 DMA access outside retained window".into());
        }
        Ok(self.dma.pointer + offset)
    }
}

impl Hardware for NativeMmio {
    fn model(&self) -> Model {
        self.model
    }
    fn validate_owner(&self) -> Result<(), String> {
        self.lease
            .validate_current_process()
            .map_err(|e| e.to_string())
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.validate_owner()?;
        self.claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| "BM1396 native mapping already claimed".into())
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        let address = self.bounds(offset)?;
        // SAFETY: checked aligned address in the retained uncached AXI mapping.
        Ok(unsafe { std::ptr::read_volatile(address as *const u32) })
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let address = self.bounds(offset)?;
        if offset == 0 {
            return Err("BM1396 VERSION/reset write semantics are not admitted".into());
        }
        // SAFETY: checked aligned address, serialized by the owning transaction.
        unsafe {
            std::ptr::write_volatile(address as *mut u32, value);
        }
        self.barrier()
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        let address = self.dma_bounds(offset, out.len())?;
        for (index, byte) in out.iter_mut().enumerate() {
            // SAFETY: byte lies within the checked retained uncached DMA range.
            *byte = unsafe { std::ptr::read_volatile((address + index) as *const u8) };
        }
        self.barrier()
    }
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        let address = self.dma_bounds(offset, bytes.len())?;
        if offset < 0x200000 || offset + bytes.len() > 0x220000 {
            return Err("BM1396 host must never write FPGA-produced outstanding table".into());
        }
        for (index, byte) in bytes.iter().copied().enumerate() {
            // SAFETY: byte lies within a checked source job buffer, never the
            // FPGA-owned outstanding table or ordinary Linux RAM.
            unsafe {
                std::ptr::write_volatile((address + index) as *mut u8, byte);
            }
        }
        self.barrier()
    }
    fn barrier(&self) -> Result<(), String> {
        self.validate_owner()?;
        std::sync::atomic::fence(Ordering::SeqCst);
        #[cfg(target_arch = "arm")]
        // SAFETY: ARMv7 full-system data barrier has no memory operands and
        // orders/drains uncached stores before publishing the DMA address.
        unsafe {
            std::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: same full-system barrier on an AArch64 host compilation;
        // native open still rejects a non-matching running kernel/profile.
        unsafe {
            std::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        Ok(())
    }
}

impl Transport<NativeMmio> {
    pub async fn open_observed(model: Model) -> Result<Arc<Self>, String> {
        let hardware = NativeMmio::open(model).await?;
        let reader = Arc::clone(&hardware);
        let mask = tokio::task::spawn_blocking(move || reader.read(8))
            .await
            .map_err(|e| e.to_string())??
            & 0xffff;
        let chains = (0..16)
            .filter(|chain| mask & (1 << chain) != 0)
            .map(|chain| chain as u8)
            .collect();
        Self::observe(hardware, model, chains).await
    }
}

#[cfg(test)]
#[path = "stock_bm1396_native_tests.rs"]
mod tests;
