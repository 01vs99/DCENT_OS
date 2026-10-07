//! Exact R06 source GPIO907 high/off, bound to held kernel PS MIO1.
//! Kernel/OF and legacy high-preload evidence is shared by exact binary hash;
//! source command identity and dual PWM outputs are independently R06-bound.
use super::*;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const GPIO_NODE: &str = "amba@0/ps7-gpio@e000a000";
const GPIO_PHYSICAL: libc::off64_t = 0xe000_a000;
const GPIO_REG_PROPERTY: [u8; 8] = [0xe0, 0, 0xa0, 0, 0, 0, 0x10, 0];

pub(super) trait Pin: Send + Sync {
    fn high(&self) -> Result<(), String>;
    fn observed_high(&self) -> Result<bool, String>;
    fn low(&self) -> Result<(), String> {
        Err("BM1396 source pin does not implement admitted low".into())
    }
}

#[path = "stock_bm1396_source.rs"]
mod source;
pub use source::SourceStartObservation;

fn read(file: &File, maximum: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0; maximum + 1];
    let count = file.read_at(&mut bytes, 0).map_err(|e| e.to_string())?;
    if count > maximum {
        return Err("BM1396 GPIO property exceeds bound".into());
    }
    bytes.truncate(count);
    Ok(bytes)
}
fn write(file: &File, bytes: &[u8]) -> Result<(), String> {
    if file.write_at(bytes, 0).map_err(|e| e.to_string())? != bytes.len() {
        return Err("BM1396 GPIO short descriptor write".into());
    }
    Ok(())
}
fn open(path: &Path, readable: bool, writable: bool) -> Result<File, String> {
    open_owned(path, readable, writable, 0)
}
fn open_owned(path: &Path, readable: bool, writable: bool, uid: u32) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(readable)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("BM1396 GPIO {}: {e}", path.display()))?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    if !info.is_file() || info.uid() != uid || info.mode() & 0o022 != 0 {
        return Err("BM1396 GPIO unsafe property owner/type/mode".into());
    }
    Ok(file)
}
fn property(path: &Path, maximum: usize, uid: u32) -> Result<Vec<u8>, String> {
    read(&open_owned(path, true, false, uid)?, maximum)
}

fn validate_controller(sysfs: &Path, tree: &Path, uid: u32) -> Result<PathBuf, String> {
    // Exact held DTB has identity translation from this PS bus to root. Reg
    // alone is not a physical address if a parent changes its ranges/cell shape.
    for relative in [
        "#address-cells",
        "#size-cells",
        "amba@0/#address-cells",
        "amba@0/#size-cells",
    ] {
        if property(&tree.join(relative), 4, uid)? != 1u32.to_be_bytes() {
            return Err("BM1396 GPIO bus cell shape differs from held DTB".into());
        }
    }
    if !property(&tree.join("amba@0/ranges"), 0, uid)?.is_empty() {
        return Err("BM1396 GPIO bus must retain identity address translation".into());
    }
    let node = tree
        .join(GPIO_NODE)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let chip = sysfs.join("gpiochip906");
    if property(&chip.join("base"), 16, uid)? != b"906\n"
        || property(&chip.join("ngpio"), 16, uid)? != b"118\n"
        || property(&chip.join("label"), 32, uid)? != b"zynq_gpio\n"
        || chip
            .join("device/of_node")
            .canonicalize()
            .map_err(|e| e.to_string())?
            != node
        || property(&node.join("reg"), 8, uid)? != GPIO_REG_PROPERTY
        || property(&node.join("compatible"), 64, uid)? != b"xlnx,zynq-gpio-1.0\0"
    {
        return Err("BM1396 GPIO907 controller/base/offset differs from held PS MIO1".into());
    }
    Ok(node)
}

fn validate_line(line: &Path, node: &Path) -> Result<(), String> {
    if line
        .join("device/of_node")
        .canonicalize()
        .map_err(|e| e.to_string())?
        != node
    {
        return Err("BM1396 exported source line belongs to a different controller".into());
    }
    Ok(())
}

struct SysfsPin {
    direction: File,
    value: File,
    active_low: File,
    preload: usize,
    _devmem: File,
}
// SAFETY: retained page mapping; only bounded volatile accesses are exposed,
// and the single PowerLine gate serializes every compound pin operation.
unsafe impl Send for SysfsPin {}
// SAFETY: no Rust references to mapped device memory exist; shared access is
// checked and serialized by the same retained PowerLine gate.
unsafe impl Sync for SysfsPin {}

impl SysfsPin {
    fn open(deadline: Instant) -> Result<Self, String> {
        let sysfs = Path::new("/sys/class/gpio");
        let node = validate_controller(sysfs, Path::new("/proc/device-tree"), 0)?;
        if Instant::now() >= deadline {
            return Err("BM1396 GPIO binding exceeded deadline".into());
        }
        let line = sysfs.join("gpio907");
        if !line.exists() {
            // Exact held kernfs export mode0200 requires O_WRONLY even for root.
            let exported = write(&open(&sysfs.join("export"), false, true)?, b"907");
            if exported.is_err() && !line.exists() {
                exported?;
            }
        }
        while !line.join("value").exists() {
            if Instant::now() >= deadline {
                return Err("BM1396 GPIO export deadline elapsed".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        validate_line(&line, &node)?;
        let direction = open(&line.join("direction"), true, true)?;
        let value = open(&line.join("value"), true, true)?;
        let active_low = open(&line.join("active_low"), true, false)?;
        if read(&active_low, 8)? != b"0\n" {
            return Err("BM1396 inverted source line is not admitted".into());
        }
        let devmem = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_SYNC | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open("/dev/mem")
            .map_err(|e| e.to_string())?;
        // SAFETY: exact OF-bound fixed PS GPIO page, retained until Drop. mmap64
        // preserves physical e000a000 on 32-bit ARM instead of signed off_t wrap.
        let preload = unsafe {
            libc::mmap64(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                devmem.as_raw_fd(),
                GPIO_PHYSICAL,
            )
        };
        if preload == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self {
            direction,
            value,
            active_low,
            preload: preload as usize,
            _devmem: devmem,
        })
    }
    fn uninverted(&self) -> Result<(), String> {
        if read(&self.active_low, 8)? != b"0\n" {
            return Err("BM1396 source inversion changed".into());
        }
        Ok(())
    }
}
impl Pin for SysfsPin {
    fn low(&self) -> Result<(), String> {
        self.uninverted()?;
        if read(&self.direction, 8)? != b"out\n" {
            return Err("BM1396 source low requires retained output mode".into());
        }
        write(&self.value, b"0")
    }
    fn high(&self) -> Result<(), String> {
        self.uninverted()?;
        // SAFETY: mask touches only PS bank0 pin1's data latch. Old4.6 enables
        // DIRM/OUTEN before writing its value, so preload high before that call.
        unsafe {
            std::ptr::write_volatile(self.preload as *mut u32, 0xfffd_0002);
        }
        std::sync::atomic::fence(Ordering::SeqCst);
        #[cfg(target_arch = "arm")]
        // SAFETY: full-system ARMv7 barrier drains the pin-latch write before
        // invoking the kernel's separate direction/output-enable transaction.
        unsafe {
            std::arch::asm!("dsb sy", options(nostack, preserves_flags));
        }
        // SAFETY: aligned DATA0 word in the same checked retained GPIO page.
        let latch = unsafe { std::ptr::read_volatile((self.preload + 0x40) as *const u32) };
        if latch & 2 == 0 {
            return Err("BM1396 source high preload was not observed".into());
        }
        write(&self.direction, b"high")?;
        if read(&self.direction, 8)? != b"out\n" {
            return Err("BM1396 source did not enter output mode".into());
        }
        // Explicit source value1 is checked too, rather than trusting a void
        // shell helper. Existing direction is never assumed from mere export.
        write(&self.value, b"1")?;
        Ok(())
    }
    fn observed_high(&self) -> Result<bool, String> {
        self.uninverted()?;
        match read(&self.value, 8)?.as_slice() {
            b"1\n" => Ok(true),
            b"0\n" => Ok(false),
            _ => Err("BM1396 malformed source pin observation".into()),
        }
    }
}
impl Drop for SysfsPin {
    fn drop(&mut self) {
        // SAFETY: matching uniquely retained page mapping; no borrowed pin
        // operation remains when its PowerLine's final reference is dropped.
        unsafe {
            libc::munmap(self.preload as *mut libc::c_void, 4096);
        }
    }
}

#[derive(Debug, Clone)]
pub struct PowerLineOffObservation {
    pub pin_high: bool,
    identity: Arc<()>,
    attempted_at: Instant,
    observed_at: Instant,
}
impl PowerLineOffObservation {
    pub fn attempted_at(&self) -> Instant {
        self.attempted_at
    }
    pub fn observed_at(&self) -> Instant {
        self.observed_at
    }
    pub(super) fn same_owner<H: Hardware>(&self, owner: &Transport<H>) -> bool {
        Arc::ptr_eq(&self.identity, &owner.identity)
    }
}

pub struct PowerLine<H: Hardware> {
    owner: Arc<Transport<H>>,
    pin: Box<dyn Pin>,
    gate: Mutex<()>,
    initial_off: Mutex<Option<PowerLineOffObservation>>,
    source_start: Mutex<Option<SourceStartObservation>>,
}
impl PowerLine<NativeMmio> {
    /// Retains the pin and independently commands/observes initial source high
    /// inside the counted worker before returning the handle. Starting source
    /// low requires this same handle's separate retained startup admission.
    pub async fn open(
        owner: Arc<Transport<NativeMmio>>,
        deadline: Instant,
    ) -> Result<Arc<Self>, String> {
        owner.check(deadline, false)?;
        owner
            .power_line_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BM1396 source power line already claimed")?;
        owner
            .worker(deadline, true, move |owner| {
                let pin = SysfsPin::open(deadline)?;
                let line = Arc::new(Self {
                    owner: owner.clone(),
                    pin: Box::new(pin),
                    gate: Mutex::new(()),
                    initial_off: Mutex::new(None),
                    source_start: Mutex::new(None),
                });
                line.high_locked(deadline)?;
                owner.check(deadline, false)?;
                Ok(line)
            })
            .await
    }
}
impl<H: Hardware> PowerLine<H> {
    pub(super) fn same_owner(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }
    fn high_locked(&self, deadline: Instant) -> Result<PowerLineOffObservation, String> {
        let _gate = self.owner.lock(&self.gate, deadline, true)?;
        self.owner.check(deadline, true)?;
        // Issued here by the actual cut operation; no caller-provided timestamp.
        let attempted_at = Instant::now();
        self.pin.high()?;
        if !self.pin.observed_high()? {
            return Err("BM1396 source high was not observed".into());
        }
        self.owner.check(deadline, true)?;
        let observation = PowerLineOffObservation {
            pin_high: true,
            identity: Arc::clone(&self.owner.identity),
            attempted_at,
            observed_at: Instant::now(),
        };
        self.initial_off
            .lock()
            .map_err(|_| "BM1396 source initial-off custody poisoned")?
            .get_or_insert_with(|| observation.clone());
        Ok(observation)
    }

    /// Async terminal receipt comes from the retained counted cut worker. It
    /// does not acquire ASIC, management or fan transaction locks.
    pub async fn terminal_high(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<PowerLineOffObservation, String> {
        self.owner.begin_terminal();
        let line = Arc::clone(self);
        self.owner
            .worker(deadline, true, move |_| line.high_locked(deadline))
            .await
    }

    /// Bounded synchronous crash/panic fallback: caller closes watchdog feed
    /// first. This returns no disarm/cut receipt and performs no management I/O.
    pub fn emergency_high(&self, deadline: Instant) -> Result<(), String> {
        self.owner.begin_terminal();
        self.high_locked(deadline).map(|_| ())
    }

    fn park_with_quiet_fans(
        &self,
        deadline: Instant,
    ) -> Result<(PowerLineOffObservation, QuietFanSetting), String> {
        self.owner.begin_terminal();
        let high = self.high_locked(deadline)?;
        let quiet = self.owner.quiet_fans_locked(deadline)?;
        if !high.same_owner(&self.owner) || !quiet.same_owner(&self.owner) {
            return Err("BM1396 source/fan observations belong to different owners".into());
        }
        Ok((high, quiet))
    }

    #[cfg(test)]
    pub(super) fn source_test_high_with_age(&self, age: Duration) {
        self.high_locked(Instant::now() + Duration::from_secs(1))
            .unwrap();
        // Explicit elapsed-time injection only. The test still executes the
        // actual pin operation and checks its high observation first.
        let mut off = self.initial_off.lock().unwrap();
        let off = off.as_mut().unwrap();
        off.attempted_at -= age;
        off.observed_at -= age;
    }

    #[cfg(test)]
    pub(super) fn from_test_pin(owner: Arc<Transport<H>>, pin: Box<dyn Pin>) -> Arc<Self> {
        owner
            .power_line_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .unwrap();
        Arc::new(Self {
            owner,
            pin,
            gate: Mutex::new(()),
            initial_off: Mutex::new(None),
            source_start: Mutex::new(None),
        })
    }
}
impl<H: Hardware> Drop for PowerLine<H> {
    fn drop(&mut self) {
        self.owner.begin_terminal();
        // Last-reference drop is additional best effort, never a completed
        // teardown receipt. Pin custody is retained until this attempt finishes.
        if self.owner.hardware.validate_owner().is_ok() {
            let _ = self.pin.high();
        }
    }
}

/// Retains zero-population terminal-only hardware through publication. The
/// transport/pin are private; no work, PIC, voltage, enable or population token
/// can be extracted from this boot result.
pub struct ParkedSourceLine {
    _line: Arc<PowerLine<NativeMmio>>,
    observation: PowerLineOffObservation,
    quiet: QuietFanSetting,
}
impl ParkedSourceLine {
    pub fn observation(&self) -> PowerLineOffObservation {
        self.observation.clone()
    }
    pub fn quiet_fans(&self) -> QuietFanSetting {
        self.quiet.clone()
    }
}

pub async fn park_source_line(model: Model, deadline: Instant) -> Result<ParkedSourceLine, String> {
    let owner = Transport::parked(NativeMmio::open(model).await?)?;
    owner.power_line_claimed.store(true, Ordering::SeqCst);
    owner
        .worker(deadline, true, move |owner| {
            let pin = SysfsPin::open(deadline)?;
            let line = Arc::new(PowerLine {
                owner: owner.clone(),
                pin: Box::new(pin),
                gate: Mutex::new(()),
                initial_off: Mutex::new(None),
                source_start: Mutex::new(None),
            });
            let (observation, quiet) = line.park_with_quiet_fans(deadline)?;
            Ok(ParkedSourceLine {
                _line: line,
                observation,
                quiet,
            })
        })
        .await
}

#[cfg(test)]
#[path = "stock_bm1396_gpio_tests.rs"]
mod tests;

// No generic pin constructor leaves this crate. Only the concrete memory-only
// modeled rig reaches this factory, and it issues the real high observation.
#[cfg(feature = "sim-hal")]
pub(super) async fn open_simulated_source_line(
    owner: Arc<Transport<super::simulation::WireSimulator>>,
    hardware: Arc<super::simulation::WireSimulator>,
    deadline: Instant,
) -> Result<Arc<PowerLine<super::simulation::WireSimulator>>, String> {
    if !Arc::ptr_eq(&owner.hardware, &hardware) {
        return Err("modeled source pin belongs to a different transport".into());
    }
    owner.check(deadline, false)?;
    owner
        .power_line_claimed
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .map_err(|_| "modeled source line already claimed")?;
    owner
        .worker(deadline, true, move |owner| {
            let line = Arc::new(PowerLine {
                owner: owner.clone(),
                pin: Box::new(super::simulation::SimulatedPin(hardware)),
                gate: Mutex::new(()),
                initial_off: Mutex::new(None),
                source_start: Mutex::new(None),
            });
            line.high_locked(deadline)?;
            owner.check(deadline, false)?;
            Ok(line)
        })
        .await
}
