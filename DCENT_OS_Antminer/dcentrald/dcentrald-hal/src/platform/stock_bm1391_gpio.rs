//! Exact held-kernel PS GPIO907: base906, controller offset1, bank0/MIO1.
//! Source low/on and high/off is independent of the FPGA IIC portal. A high
//! pin readback is not a voltage measurement at the PSU or hashboard rail.
use super::*;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

const GPIO_PHYSICAL: libc::off64_t = 0xe000_a000;
const GPIO_NODE: &str = "amba@0/ps7-gpio@e000a000";

pub(super) trait Pin: Send + Sync {
    fn high(&self) -> Result<(), String>;
    fn low(&self) -> Result<(), String>;
    fn observed_high(&self) -> Result<bool, String>;
}

struct SysfsPin {
    direction: File,
    value: File,
    active_low: File,
    preload: usize,
    _devmem: File,
}
// SAFETY: the mapping is retained, fixed and aligned; compound writes and
// sysfs operations require PowerLine's gate. Drop unmaps after the last owner.
unsafe impl Send for SysfsPin {}
unsafe impl Sync for SysfsPin {}

fn read(file: &File, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![0; limit + 1];
    let count = file.read_at(&mut bytes, 0).map_err(|e| e.to_string())?;
    if count > limit {
        return Err("BM1391 GPIO property exceeds its bound".into());
    }
    bytes.truncate(count);
    Ok(bytes)
}
fn write(file: &File, bytes: &[u8]) -> Result<(), String> {
    let count = file.write_at(bytes, 0).map_err(|e| e.to_string())?;
    if count != bytes.len() {
        return Err("BM1391 GPIO short sysfs write".into());
    }
    Ok(())
}
fn open(path: &Path, writable: bool) -> Result<File, String> {
    open_checked(path, true, writable)
}
fn open_checked(path: &Path, readable: bool, writable: bool) -> Result<File, String> {
    let file = open_descriptor(path, readable, writable)?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    if !info.is_file() || info.uid() != 0 || info.mode() & 0o022 != 0 {
        return Err("BM1391 GPIO unsafe property ownership/type/mode".into());
    }
    Ok(file)
}
fn open_descriptor(path: &Path, readable: bool, writable: bool) -> Result<File, String> {
    OpenOptions::new()
        .read(readable)
        .write(writable)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("BM1391 GPIO {}: {e}", path.display()))
}
fn property(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    read(&open(path, false)?, limit)
}

fn validate_controller(sysfs: &Path, tree: &Path) -> Result<PathBuf, String> {
    let node = tree
        .join(GPIO_NODE)
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let chip = sysfs.join("gpiochip906");
    if property(&chip.join("base"), 16)? != b"906\n"
        || property(&chip.join("ngpio"), 16)? != b"118\n"
        || property(&chip.join("label"), 32)? != b"zynq_gpio\n"
        || chip
            .join("device/of_node")
            .canonicalize()
            .map_err(|e| e.to_string())?
            != node
        || property(&node.join("reg"), 8)? != [0xe0, 0, 0xa0, 0, 0, 0, 0x10, 0]
        || property(&node.join("compatible"), 64)? != b"xlnx,zynq-gpio-1.0\0"
    {
        return Err("BM1391 GPIO907 does not bind the held PS controller/base/line".into());
    }
    Ok(node)
}
impl SysfsPin {
    fn open(deadline: Instant) -> Result<Self, String> {
        let sysfs = Path::new("/sys/class/gpio");
        let node = validate_controller(sysfs, Path::new("/proc/device-tree"))?;
        let line = sysfs.join("gpio907");
        if !line.exists() {
            // Export only this already-bound exact line; never unexport it in
            // Drop, which would release pin custody before terminal handling.
            // kernfs checks attribute permission bits even for root. Export
            // is0200 and must be opened O_WRONLY; O_RDWR is rejected by4.6.
            let result = write(&open_checked(&sysfs.join("export"), false, true)?, b"907");
            if result.is_err() && !line.exists() {
                result?;
            }
        }
        while !line.join("value").exists() {
            if Instant::now() >= deadline {
                return Err("BM1391 GPIO export deadline elapsed".into());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        // Exported gpio907 has gpio_device.dev as parent, whereas gpiochip906
        // has the platform-device parent. Their inherited OF node is the join.
        if line
            .join("device/of_node")
            .canonicalize()
            .map_err(|e| e.to_string())?
            != node
        {
            return Err("BM1391 exported GPIO907 belongs to another controller".into());
        }
        let direction = open(&line.join("direction"), true)?;
        let value = open(&line.join("value"), true)?;
        let active_low = open(&line.join("active_low"), false)?;
        if read(&active_low, 8)? != b"0\n" {
            return Err("BM1391 GPIO907 logical inversion is not admitted".into());
        }
        let devmem = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_SYNC | libc::O_CLOEXEC)
            .open("/dev/mem")
            .map_err(|e| e.to_string())?;
        // SAFETY: exact device-tree-bound PS GPIO page, fixed length retained
        // until SysfsPin Drop. Only the pin1 masked high-data store is exposed.
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
            return Err("BM1391 GPIO907 inversion changed".into());
        }
        Ok(())
    }
}
impl Pin for SysfsPin {
    fn high(&self) -> Result<(), String> {
        // Old4.6 zynq_gpio_dir_out sets DIRM/OUTEN before data. Preload only
        // pin1's high output latch through masked DATA_LSW before asking that
        // driver to enable output. No RMW of other pins or direction registers.
        // This is ordered software control, not a measured glitch-free waveform.
        unsafe {
            std::ptr::write_volatile(self.preload as *mut u32, 0xfffd_0002);
        }
        std::sync::atomic::fence(Ordering::SeqCst);
        // DATA_0 reads the output latch; DATA_RO_0 separately reads the pin.
        // Check the high latch before enabling direction/output.
        let data = unsafe { std::ptr::read_volatile((self.preload + 0x40) as *const u32) };
        if data & 2 == 0 {
            return Err("BM1391 GPIO907 high preload latch readback failed".into());
        }
        self.uninverted()?;
        write(&self.direction, b"high")?;
        if read(&self.direction, 8)? != b"out\n" {
            return Err("BM1391 GPIO907 did not enter output mode".into());
        }
        Ok(())
    }
    fn low(&self) -> Result<(), String> {
        self.uninverted()?;
        if read(&self.direction, 8)? != b"out\n" {
            return Err("BM1391 GPIO907 output custody changed".into());
        }
        write(&self.value, b"0")
    }
    fn observed_high(&self) -> Result<bool, String> {
        self.uninverted()?;
        match read(&self.value, 8)?.as_slice() {
            b"0\n" => Ok(false),
            b"1\n" => Ok(true),
            _ => Err("BM1391 GPIO907 invalid pin readback".into()),
        }
    }
}
impl Drop for SysfsPin {
    fn drop(&mut self) {
        // SAFETY: the exact uniquely owned mapping and its original length.
        unsafe {
            libc::munmap(self.preload as *mut libc::c_void, 4096);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PowerLineOffObservation {
    pub pin_high: bool,
}

/// Source parking retains its GPIO and mapping owners but exposes no work,
/// PIC, voltage or enable operation. It also permits an empty board inventory.
pub struct ParkedSourceLine {
    _line: Arc<PowerLine<NativeMmio>>,
    observed: PowerLineOffObservation,
    quiet: QuietFanSetting,
}
impl ParkedSourceLine {
    pub fn observation(&self) -> PowerLineOffObservation {
        self.observed
    }
    pub fn quiet_fans(&self) -> QuietFanSetting {
        self.quiet
    }
}

/// Exact current-boot native source-high parking, including images whose
/// mining is disabled. This grants no authority to start mining afterwards;
/// the later daemon must acquire its own mapping and repeat native admission.
pub async fn park_source_line(model: Model, deadline: Instant) -> Result<ParkedSourceLine, String> {
    let owner = Transport::new_parked(NativeMmio::open(model).await?)?;
    let task_owner = owner.clone();
    tokio::task::spawn_blocking(move || {
        task_owner.registers.validate_owner()?;
        if Instant::now() >= deadline {
            return Err("BM1391 source park expired".into());
        }
        task_owner.power_line_claimed.store(true, Ordering::SeqCst);
        let line = Arc::new(PowerLine {
            owner: task_owner,
            pin: Box::new(SysfsPin::open(deadline)?),
            gate: Mutex::new(()),
        });
        let (observed, quiet) = line.park_with_quiet_fans(deadline)?;
        Ok(ParkedSourceLine {
            _line: line,
            observed,
            quiet,
        })
    })
    .await
    .map_err(|error| format!("BM1391 source park worker: {error}"))?
}

/// One retained source power line per native transport. The source-level high
/// cut works independently of ASIC/management locks and an unresolved IIC byte.
pub struct PowerLine<R: Registers> {
    owner: Arc<Transport<R>>,
    pin: Box<dyn Pin>,
    gate: Mutex<()>,
}
impl PowerLine<NativeMmio> {
    pub async fn open(
        owner: Arc<Transport<NativeMmio>>,
        deadline: Instant,
    ) -> Result<Arc<Self>, String> {
        owner.active(deadline)?;
        owner
            .power_line_claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "BM1391 power line already has an owner".to_string())?;
        let mut cancellation = AsyncCancellation::new(owner.clone());
        let task_owner = owner.clone();
        let result = tokio::task::spawn_blocking(move || {
            task_owner.active(deadline)?;
            match &task_owner.registers.backing {
                super::MmioBacking::Physical { lease, .. } => lease
                    .validate_current_process()
                    .map_err(|e| e.to_string())?,
                #[cfg(feature = "sim-hal")]
                super::MmioBacking::Simulated(_) => {
                    return Err("simulated BM1391 owner cannot open a physical GPIO".to_string());
                }
            }
            let pin = SysfsPin::open(deadline)?;
            let line = Arc::new(Self {
                owner: task_owner.clone(),
                pin: Box::new(pin),
                gate: Mutex::new(()),
            });
            line.initial_high(deadline)?;
            Ok::<_, String>(line)
        })
        .await
        .map_err(|e| format!("BM1391 GPIO owner worker: {e}"))?;
        if result.is_err() {
            owner.latch_terminal();
        }
        cancellation.complete();
        result
    }
}
impl<R: Registers> PowerLine<R> {
    #[cfg(feature = "sim-hal")]
    pub(super) fn from_simulated_pin(
        owner: Arc<Transport<R>>,
        pin: Box<dyn Pin>,
        deadline: Instant,
    ) -> Result<Arc<Self>, String> {
        let line = Arc::new(Self {
            owner,
            pin,
            gate: Mutex::new(()),
        });
        // The real initial-high transaction and readback still own admission.
        line.initial_high(deadline)?;
        Ok(line)
    }

    fn park_with_quiet_fans(
        &self,
        deadline: Instant,
    ) -> Result<(PowerLineOffObservation, QuietFanSetting), String> {
        // The same retained worker first observes the independent source cut.
        // Quiet PWM has its own source-proven register and permits terminal
        // owners; no PIC, work or fan-population admission is constructed.
        let observed = self.terminal_high(deadline)?;
        let quiet = self.owner.quiet_fans_locked(deadline)?;
        Ok((observed, quiet))
    }
    #[cfg(test)]
    pub(super) fn from_test_pin(owner: Arc<Transport<R>>, pin: Box<dyn Pin>) -> Arc<Self> {
        Arc::new(Self {
            owner,
            pin,
            gate: Mutex::new(()),
        })
    }
    pub(super) fn same_owner(&self, owner: &Arc<Transport<R>>) -> bool {
        Arc::ptr_eq(&self.owner, owner)
    }
    fn check_process(&self) -> Result<(), String> {
        self.owner.registers.validate_owner()
    }
    fn high_locked(&self, deadline: Instant) -> Result<PowerLineOffObservation, String> {
        self.check_process()?;
        if Instant::now() >= deadline {
            return Err("BM1391 GPIO cut deadline elapsed".into());
        }
        self.pin.high()?;
        if !self.pin.observed_high()? {
            return Err("BM1391 GPIO high cut readback failed".into());
        }
        if Instant::now() >= deadline {
            return Err("BM1391 GPIO cut completed late".into());
        }
        Ok(PowerLineOffObservation { pin_high: true })
    }
    fn initial_high(&self, deadline: Instant) -> Result<(), String> {
        let _gate = Transport::<R>::lock_lane_until(&self.gate, deadline)?;
        self.high_locked(deadline)?;
        self.owner.active(deadline)
    }
    /// Source low/on; full runtime must arm its watchdog and establish cooling
    /// and startup admission before calling. This grants no PIC voltage command.
    pub fn enable_source_line(&self, deadline: Instant) -> Result<(), String> {
        let _gate = Transport::<R>::lock_lane_until(&self.gate, deadline)?;
        let result = (|| {
            self.check_process()?;
            self.owner.active(deadline)?;
            self.pin.low()?;
            if self.pin.observed_high()? {
                return Err("BM1391 GPIO low/on readback failed".into());
            }
            self.owner.active(deadline)
        })();
        if result.is_err() {
            self.owner.latch_terminal();
            let cut = self.high_locked(deadline);
            return Err(format!(
                "{}; subsequent high cut: {cut:?}",
                result.unwrap_err()
            ));
        }
        result
    }
    pub fn terminal_high(&self, deadline: Instant) -> Result<PowerLineOffObservation, String> {
        self.owner.latch_terminal();
        let _gate = Transport::<R>::lock_lane_until(&self.gate, deadline)?;
        self.high_locked(deadline)
    }
}
impl<R: Registers> Drop for PowerLine<R> {
    fn drop(&mut self) {
        self.owner.latch_terminal();
        // Final Arc drop cannot overlap a borrowed pin operation. Best effort
        // high is additional cleanup; only explicit observed closeout is proof.
        if self.check_process().is_ok() {
            let _ = self.pin.high();
        }
    }
}

#[cfg(test)]
#[path = "stock_bm1391_gpio_tests.rs"]
mod tests;
