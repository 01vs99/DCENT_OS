//! am2 PSU GPIO gate helper.
//!
//! S19j Pro `a lab unit` Phase 13/14 RE showed the APW121215a PSU bus is GPIO-gated:
//! bosminer asserts the `PWR_CONTROL` line before any I2C traffic reaches slave
//! `0x10`. Without that gate, every PSU opcode EIOs even when the frame bytes
//! and retry strategy are otherwise correct.
//!
//! Prefer the explicit `pwr_control_gpio` from the am2 production config.
//! Device-tree labels are useful when present, but `a lab unit` bring-up showed
//! stale or absent labels can point at the wrong line; fail closed if the
//! label cannot be resolved.

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;

use crate::{HalError, Result};

const DEFAULT_LABEL: &str = "PWR_CONTROL";
const GPIO_SETTLE_DELAY_MS: u64 = 50;

fn env_flag(name: &str) -> bool {
    dcentrald_common::lab_env::var(name)
        .ok()
        .map(|v| {
            matches!(
                v.trim(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

/// `(dt gpio-line-names path, Linux global GPIO base)` pairs for the am2 board.
///
/// Bases were live-probed on S19j Pro `a lab unit` during Phase 14 exploration:
/// - `gpio@41220000` -> 895..896
/// - `gpio@41210000` -> 897..901
/// - `gpio@41200000` -> 902..905
/// - `zynq_gpio` -> 906..
const DT_GPIO_LABEL_SOURCES: &[(&str, u32)] = &[
    (
        "/sys/firmware/devicetree/base/amba/gpio@41220000/gpio-line-names",
        895,
    ),
    (
        "/sys/firmware/devicetree/base/amba/gpio@41210000/gpio-line-names",
        897,
    ),
    (
        "/sys/firmware/devicetree/base/amba/gpio@41200000/gpio-line-names",
        902,
    ),
    (
        "/sys/firmware/devicetree/base/gpio@e000a000/gpio-line-names",
        906,
    ),
    (
        "/sys/firmware/devicetree/base/amba_ps/gpio@e000a000/gpio-line-names",
        906,
    ),
];

/// Scoped `PWR_CONTROL` assertion guard.
///
/// Records the line's prior sysfs direction/value and restores it on `Drop`.
pub struct PsuGpioGate {
    io: Arc<dyn GpioIo>,
    gpio: u32,
    /// Polarity is part of the admitted hardware session. Re-reading mutable
    /// process environment during teardown could invert the electrical
    /// meaning of a matching GPIO readback and mint false safe-off evidence.
    active_low: bool,
    off_level: bool,
    restore_direction: String,
    restore_value: Option<bool>,
    exported_by_us: bool,
    asserted: bool,
    /// Once terminal safe-off is requested, the inherited state must never be
    /// restored—even if polarity resolution, write, or readback fails.
    terminal_restore_retired: bool,
    /// OFF level to retry from Drop after a failed terminal transition. `None`
    /// after successful verified closeout (no late hardware write remains).
    terminal_off_retry: Option<bool>,
}

/// Proof that terminal teardown drove `PWR_CONTROL` to its electrically OFF
/// level and read the same level back before retiring the scoped gate.
///
/// This differs deliberately from [`PsuGpioGate::deassert`], which restores
/// the line's pre-assertion state and therefore is not necessarily a safe-off
/// operation when firmware inherited an already-energized rail.
#[derive(Debug)]
pub struct PsuGpioSafeOffReceipt {
    gpio: u32,
    off_level: bool,
}

impl PsuGpioSafeOffReceipt {
    pub fn gpio(&self) -> u32 {
        self.gpio
    }

    pub fn off_level(&self) -> bool {
        self.off_level
    }
}

/// Outcome of attempting to bring a GPIO line under sysfs control.
#[derive(Debug, Clone, Copy)]
enum ExportOutcome {
    /// A `/sys/class/gpio/gpioN/` directory was already present (either from a
    /// previous `PsuGpioGate` instance or from a boot-time init script).
    Existed,
    /// We exported it ourselves and should unexport on `Drop`.
    Created,
    /// Kernel-internal consumer holds the line (sysfs export returned EBUSY).
    /// Kernel-internal consumer holds the line (sysfs export returned EBUSY).
    /// This is not proof the line is asserted; callers must provide an
    /// explicit GPIO spec on AM2 production images so we can fail closed when
    /// sysfs cannot drive the gate.
    KernelClaimed,
}

/// Narrow, injectable boundary for the legacy sysfs GPIO ABI. Keeping this
/// interface at the electrical operations (rather than arbitrary filesystem
/// calls) makes lifecycle ordering and every fail-closed stage deterministic
/// under unit tests while production still uses the same byte-for-byte sysfs
/// writes.
trait GpioIo: Send + Sync {
    fn ensure_exported(&self, gpio: u32) -> Result<ExportOutcome>;
    fn read_direction(&self, gpio: u32) -> Result<String>;
    fn read_value(&self, gpio: u32) -> Result<bool>;
    fn write_direction(&self, gpio: u32, direction: &str) -> Result<()>;
    fn write_value(&self, gpio: u32, high: bool) -> Result<()>;
    fn unexport(&self, gpio: u32) -> Result<()>;
}

#[derive(Debug, Default)]
struct SysfsGpioIo;

impl GpioIo for SysfsGpioIo {
    fn ensure_exported(&self, gpio: u32) -> Result<ExportOutcome> {
        ensure_exported(gpio)
    }

    fn read_direction(&self, gpio: u32) -> Result<String> {
        read_trimmed(&direction_path(gpio))
    }

    fn read_value(&self, gpio: u32) -> Result<bool> {
        read_value(gpio)
    }

    fn write_direction(&self, gpio: u32, direction: &str) -> Result<()> {
        write_direction(gpio, direction)
    }

    fn write_value(&self, gpio: u32, high: bool) -> Result<()> {
        write_value(gpio, high)
    }

    fn unexport(&self, gpio: u32) -> Result<()> {
        fs::write("/sys/class/gpio/unexport", format!("{}", gpio))
            .map_err(|e| HalError::Gpio(format!("unexport GPIO {}: {}", gpio, e)))
    }
}

impl PsuGpioGate {
    /// Assert the am2 PSU hardware gate before any PSU I2C access.
    ///
    /// `spec` accepts:
    /// - `None` -> lookup `label:PWR_CONTROL`
    /// - `label:PWR_CONTROL`
    /// - `gpio:901`
    /// - `901`
    pub fn assert(spec: Option<&str>) -> Result<Self> {
        Self::assert_with_io(spec, Arc::new(SysfsGpioIo))
    }

    fn assert_with_io(spec: Option<&str>, io: Arc<dyn GpioIo>) -> Result<Self> {
        let gpio = resolve_gpio(spec)?;
        // Resolve polarity before exporting or mutating the line, then retain
        // it immutably for the full RAII session and terminal closeout.
        let active_low = pwr_control_active_low(gpio)?;
        Self::assert_resolved_with_io(gpio, active_low, io)
    }

    fn assert_resolved_with_io(gpio: u32, active_low: bool, io: Arc<dyn GpioIo>) -> Result<Self> {
        let asserted_value = !active_low;
        let off_level = active_low;
        let outcome = io.ensure_exported(gpio)?;

        if matches!(outcome, ExportOutcome::KernelClaimed) {
            return Err(HalError::Gpio(format!(
                "PWR_CONTROL GPIO {} is kernel-claimed (EBUSY); cannot verify/assert PSU gate",
                gpio
            )));
        }

        let exported_by_us = matches!(outcome, ExportOutcome::Created);
        let restore_direction = io.read_direction(gpio)?;
        let restore_value = io.read_value(gpio).ok();

        // Establish RAII ownership before the first direction/value mutation.
        // From this point onward every `?` path either restores the inherited
        // pre-assert state (before an ON write) or is explicitly retired into
        // terminal-OFF retry ownership below.
        let mut gate = Self {
            io,
            gpio,
            active_low,
            off_level,
            restore_direction,
            restore_value,
            exported_by_us,
            asserted: true,
            terminal_restore_retired: false,
            terminal_off_retry: None,
        };

        // The sysfs GPIO ABI accepts `high`/`low` on the direction attribute,
        // setting output direction and the initial latch as one operation.
        // Establish electrical OFF before attempting ON so changing an input
        // to an output cannot expose an inherited ON latch even transiently.
        let off_direction = if off_level { "high" } else { "low" };
        if let Err(error) = gate.io.write_direction(gpio, off_direction) {
            let rollback = gate.force_safe_off_verified();
            return Err(HalError::Gpio(format!(
                "PWR_CONTROL gpio{} failed to establish terminal-OFF output before assert: {}; terminal OFF rollback={:?}",
                gpio, error, rollback
            )));
        }
        // The exact wiring recipe was resolved before export. Keep that
        // ON/OFF pair for this owner and every terminal retry; never infer
        // a sibling's GPIO907 polarity from a shared AM2 platform marker.
        if let Err(error) = gate.io.write_value(gpio, asserted_value) {
            let rollback = gate.force_safe_off_verified();
            return Err(HalError::Gpio(format!(
                "PWR_CONTROL gpio{} ON write failed (active_low={}): {}; terminal OFF rollback={:?}",
                gpio, active_low, error, rollback
            )));
        }
        let observed_value = gate.io.read_value(gpio).ok();
        // P1 (2026-06-13): verify the readback on the RESOLVED gpio, identical to
        // the polarity gate above (`gpio == AM2_PSU_ENABLE_GPIO`), NOT on the
        // literal spec string. `None`, `"PWR_CONTROL"`, `"label:PWR_CONTROL"`,
        // `"907"`, and `"gpio:907"` all resolve to the PSU-enable line (see
        // `resolve_gpio` + the P2 reconcile), and a silent assert-readback
        // mismatch on that line must fail closed regardless of how the operator
        // spelled the spec. The old `explicit_gpio907` string gate skipped the
        // check for the label/None forms.
        if gpio == crate::board_control::AM2_PSU_ENABLE_GPIO {
            match observed_value {
                Some(value) if value == asserted_value => {}
                Some(value) => {
                    let rollback = gate.force_safe_off_verified();
                    return Err(HalError::Gpio(format!(
                        "PWR_CONTROL gpio{} readback mismatch after assert: wrote {} \
                         (active_low={}), read {}; terminal OFF rollback={:?}",
                        gpio, asserted_value as u8, active_low, value as u8, rollback
                    )));
                }
                None => {
                    let rollback = gate.force_safe_off_verified();
                    return Err(HalError::Gpio(format!(
                        "PWR_CONTROL gpio{} readback unavailable after assert; terminal OFF rollback={:?}",
                        gpio, rollback
                    )));
                }
            }
        }

        tracing::info!(
            gpio,
            active_low,
            observed_asserted = ?observed_value,
            "PWR_CONTROL asserted before PSU init (sysfs readback recorded)"
        );

        Ok(gate)
    }

    pub fn gpio(&self) -> u32 {
        self.gpio
    }

    pub fn is_asserted(&self) -> bool {
        self.asserted
    }

    /// Test-only constructor: builds a guard for a fake line without touching
    /// `/sys`. `Drop`/`deassert` will fail their sysfs writes (swallowed by
    /// `Drop`), so don't rely on them in tests beyond "must not panic".
    #[cfg(test)]
    pub(crate) fn for_test(gpio: u32) -> Self {
        Self::for_test_with_active_low(gpio, false)
    }

    #[cfg(test)]
    fn for_test_with_active_low(gpio: u32, active_low: bool) -> Self {
        Self {
            io: Arc::new(SysfsGpioIo),
            gpio,
            active_low,
            off_level: active_low,
            restore_direction: "in".to_string(),
            restore_value: None,
            exported_by_us: false,
            asserted: true,
            terminal_restore_retired: false,
            terminal_off_retry: None,
        }
    }

    /// Restore the line to its pre-asserted state.
    pub fn deassert(&mut self) -> Result<()> {
        if self.terminal_restore_retired {
            return Err(HalError::Gpio(format!(
                "PWR_CONTROL gpio{} scoped restore was terminally retired",
                self.gpio
            )));
        }
        if !self.asserted {
            return Ok(());
        }

        match self.restore_direction.as_str() {
            "in" => self.io.write_direction(self.gpio, "in")?,
            "out" => {
                self.io.write_direction(self.gpio, "out")?;
                if let Some(prev) = self.restore_value {
                    self.io.write_value(self.gpio, prev)?;
                }
            }
            other => {
                tracing::warn!(
                    gpio = self.gpio,
                    direction = other,
                    "Unexpected GPIO direction while restoring PWR_CONTROL; falling back to stored value"
                );
                if let Some(prev) = self.restore_value {
                    self.io.write_direction(self.gpio, "out")?;
                    self.io.write_value(self.gpio, prev)?;
                } else {
                    self.io.write_direction(self.gpio, "in")?;
                }
            }
        }

        if self.exported_by_us {
            let _ = self.io.unexport(self.gpio);
        }

        self.asserted = false;
        tracing::info!(gpio = self.gpio, "PWR_CONTROL restored");
        Ok(())
    }

    /// Drive the rail gate to its terminal OFF level, verify readback, and
    /// retire this guard's later pre-assert-state restoration.
    ///
    /// On success, `Drop` becomes a no-op for the electrical state. Keeping
    /// the sysfs line exported and driven as an output is intentional: an
    /// unexport or direction restore would weaken the just-observed OFF state.
    pub fn force_safe_off_verified(&mut self) -> Result<PsuGpioSafeOffReceipt> {
        // Retire inherited-state restoration before the first fallible step.
        // A failed terminal attempt must never later restore an inherited ON
        // state and re-energize the rail during scope teardown.
        self.terminal_restore_retired = true;
        self.asserted = false;
        self.exported_by_us = false;

        let active_low = self.active_low;
        let off_level = self.off_level;
        self.terminal_off_retry = Some(off_level);

        self.io.write_direction(self.gpio, "out")?;
        self.io.write_value(self.gpio, off_level)?;
        let observed = self.io.read_value(self.gpio)?;
        if observed != off_level {
            return Err(HalError::Gpio(format!(
                "PWR_CONTROL gpio{} readback mismatch after terminal safe-off: wrote {} \
                 (active_low={}), read {}",
                self.gpio, off_level as u8, active_low, observed as u8
            )));
        }

        // Terminal safe-off supersedes the ordinary scoped-restore contract.
        // Marking the guard inactive prevents a later Drop from restoring an
        // inherited ON state after the software watchdog has been disarmed.
        self.restore_direction = "out".to_string();
        self.restore_value = Some(off_level);
        self.terminal_off_retry = None;

        tracing::info!(
            gpio = self.gpio,
            active_low,
            off_level,
            observed,
            "PWR_CONTROL terminal safe-off completed (readback verified; scoped restore retired)"
        );
        Ok(PsuGpioSafeOffReceipt {
            gpio: self.gpio,
            off_level,
        })
    }
}

impl Drop for PsuGpioGate {
    fn drop(&mut self) {
        if self.terminal_restore_retired {
            if let Some(off_level) = self.terminal_off_retry {
                let result = self
                    .io
                    .write_direction(self.gpio, "out")
                    .and_then(|()| self.io.write_value(self.gpio, off_level))
                    .and_then(|()| {
                        let observed = self.io.read_value(self.gpio)?;
                        if observed == off_level {
                            Ok(())
                        } else {
                            Err(HalError::Gpio(format!(
                                "PWR_CONTROL gpio{} terminal OFF retry readback mismatch: expected {}, read {}",
                                self.gpio, off_level as u8, observed as u8
                            )))
                        }
                    });
                match result {
                    Ok(()) => tracing::warn!(
                        gpio = self.gpio,
                        off_level,
                        "PWR_CONTROL terminal safe-off retry succeeded during Drop"
                    ),
                    Err(error) => tracing::error!(
                        gpio = self.gpio,
                        off_level,
                        error = %error,
                        "PWR_CONTROL terminal safe-off retry failed during Drop; inherited state remains retired"
                    ),
                }
            }
            return;
        }
        if let Err(e) = self.deassert() {
            tracing::warn!(gpio = self.gpio, error = %e, "Failed to restore PWR_CONTROL on drop");
        }
    }
}

fn pwr_control_active_low(gpio: u32) -> Result<bool> {
    let active_low = env_flag("DCENT_AM2_PWR_CONTROL_ACTIVE_LOW");
    if gpio != crate::board_control::AM2_PSU_ENABLE_GPIO {
        return Ok(active_low);
    }
    let lab_declared = dcentrald_common::lab_env::var_os("DCENT_AM2_PWR_CONTROL_ACTIVE_LOW").is_some()
        || dcentrald_common::lab_env::var_os("DCENT_AM2_PWR_CONTROL_ACTIVE_HIGH").is_some();
    dcentrald_common::runtime_hardware_recipe::resolve_power_control_polarity(
        dcentrald_common::runtime_hardware_recipe::gpio907_polarity(),
        lab_declared.then(|| (active_low, env_flag("DCENT_AM2_PWR_CONTROL_ACTIVE_HIGH"))),
    )
    .map(|polarity| polarity.active_low())
    .map_err(|message| HalError::Gpio(format!("PWR_CONTROL gpio{}: {}", gpio, message)))
}

fn resolve_gpio(spec: Option<&str>) -> Result<u32> {
    match parse_spec(spec)? {
        ParsedSpec::Gpio(gpio) => Ok(gpio),
        // P2 (2026-06-13): the canonical `PWR_CONTROL` label resolves to the
        // live-pinned am2 PSU-enable line, IDENTICAL to the teardown resolver
        // (`s19j_hybrid_mining::parse_gpio_number_spec`), so `assert` and
        // `force_pwr_control_low` can never drive different GPIOs for the same
        // spec. Previously this label went to DT `gpio-line-names`, which a unit
        // test pins to gpio901 for the 0x41210000 bank — a teardown/assert
        // divergence that could leave the rail energized. Only a NON-canonical
        // label still falls through to DT lookup (the `a lab unit` bring-up fallback).
        ParsedSpec::Label(label) if label.eq_ignore_ascii_case(DEFAULT_LABEL) => {
            Ok(crate::board_control::AM2_PSU_ENABLE_GPIO)
        }
        ParsedSpec::Label(label) => match find_gpio_by_dt_label(label)? {
            Some(gpio) => Ok(gpio),
            None => Err(HalError::Gpio(format!(
                "failed to resolve GPIO label '{}' from DT gpio-line-names",
                label
            ))),
        },
    }
}

enum ParsedSpec<'a> {
    Gpio(u32),
    Label(&'a str),
}

fn parse_spec(spec: Option<&str>) -> Result<ParsedSpec<'_>> {
    match spec.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(ParsedSpec::Label(DEFAULT_LABEL)),
        Some(raw) => {
            if let Some(rest) = raw.strip_prefix("gpio:") {
                let gpio = rest
                    .trim()
                    .parse::<u32>()
                    .map_err(|e| HalError::Gpio(format!("invalid gpio spec '{}': {}", raw, e)))?;
                return Ok(ParsedSpec::Gpio(gpio));
            }
            if let Some(rest) = raw.strip_prefix("label:") {
                let label = rest.trim();
                if label.is_empty() {
                    return Err(HalError::Gpio("empty GPIO label spec".into()));
                }
                return Ok(ParsedSpec::Label(label));
            }
            if raw.bytes().all(|b| b.is_ascii_digit()) {
                let gpio = raw
                    .parse::<u32>()
                    .map_err(|e| HalError::Gpio(format!("invalid gpio number '{}': {}", raw, e)))?;
                return Ok(ParsedSpec::Gpio(gpio));
            }
            Ok(ParsedSpec::Label(raw))
        }
    }
}

fn find_gpio_by_dt_label(label: &str) -> Result<Option<u32>> {
    for (path, base) in DT_GPIO_LABEL_SOURCES {
        let dt_path = Path::new(path);
        if !dt_path.exists() {
            continue;
        }
        let blob = fs::read(dt_path).map_err(|e| {
            HalError::Gpio(format!(
                "read DT gpio-line-names '{}': {}",
                dt_path.display(),
                e
            ))
        })?;
        if let Some(gpio) = gpio_from_dt_blob(&blob, *base, label) {
            tracing::info!(label, gpio, dt_path = %dt_path.display(), "Resolved GPIO label from DT");
            return Ok(Some(gpio));
        }
    }
    Ok(None)
}

fn gpio_from_dt_blob(blob: &[u8], base: u32, label: &str) -> Option<u32> {
    for (idx, raw_name) in blob.split(|b| *b == 0).enumerate() {
        if raw_name == label.as_bytes() {
            return Some(base + idx as u32);
        }
    }
    None
}

fn gpio_dir(gpio: u32) -> String {
    format!("/sys/class/gpio/gpio{}", gpio)
}

fn direction_path(gpio: u32) -> String {
    format!("{}/direction", gpio_dir(gpio))
}

fn value_path(gpio: u32) -> String {
    format!("{}/value", gpio_dir(gpio))
}

fn ensure_exported(gpio: u32) -> Result<ExportOutcome> {
    let dir = gpio_dir(gpio);
    if Path::new(&dir).exists() {
        return Ok(ExportOutcome::Existed);
    }

    match fs::write("/sys/class/gpio/export", format!("{}", gpio)) {
        Ok(()) => {
            sleep(Duration::from_millis(GPIO_SETTLE_DELAY_MS));
            if !Path::new(&dir).exists() {
                return Err(HalError::Gpio(format!(
                    "GPIO {} did not appear after export",
                    gpio
                )));
            }
            Ok(ExportOutcome::Created)
        }
        // EBUSY (errno 16): kernel consumer holds the line. See ExportOutcome::KernelClaimed.
        Err(e) if e.raw_os_error() == Some(16) => {
            tracing::warn!(
                gpio,
                "GPIO {} EBUSY on sysfs export — kernel already claims the line \
                 (no consumer label; likely Xilinx xps-gpio default hold)",
                gpio
            );
            Ok(ExportOutcome::KernelClaimed)
        }
        Err(e) => Err(HalError::Gpio(format!("export GPIO {}: {}", gpio, e))),
    }
}

fn read_trimmed(path: &str) -> Result<String> {
    Ok(fs::read_to_string(path)
        .map_err(|e| HalError::Gpio(format!("read {}: {}", path, e)))?
        .trim()
        .to_string())
}

fn read_value(gpio: u32) -> Result<bool> {
    Ok(read_trimmed(&value_path(gpio))? == "1")
}

fn write_direction(gpio: u32, dir: &str) -> Result<()> {
    fs::write(direction_path(gpio), dir)
        .map_err(|e| HalError::Gpio(format!("GPIO {} direction {}: {}", gpio, dir, e)))
}

fn write_value(gpio: u32, high: bool) -> Result<()> {
    fs::write(value_path(gpio), if high { "1" } else { "0" })
        .map_err(|e| HalError::Gpio(format!("GPIO {} value {}: {}", gpio, high as u8, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, VecDeque};
    use std::sync::Mutex;

    static POLARITY_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FakeOp {
        EnsureExported,
        ReadDirection,
        ReadValue,
        WriteDirection(String),
        WriteValue(bool),
        Unexport,
    }

    #[derive(Debug)]
    struct FakeGpioState {
        operations: Vec<FakeOp>,
        direction: String,
        value: bool,
        fail_calls: BTreeSet<usize>,
        read_overrides: VecDeque<bool>,
    }

    #[derive(Debug)]
    struct FakeGpioIo {
        state: Mutex<FakeGpioState>,
    }

    impl FakeGpioIo {
        fn inherited(direction: &str, value: bool) -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new(FakeGpioState {
                    operations: Vec::new(),
                    direction: direction.to_string(),
                    value,
                    fail_calls: BTreeSet::new(),
                    read_overrides: VecDeque::new(),
                }),
            })
        }

        fn fail_call(&self, call_index: usize) {
            self.state.lock().unwrap().fail_calls.insert(call_index);
        }

        fn override_next_read(&self, value: bool) {
            self.state.lock().unwrap().read_overrides.push_back(value);
        }

        fn snapshot(&self) -> (Vec<FakeOp>, String, bool) {
            let state = self.state.lock().unwrap();
            (
                state.operations.clone(),
                state.direction.clone(),
                state.value,
            )
        }

        fn record(state: &mut FakeGpioState, operation: FakeOp) -> Result<()> {
            let call_index = state.operations.len();
            state.operations.push(operation);
            if state.fail_calls.remove(&call_index) {
                return Err(HalError::Gpio(format!(
                    "injected GPIO failure at call {call_index}"
                )));
            }
            Ok(())
        }
    }

    impl GpioIo for FakeGpioIo {
        fn ensure_exported(&self, _gpio: u32) -> Result<ExportOutcome> {
            let mut state = self.state.lock().unwrap();
            Self::record(&mut state, FakeOp::EnsureExported)?;
            Ok(ExportOutcome::Existed)
        }

        fn read_direction(&self, _gpio: u32) -> Result<String> {
            let mut state = self.state.lock().unwrap();
            Self::record(&mut state, FakeOp::ReadDirection)?;
            Ok(state.direction.clone())
        }

        fn read_value(&self, _gpio: u32) -> Result<bool> {
            let mut state = self.state.lock().unwrap();
            Self::record(&mut state, FakeOp::ReadValue)?;
            Ok(state.read_overrides.pop_front().unwrap_or(state.value))
        }

        fn write_direction(&self, _gpio: u32, direction: &str) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            Self::record(&mut state, FakeOp::WriteDirection(direction.to_string()))?;
            state.direction = if matches!(direction, "high" | "low") {
                "out".to_string()
            } else {
                direction.to_string()
            };
            if direction == "high" {
                state.value = true;
            } else if direction == "low" {
                state.value = false;
            }
            Ok(())
        }

        fn write_value(&self, _gpio: u32, high: bool) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            Self::record(&mut state, FakeOp::WriteValue(high))?;
            state.value = high;
            Ok(())
        }

        fn unexport(&self, _gpio: u32) -> Result<()> {
            let mut state = self.state.lock().unwrap();
            Self::record(&mut state, FakeOp::Unexport)
        }
    }

    #[test]
    fn parse_numeric_gpio_specs() {
        match parse_spec(Some("901")).unwrap() {
            ParsedSpec::Gpio(gpio) => assert_eq!(gpio, 901),
            _ => panic!("expected numeric gpio spec"),
        }
        match parse_spec(Some("gpio:907")).unwrap() {
            ParsedSpec::Gpio(gpio) => assert_eq!(gpio, 907),
            _ => panic!("expected prefixed numeric gpio spec"),
        }
    }

    #[test]
    fn parse_label_specs() {
        match parse_spec(None).unwrap() {
            ParsedSpec::Label(label) => assert_eq!(label, "PWR_CONTROL"),
            _ => panic!("expected default label spec"),
        }
        match parse_spec(Some("label:PWR_CONTROL")).unwrap() {
            ParsedSpec::Label(label) => assert_eq!(label, "PWR_CONTROL"),
            _ => panic!("expected label spec"),
        }
    }

    #[test]
    fn resolve_label_from_dt_blob() {
        let blob = b"HB0_RESET\0HB1_RESET\0HB2_RESET\0HB3_RESET\0PWR_CONTROL\0";
        assert_eq!(gpio_from_dt_blob(blob, 897, "PWR_CONTROL"), Some(901));
        assert_eq!(gpio_from_dt_blob(blob, 897, "HB1_RESET"), Some(898));
        assert_eq!(gpio_from_dt_blob(blob, 897, "missing"), None);
    }

    #[test]
    fn terminal_safe_off_receipt_reports_verified_line_and_level() {
        let receipt = PsuGpioSafeOffReceipt {
            gpio: 907,
            off_level: true,
        };
        assert_eq!(receipt.gpio(), 907);
        assert!(receipt.off_level());
    }

    #[test]
    fn injected_gpio_lifecycle_establishes_off_before_on_and_never_restores_inherited_on() {
        let fake = FakeGpioIo::inherited("out", true);
        let mut gate = PsuGpioGate::assert_resolved_with_io(907, false, fake.clone()).unwrap();
        assert!(gate.is_asserted());

        let receipt = gate.force_safe_off_verified().unwrap();
        assert_eq!(receipt.gpio(), 907);
        assert!(!receipt.off_level());
        drop(gate);

        let (operations, direction, value) = fake.snapshot();
        assert_eq!(direction, "out");
        assert!(!value);
        assert_eq!(
            operations,
            vec![
                FakeOp::EnsureExported,
                FakeOp::ReadDirection,
                FakeOp::ReadValue,
                FakeOp::WriteDirection("low".to_string()),
                FakeOp::WriteValue(true),
                FakeOp::ReadValue,
                FakeOp::WriteDirection("out".to_string()),
                FakeOp::WriteValue(false),
                FakeOp::ReadValue,
            ]
        );
    }

    #[test]
    fn injected_assertion_failures_are_bounded_and_post_mutation_failures_end_off() {

        for failure_call in [0usize, 1, 3, 4, 5] {
            let fake = FakeGpioIo::inherited("out", true);
            fake.fail_call(failure_call);
            let result = PsuGpioGate::assert_resolved_with_io(907, false, fake.clone());
            assert!(
                result.is_err(),
                "failure call {failure_call} must reject assert"
            );
            let (_, _, value) = fake.snapshot();
            if failure_call >= 3 {
                assert!(
                    !value,
                    "post-mutation failure call {failure_call} must finish electrically OFF"
                );
            }
        }

        // The inherited value is useful restore metadata but is not required
        // for safe assertion. Losing that read must remain explicit in the
        // trace and terminal closeout must still prove OFF.
        let fake = FakeGpioIo::inherited("out", true);
        fake.fail_call(2);
        let mut gate = PsuGpioGate::assert_resolved_with_io(907, false, fake.clone()).unwrap();
        assert_eq!(gate.restore_value, None);
        gate.force_safe_off_verified().unwrap();
        drop(gate);
        assert!(!fake.snapshot().2);
    }

    #[test]
    fn injected_terminal_failures_are_retried_by_drop_without_inherited_restore() {

        for terminal_failure_offset in 0usize..=2 {
            let fake = FakeGpioIo::inherited("out", true);
            let mut gate = PsuGpioGate::assert_resolved_with_io(907, false, fake.clone()).unwrap();
            let first_terminal_call = fake.snapshot().0.len();
            fake.fail_call(first_terminal_call + terminal_failure_offset);
            assert!(gate.force_safe_off_verified().is_err());
            assert!(gate.terminal_restore_retired);
            assert_eq!(gate.terminal_off_retry, Some(false));
            drop(gate);
            let (_, direction, value) = fake.snapshot();
            assert_eq!(direction, "out");
            assert!(!value, "Drop retry must leave the active-high rail OFF");
        }

        let fake = FakeGpioIo::inherited("out", true);
        let mut gate = PsuGpioGate::assert_resolved_with_io(907, false, fake.clone()).unwrap();
        fake.override_next_read(true);
        assert!(gate.force_safe_off_verified().is_err());
        drop(gate);
        assert!(
            !fake.snapshot().2,
            "readback mismatch retry must finish OFF"
        );
    }

    #[test]
    fn captured_active_low_polarity_survives_terminal_retry_and_drop() {
        let fake = FakeGpioIo::inherited("out", false);
        let mut gate = PsuGpioGate::assert_resolved_with_io(907, true, fake.clone()).unwrap();
        assert!(!fake.snapshot().2, "active-low ON is low");
        fake.fail_call(fake.snapshot().0.len());
        assert!(gate.force_safe_off_verified().is_err());
        assert_eq!(gate.terminal_off_retry, Some(true));
        drop(gate);
        assert!(fake.snapshot().2, "retained active-low owner must retry OFF high");
        assert!(fake.snapshot().0.contains(&FakeOp::WriteDirection("high".into())));
    }

    #[test]
    fn unknown_gpio907_polarity_refuses_before_export() {
        // No production recipe is installed in this unit-test process.
        // Use a child to isolate the original lab parser from other tests.
        const CHILD: &str = "DCENT_PSU_POLARITY_TEST_CHILD";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "psu_gpio_gate::tests::unknown_gpio907_polarity_refuses_before_export"])
                .env(CHILD, "1")
                .env_remove("DCENT_AM2_PWR_CONTROL_ACTIVE_LOW")
                .env_remove("DCENT_AM2_PWR_CONTROL_ACTIVE_HIGH")
                .status().unwrap();
            assert!(status.success());
            return;
        }
        let fake = FakeGpioIo::inherited("out", true);
        assert!(PsuGpioGate::assert_with_io(Some("gpio:907"), fake.clone()).is_err());
        assert!(fake.snapshot().0.is_empty(), "unknown polarity must not export or write");
    }

    #[test]
    fn failed_terminal_transition_irrevocably_retires_scoped_restore() {
        let mut gate = PsuGpioGate::for_test(u32::MAX - 1);
        assert!(gate.force_safe_off_verified().is_err());
        assert!(gate.terminal_restore_retired);
        assert!(!gate.asserted);
        assert!(gate.terminal_off_retry.is_some());
        assert!(gate.deassert().is_err());
    }

    #[test]
    fn terminal_safe_off_uses_session_polarity_after_environment_changes() {
        let _lock = POLARITY_ENV_LOCK.lock().unwrap();
        let low_key = "DCENT_AM2_PWR_CONTROL_ACTIVE_LOW";
        let high_key = "DCENT_AM2_PWR_CONTROL_ACTIVE_HIGH";
        let previous_low = std::env::var_os(low_key);
        let previous_high = std::env::var_os(high_key);

        // This owner represents a session admitted as active-low. Mutating the
        // process environment afterward must neither change its OFF level nor
        // make terminal closeout re-run polarity admission.
        let mut gate = PsuGpioGate::for_test_with_active_low(u32::MAX - 2, true);
        std::env::remove_var(low_key);
        std::env::set_var(high_key, "1");

        assert!(gate.force_safe_off_verified().is_err());
        assert_eq!(gate.terminal_off_retry, Some(true));
        assert!(gate.active_low);
        assert!(gate.off_level);

        match previous_low {
            Some(value) => std::env::set_var(low_key, value),
            None => std::env::remove_var(low_key),
        }
        match previous_high {
            Some(value) => std::env::set_var(high_key, value),
            None => std::env::remove_var(high_key),
        }
    }
}
