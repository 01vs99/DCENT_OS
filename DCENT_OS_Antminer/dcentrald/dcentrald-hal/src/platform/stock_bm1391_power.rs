//! Exact APW8 setting and quiet-fan operations through the retained C501 owner.
//! Sources: S15 7a57c/7a3b0/82fd0/87680/87988 and T15 counterparts; original
//! replay and limits in evidence/r04/power-thermal-{source.md,replay-v1.json}.
//! Software voltage limits and command completion do not establish rail voltage.
use super::*;

const POWER_IIC: u32 = 0x30;
const FAN_PWM: u32 = 0x84;
const FAN_TACH: u32 = 0x04;
// Exact stock PWM30: 15 high counts and35 low counts in the 50-count period.
const QUIET_PWM: u32 = 0x000f_0023;
// S15 63db8/T15 63dc8: 1603..2028 in hundredths of a volt. These are the
// observed software envelope, not independently qualified physical safe limits.
const MIN_VOLTS: f64 = 16.03;
const MAX_VOLTS: f64 = 20.28;

#[derive(Clone, Copy, Debug, PartialEq)]
struct Apw8Setting {
    volts: f64,
    code: u8,
}
impl Apw8Setting {
    fn new(volts: f64) -> Result<Self, String> {
        if !volts.is_finite() || !(MIN_VOLTS..=MAX_VOLTS).contains(&volts) {
            return Err(
                "BM1391 APW8 setting is outside the exact finite16.03..20.28V software envelope"
                    .into(),
            );
        }
        // Exact original doubles and truncating VFP conversion, including the
        // original DAC saturation. No inferred voltage readback is produced.
        let code = (1215.894_44 - volts * 59.931_506_85).clamp(0.0, 255.0) as u8;
        Ok(Self { volts, code })
    }
}

/// A completed FPGA command and software settling interval. `requested_volts`
/// is a request; the exact stock APW8 path has no measured voltage readback.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CommandedVoltage {
    pub requested_volts: f64,
    pub dac_code: u8,
    pub settled_at: Instant,
}

/// Exact stock30-percent register setting and its immediate MMIO readback.
/// This does not prove a physical fan speed or current airflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuietFanSetting {
    pub percent: u8,
    pub register_word: u32,
}

/// One raw hardware observation, not an established fresh physical fan identity.
/// Stock has no tach generation counter; the runtime must require its expected
/// fan population, reject missing/duplicate-only sets and enforce a sample age.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FanTachSample {
    pub raw_word: u32,
    pub fan_index: u8,
    pub raw_count: u8,
    pub stock_rpm: u32,
}
impl FanTachSample {
    fn decode(raw_word: u32) -> Option<Self> {
        // Original upper-level caller excludes the all-ones return before
        // treating the lower fields as a fan observation.
        (raw_word != u32::MAX).then_some(Self {
            raw_word,
            fan_index: ((raw_word >> 8) & 7) as u8,
            raw_count: raw_word as u8,
            stock_rpm: (raw_word & 255) * 120,
        })
    }
}

/// Sixteen original-style consecutive tach reads, preserving duplicates and
/// unavailable observations. The timestamp is host observation time only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FanTachSnapshot {
    pub observed_at: Instant,
    pub samples: [Option<FanTachSample>; 16],
}

struct PowerCancellation<R: Registers> {
    owner: Arc<Transport<R>>,
    completed: bool,
}
impl<R: Registers> Drop for PowerCancellation<R> {
    fn drop(&mut self) {
        if !self.completed {
            self.owner.latch_terminal();
        }
    }
}

impl<R: Registers> PicApplication<R> {
    /// Set the shared APW8 through the observed PIC population's retained owner.
    /// Requires five stable fresh heartbeat rounds, checked under management
    /// custody and again immediately before the command. The runtime still owns
    /// exact board voltage policy, cooling, independent cutoff and rail proof.
    pub async fn set_apw8_voltage(
        self: &Arc<Self>,
        volts: f64,
        deadline: Instant,
    ) -> Result<CommandedVoltage, String> {
        let setting = Apw8Setting::new(volts)?;
        let owner = self.transport().clone();
        let mut cancellation = PowerCancellation {
            owner: owner.clone(),
            completed: false,
        };
        let app = self.clone();
        let result = tokio::task::spawn_blocking(move || {
            owner.apw8_with_delay(
                setting,
                deadline,
                |ms| owner.power_delay(ms, deadline, false),
                || app.require_voltage_health(deadline),
            )
        })
        .await
        .map_err(|e| format!("BM1391 APW8 worker: {e}"));
        if result.is_err() {
            self.transport().latch_terminal();
        }
        cancellation.completed = true;
        result?
    }
}

impl<R: Registers> Transport<R> {
    fn power_check(&self, deadline: Instant, cooling_after_terminal: bool) -> Result<(), String> {
        if Instant::now() >= deadline || (!cooling_after_terminal && self.terminal()) {
            Err("BM1391 power/fan operation is terminal or expired".into())
        } else {
            Ok(())
        }
    }

    fn power_delay(
        &self,
        ms: u64,
        deadline: Instant,
        cooling_after_terminal: bool,
    ) -> Result<(), String> {
        let until = Instant::now() + Duration::from_millis(ms);
        loop {
            self.power_check(deadline, cooling_after_terminal)?;
            let Some(remaining) = until.checked_duration_since(Instant::now()) else {
                return Ok(());
            };
            std::thread::sleep(remaining.min(Duration::from_millis(1)));
        }
    }

    fn apw8_with_delay(
        &self,
        setting: Apw8Setting,
        deadline: Instant,
        mut delay: impl FnMut(u64) -> Result<(), String>,
        mut health: impl FnMut() -> Result<(), String>,
    ) -> Result<CommandedVoltage, String> {
        // Keep the guard through fault publication. Releasing it before the
        // error handler would let a waiting PIC writer overtake quarantine.
        let _management = match self.lock_management_until(deadline) {
            Ok(guard) => guard,
            Err(error) => {
                self.latch_terminal();
                return Err(error);
            }
        };
        let mut command_started = false;
        let mut command_completed = false;
        let result = (|| {
            self.power_check(deadline, false)?;
            if self.management_fault.load(Ordering::SeqCst) {
                return Err("BM1391 APW8 management portal is unresolved".into());
            }
            health()?;
            delay(100)?;
            self.power_check(deadline, false)?;
            health()?;
            command_started = true;
            // General-IIC bus1/device10/write/register02, one DAC byte.
            self.registers
                .write(POWER_IIC, 0x0520_0200 | u32::from(setting.code))?;
            for _ in 0..101 {
                delay(5)?;
                self.power_check(deadline, false)?;
                if self.registers.read(POWER_IIC)? & 0x8000_0000 != 0 {
                    command_completed = true;
                    break;
                }
            }
            if !command_completed {
                return Err("BM1391 APW8 FPGA byte completion timed out".into());
            }
            delay(300)?;
            self.power_check(deadline, false)?;
            Ok(CommandedVoltage {
                requested_volts: setting.volts,
                dac_code: setting.code,
                settled_at: Instant::now(),
            })
        })();
        if result.is_err() {
            if command_started && !command_completed {
                // A later terminal PIC operation must not overwrite an active
                // or uncertain +30 transaction. Independent cutoff is separate.
                self.management_fault.store(true, Ordering::SeqCst);
            }
            self.latch_terminal();
        }
        result
    }

    pub(super) fn quiet_fans_locked(&self, deadline: Instant) -> Result<QuietFanSetting, String> {
        let _fan = match self.lock_fan_until(deadline) {
            Ok(guard) => guard,
            Err(error) => {
                self.latch_terminal();
                return Err(error);
            }
        };
        let result = (|| {
            self.power_check(deadline, true)?;
            self.registers.write(FAN_PWM, QUIET_PWM)?;
            self.power_check(deadline, true)?;
            if self.registers.read(FAN_PWM)? != QUIET_PWM {
                return Err("BM1391 quiet fan PWM register readback mismatch".into());
            }
            self.power_check(deadline, true)?;
            Ok(QuietFanSetting {
                percent: 30,
                register_word: QUIET_PWM,
            })
        })();
        if result.is_err() {
            self.latch_terminal();
        }
        result
    }

    /// Apply only the source-backed quiet30 setting. Available after the work
    /// latch closes, including an unresolved IIC command: fan+84 is independent.
    pub async fn set_quiet_fans(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<QuietFanSetting, String> {
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || owner.quiet_fans_locked(deadline))
            .await
            .map_err(|e| format!("BM1391 quiet fan worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        result?
    }

    fn tach_snapshot_locked(&self, deadline: Instant) -> Result<FanTachSnapshot, String> {
        let _fan = match self.lock_fan_until(deadline) {
            Ok(guard) => guard,
            Err(error) => {
                self.latch_terminal();
                return Err(error);
            }
        };
        let result = (|| {
            let mut samples = [None; 16];
            for sample in &mut samples {
                self.power_check(deadline, true)?;
                *sample = FanTachSample::decode(self.registers.read(FAN_TACH)?);
            }
            self.power_check(deadline, true)?;
            Ok(FanTachSnapshot {
                observed_at: Instant::now(),
                samples,
            })
        })();
        if result.is_err() {
            self.latch_terminal();
        }
        result
    }

    /// Observe raw tach records without assigning fan identity or airflow.
    /// Terminal-off cooling can continue to observe this independent register.
    pub async fn fan_tach_snapshot(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<FanTachSnapshot, String> {
        let owner = self.clone();
        let result = tokio::task::spawn_blocking(move || owner.tach_snapshot_locked(deadline))
            .await
            .map_err(|e| format!("BM1391 fan tach worker: {e}"));
        if result.is_err() {
            self.latch_terminal();
        }
        result?
    }
}

#[cfg(test)]
#[path = "stock_bm1391_power_tests.rs"]
mod tests;
