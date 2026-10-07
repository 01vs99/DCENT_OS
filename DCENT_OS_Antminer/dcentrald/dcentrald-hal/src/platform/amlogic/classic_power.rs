//! Exact classic AML power/reset/cooling composition. Constants are bound to
//! R10 bm1362-aml-production-power.asm, PIC application/ADC original replays,
//! and the exact BHB42601/21/41 factory owner in the parent module.
use super::super::s21_psu::{ProductionProfile, S21PsuService};
use super::*;
use std::path::PathBuf;

const HEALTH_MAX_AGE: Duration = Duration::from_secs(5);
const MAX_TEMP_C: f64 = 80.0; // Conservative DCENT operating policy.
const MIN_FAN_RPM: u32 = 1800; // Admission floor, not calibrated airflow.

#[derive(Debug)]
pub struct ClassicHealth {
    pub temperatures: Vec<ClassicTemperature>,
    pub voltages: Vec<ClassicVoltage>,
    pub fans: Vec<(u8, u32)>,
    pub observed_from: Instant,
    pub completed_at: Instant,
}
#[derive(Debug, Clone)]
pub struct ClassicControlCut {
    pub(super) attempted_at: Option<Instant>,
    pub(super) rail_observed_at: Option<Instant>,
    /// Software sysfs write/readback only; no independent electrical claim.
    pub rail_off: bool,
    pub resets_held: bool,
    pub quiet_fans: bool,
    pub errors: Vec<String>,
}
#[derive(Debug)]
pub struct ClassicPowerCloseReport {
    controls: ClassicControlCut,
    pic: Option<ClassicCloseReport>,
    psu_closed: bool,
    errors: Vec<String>,
    issuer: Arc<()>,
    cutoff_started: Option<Instant>,
    cutoff_observed_at: Option<Instant>,
    finished_at: Instant,
}
impl ClassicPowerCloseReport {
    pub fn same_owner(&self, owner: &ClassicAmlPowerOwner) -> bool {
        Arc::ptr_eq(&self.issuer, &owner.shared.issuer)
    }
    pub fn cutoff_started(&self) -> Option<Instant> {
        self.cutoff_started
    }
    pub fn cutoff_observed_at(&self) -> Option<Instant> {
        self.cutoff_observed_at
    }
    pub fn finished_at(&self) -> Instant {
        self.finished_at
    }
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
    pub fn software_cleanup_complete(&self) -> bool {
        self.controls.rail_off
            && self.controls.resets_held
            && self.controls.quiet_fans
            && self.psu_closed
            && self.errors.is_empty()
            && self
                .pic
                .as_ref()
                .is_some_and(|p| p.workers_closed && p.cuts.iter().all(|(_, r)| r.is_ok()))
    }
}

pub(super) trait Controls: Send + Sync {
    fn fence(&self);
    fn discover(&self, deadline: Instant) -> Result<()>;
    fn configure(&self, volts: f64, deadline: Instant) -> Result<()>;
    fn heartbeat(&self, deadline: Instant) -> Result<()>;
    fn rail(&self, on: bool, deadline: Instant) -> Result<()>;
    fn resets(&self, populated: [bool; 3], release: bool, deadline: Instant) -> Result<()>;
    fn verify(
        &self,
        populated: [bool; 3],
        rail: bool,
        released: bool,
        deadline: Instant,
    ) -> Result<()>;
    fn fans(&self, deadline: Instant) -> Result<Vec<(u8, u32)>>;
    fn cut(&self, deadline: Instant) -> ClassicControlCut;
    fn close(&self, deadline: Instant) -> Result<()>;
}

struct LiveControls {
    recipe: Gpio437DriveRecipe,
    psu: S21PsuService,
    fan: AmlogicFan,
    terminal: AtomicBool,
    psu_failed: AtomicBool,
    closed: AtomicBool,
    // GPIO enable/reset release and independent terminal cut share this lane.
    // PSU commands have a separate lane so cut never waits on their parser.
    pins: Mutex<()>,
    psu_lane: Mutex<()>,
}
impl Drop for LiveControls {
    fn drop(&mut self) {
        self.fence();
        if !self.closed.load(Ordering::SeqCst) {
            // Deliberately retain an unresolved exact raw fabric owner until
            // process reset. A dropped/failed classic owner may not silently
            // free the bus for a new ordinary owner. Explicit healthy close is
            // the sole release path; the mutation journal sees retained custody.
            std::mem::forget(self.psu.clone());
        }
    }
}
impl LiveControls {
    fn open(recipe: Gpio437DriveRecipe) -> Result<Self> {
        let fan = AmlogicFan::new()?;
        let psu = S21PsuService::open(ProductionProfile::ClassicApw121215)?;
        // Exact repeated factory/PIC observations preceded this constructor.
        // Taking an input pin into ownership begins at the qualified OFF level.
        drive_psu_checked_at(
            Path::new("/sys/class/gpio"),
            437,
            recipe,
            false,
            |path, value| fs::write(path, value),
        )?;
        Ok(Self {
            recipe,
            psu,
            fan,
            terminal: AtomicBool::new(false),
            psu_failed: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            pins: Mutex::new(()),
            psu_lane: Mutex::new(()),
        })
    }
    fn live(&self, deadline: Instant) -> Result<()> {
        if self.terminal.load(Ordering::SeqCst) || Instant::now() >= deadline {
            Err(error("classic AML controls terminal or expired"))
        } else {
            Ok(())
        }
    }
    fn gpio(gpio: u32, want: u8, write: bool) -> Result<()> {
        let base = PathBuf::from(format!("/sys/class/gpio/gpio{gpio}"));
        if fs::read_to_string(base.join("active_low"))?.trim() != "0"
            || fs::read_to_string(base.join("direction"))?.trim() != "out"
        {
            return Err(error(format!(
                "classic AML GPIO{gpio} lost prepared raw output"
            )));
        }
        if write {
            fs::write(base.join("value"), want.to_string())?;
        }
        if fs::read_to_string(base.join("value"))?.trim() != want.to_string() {
            return Err(error(format!(
                "classic AML GPIO{gpio} raw readback mismatch"
            )));
        }
        Ok(())
    }
    fn quiet(&self) -> Result<()> {
        self.fan.set_speed_checked(30)?;
        for pwm in [0, 1] {
            let base = PathBuf::from(format!("/sys/class/pwm/pwmchip0/pwm{pwm}"));
            for (name, want) in [
                ("enable", "1"),
                ("period", "100000"),
                ("duty_cycle", "30000"),
            ] {
                if fs::read_to_string(base.join(name))?.trim() != want {
                    return Err(error(format!("classic AML PWM{pwm} {name} readback")));
                }
            }
        }
        Ok(())
    }
    fn psu_call(
        &self,
        deadline: Instant,
        call: impl FnOnce(&S21PsuService) -> Result<()>,
    ) -> Result<()> {
        let _lane = self
            .psu_lane
            .lock()
            .map_err(|_| error("classic PSU lane poisoned"))?;
        self.live(deadline)?;
        let result = call(&self.psu).and_then(|()| self.live(deadline));
        if result.is_err() {
            // Publish before dropping the outer lane: waiting callers cannot
            // enter a PSU parser after a failed or cancelled transaction.
            self.psu_failed.store(true, Ordering::SeqCst);
            self.fence();
        }
        result
    }
}
impl Controls for LiveControls {
    fn fence(&self) {
        self.terminal.store(true, Ordering::SeqCst);
        self.psu.fence();
    }
    fn discover(&self, deadline: Instant) -> Result<()> {
        self.psu_call(deadline, |p| p.discover().map(|_| ()))
    }
    fn configure(&self, volts: f64, deadline: Instant) -> Result<()> {
        self.psu_call(deadline, |p| p.initialize(volts))
    }
    fn heartbeat(&self, deadline: Instant) -> Result<()> {
        self.psu_call(deadline, S21PsuService::heartbeat)
    }
    fn rail(&self, on: bool, deadline: Instant) -> Result<()> {
        let _lane = self
            .pins
            .lock()
            .map_err(|_| error("classic GPIO lane poisoned"))?;
        self.live(deadline)?;
        Self::gpio(
            437,
            if on {
                self.recipe.on_raw()
            } else {
                self.recipe.off_raw()
            },
            true,
        )?;
        self.live(deadline)
    }
    fn resets(&self, populated: [bool; 3], release: bool, deadline: Instant) -> Result<()> {
        let _lane = self
            .pins
            .lock()
            .map_err(|_| error("classic GPIO lane poisoned"))?;
        for (slot, present) in populated.into_iter().enumerate() {
            self.live(deadline)?;
            Self::gpio(454 + slot as u32, u8::from(release && present), true)?;
        }
        self.live(deadline)
    }
    fn verify(
        &self,
        populated: [bool; 3],
        rail: bool,
        released: bool,
        deadline: Instant,
    ) -> Result<()> {
        let _lane = self
            .pins
            .lock()
            .map_err(|_| error("classic GPIO lane poisoned"))?;
        self.live(deadline)?;
        Self::gpio(
            437,
            if rail {
                self.recipe.on_raw()
            } else {
                self.recipe.off_raw()
            },
            false,
        )?;
        for (slot, present) in populated.into_iter().enumerate() {
            Self::gpio(454 + slot as u32, u8::from(released && present), false)?;
        }
        self.quiet()?;
        self.live(deadline)
    }
    fn fans(&self, deadline: Instant) -> Result<Vec<(u8, u32)>> {
        self.live(deadline)?;
        self.quiet()?;
        let fans = self.fan.get_per_fan_rpm();
        self.live(deadline)?;
        if !self.fan.tach_available() {
            return Err(error("classic AML tach custody failed"));
        }
        Ok(fans)
    }
    fn cut(&self, deadline: Instant) -> ClassicControlCut {
        self.fence();
        let mut report = ClassicControlCut {
            attempted_at: None,
            rail_observed_at: None,
            rail_off: false,
            resets_held: false,
            quiet_fans: false,
            errors: vec![],
        };
        // No ordinary command/parser lane is needed for this independent cut.
        let _lane = loop {
            match self.pins.try_lock() {
                Ok(lane) => break lane,
                Err(std::sync::TryLockError::Poisoned(e)) => {
                    report.errors.push("classic GPIO lane poisoned".into());
                    break e.into_inner();
                }
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => {
                    report
                        .errors
                        .push("classic GPIO cut lane did not quiesce".into());
                    return report;
                }
            }
        };
        let mut checked = |result: Result<()>| match result {
            Ok(()) => true,
            Err(e) => {
                report.errors.push(e.to_string());
                false
            }
        };
        report.attempted_at = Some(Instant::now());
        report.rail_off = checked(Self::gpio(437, self.recipe.off_raw(), true));
        report.rail_observed_at = report.rail_off.then(Instant::now);
        report.resets_held = true;
        for gpio in [454, 455, 456] {
            report.resets_held &= checked(Self::gpio(gpio, 0, true));
        }
        report.quiet_fans = report.rail_off && checked(self.quiet());
        if Instant::now() >= deadline {
            report
                .errors
                .push("classic GPIO cut missed deadline".into());
        }
        report
    }
    fn close(&self, deadline: Instant) -> Result<()> {
        self.fence();
        let _lane = loop {
            match self.psu_lane.try_lock() {
                Ok(lane) => break lane,
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    return Err(error("classic PSU lane poisoned; raw fabric retained"))
                }
                Err(std::sync::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(_) => {
                    return Err(error(
                        "classic PSU operation failed to quiesce; raw fabric retained",
                    ))
                }
            }
        };
        if self.psu_failed.load(Ordering::SeqCst) {
            return Err(error("classic PSU parser unresolved; raw fabric retained"));
        }
        self.psu.close_until(deadline)?;
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

struct Shared {
    issuer: Arc<()>,
    pic: Arc<ClassicAmlPicOwner>,
    controls: Arc<dyn Controls>,
    terminal: AtomicBool,
    inflight: Arc<std::sync::atomic::AtomicUsize>,
}
struct ControlFlight(Arc<std::sync::atomic::AtomicUsize>);
impl Drop for ControlFlight {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Shared {
    fn fence(&self) {
        self.terminal.store(true, Ordering::SeqCst);
        self.pic.fence();
        self.controls.fence();
    }
    fn live(&self, deadline: Instant) -> Result<()> {
        if self.terminal.load(Ordering::SeqCst) || Instant::now() >= deadline {
            Err(error("classic power composition terminal or expired"))
        } else {
            Ok(())
        }
    }
    async fn control<T: Send + 'static>(
        &self,
        deadline: Instant,
        call: impl FnOnce(&dyn Controls) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.live(deadline)?;
        let controls = self.controls.clone();
        self.inflight.fetch_add(1, Ordering::SeqCst);
        let flight = ControlFlight(self.inflight.clone());
        tokio::task::spawn_blocking(move || {
            let _flight = flight;
            call(controls.as_ref())
        })
        .await
        .map_err(|e| error(format!("classic control worker: {e}")))?
    }
}
struct PowerAttempt {
    shared: Arc<Shared>,
    complete: bool,
}
impl Drop for PowerAttempt {
    fn drop(&mut self) {
        if !self.complete {
            self.shared.fence();
        }
    }
}
struct PowerState {
    started: bool,
    last_health: Option<Instant>,
    target_volts: f64,
    min_rpm: u32,
}
/// Joined exact classic application, APW12, reset, fans and rail observations.
/// Daemon watchdog custody must precede acquisition and remain through close.
pub struct ClassicAmlPowerOwner {
    shared: Arc<Shared>,
    state: tokio::sync::Mutex<PowerState>,
}
impl Drop for ClassicAmlPowerOwner {
    fn drop(&mut self) {
        self.shared.fence();
    }
}
impl ClassicAmlPowerOwner {
    #[cfg(test)]
    pub(super) fn test_with(pic: Arc<ClassicAmlPicOwner>, controls: Arc<dyn Controls>) -> Self {
        Self {
            shared: Arc::new(Shared {
                issuer: Arc::new(()),
                pic,
                controls,
                terminal: AtomicBool::new(false),
                inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }),
            state: tokio::sync::Mutex::new(PowerState {
                started: false,
                last_health: None,
                target_volts: 0.0,
                min_rpm: MIN_FAN_RPM,
            }),
        }
    }
    pub async fn acquire_at(deadline: Instant) -> Result<Self> {
        let pic = Arc::new(ClassicAmlPicOwner::observe_at(deadline).await?);
        let recipe = pic.gpio437_recipe()?;
        let controls = tokio::task::spawn_blocking(move || LiveControls::open(recipe))
            .await
            .map_err(|e| error(format!("classic control acquisition: {e}")))??;
        let shared = Arc::new(Shared {
            issuer: Arc::new(()),
            pic,
            controls: Arc::new(controls),
            terminal: AtomicBool::new(false),
            inflight: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        });
        let mut attempt = PowerAttempt {
            shared: shared.clone(),
            complete: false,
        };
        shared.live(deadline)?;
        let populated = shared.pic.snapshot.populated;
        shared
            .control(deadline, move |c| {
                c.verify(populated, false, false, deadline)
            })
            .await?;
        attempt.complete = true;
        Ok(Self {
            shared,
            state: tokio::sync::Mutex::new(PowerState {
                started: false,
                last_health: None,
                target_volts: 0.0,
                min_rpm: MIN_FAN_RPM,
            }),
        })
    }
    pub fn physical_chains(&self) -> Vec<u8> {
        self.shared.pic.physical_chains()
    }
    pub fn fence(&self) {
        self.shared.fence();
    }

    /// Stop-only crash path for this retained exact route. It bypasses PIC
    /// and PSU parser waits and attempts the independently held GPIO cutoff.
    /// This synchronous, bounded best effort cannot grant clean closeout or
    /// watchdog disarm; normal runtime I/O uses close_at on a blocking worker.
    pub fn emergency_cut_until(&self, deadline: Instant) -> ClassicControlCut {
        self.shared.fence();
        self.shared.controls.cut(deadline)
    }
    async fn state(&self, deadline: Instant) -> Result<tokio::sync::MutexGuard<'_, PowerState>> {
        self.shared.live(deadline)?;
        let state = tokio::time::timeout_at(deadline.into(), self.state.lock())
            .await
            .map_err(|_| error("classic power state admission timeout"))?;
        self.shared.live(deadline)?;
        Ok(state)
    }
    pub async fn start_at(
        &self,
        target_volts: f64,
        min_rpm: u32,
        deadline: Instant,
    ) -> Result<ClassicHealth> {
        let mut attempt = PowerAttempt {
            shared: self.shared.clone(),
            complete: false,
        };
        let mut state = self.state(deadline).await?;
        if state.started
            || !target_volts.is_finite()
            || !(13.0..=13.8).contains(&target_volts)
            || min_rpm < MIN_FAN_RPM
        {
            return Err(error(
                "classic startup must be cold with13.0..13.8V and credible fan floor",
            ));
        }
        let populated = self.shared.pic.snapshot.populated;
        self.shared
            .control(deadline, move |c| {
                c.verify(populated, false, false, deadline)
            })
            .await?;
        let fans = self
            .shared
            .control(deadline, move |c| c.fans(deadline))
            .await?;
        validate_fans(&fans, min_rpm)?;
        loop {
            let round = self.shared.pic.heartbeat_round_at(deadline).await?;
            if round.stable_rounds == 5 {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            self.shared.live(deadline)?;
        }
        // Every populated PIC-local sensor is checked before any rail mutation.
        self.thermal_at(deadline).await?;
        self.shared
            .control(deadline, move |c| c.discover(deadline))
            .await?;
        self.shared
            .control(deadline, move |c| c.rail(true, deadline))
            .await?;
        self.shared
            .control(deadline, move |c| c.configure(target_volts, deadline))
            .await?;
        self.shared.pic.heartbeat_round_at(deadline).await?;
        self.shared.pic.enable_at(deadline).await?;
        let rails = self.shared.pic.voltages_at(deadline).await?;
        validate_voltages(&rails, &self.physical_chains(), target_volts)?;
        self.shared
            .control(deadline, move |c| c.resets(populated, true, deadline))
            .await?;
        state.target_volts = target_volts;
        state.min_rpm = min_rpm;
        state.started = true;
        let health = self.health_locked(&state, deadline).await?;
        state.last_health = Some(health.observed_from);
        attempt.complete = true;
        Ok(health)
    }
    async fn thermal_at(&self, deadline: Instant) -> Result<Vec<ClassicTemperature>> {
        let mut temperatures = Vec::new();
        for chain in self.physical_chains() {
            self.shared.pic.heartbeat_round_at(deadline).await?;
            let values = self.shared.pic.temperatures_at(chain, deadline).await?;
            if values.len() != 4
                || values.iter().enumerate().any(|(i, t)| {
                    t.chain != chain
                        || t.sensor != 0x48 + i as u8
                        || !t.celsius.is_finite()
                        || !(-20.0..MAX_TEMP_C).contains(&t.celsius)
                })
            {
                return Err(error(format!(
                    "classic HB{chain} temperature coverage/envelope rejected"
                )));
            }
            temperatures.extend(values);
        }
        Ok(temperatures)
    }
    async fn health_locked(&self, state: &PowerState, deadline: Instant) -> Result<ClassicHealth> {
        let observed_from = Instant::now();
        self.shared
            .control(deadline, move |c| c.heartbeat(deadline))
            .await?;
        let temperatures = self.thermal_at(deadline).await?;
        let voltages = self.shared.pic.voltages_at(deadline).await?;
        validate_voltages(&voltages, &self.physical_chains(), state.target_volts)?;
        let fans = self
            .shared
            .control(deadline, move |c| c.fans(deadline))
            .await?;
        validate_fans(&fans, state.min_rpm)?;
        let populated = self.shared.pic.snapshot.populated;
        self.shared
            .control(deadline, move |c| c.verify(populated, true, true, deadline))
            .await?;
        self.shared.pic.validate_current(deadline).await?;
        self.shared.live(deadline)?;
        if observed_from.elapsed() >= HEALTH_MAX_AGE {
            return Err(error(
                "classic health observation aged out before publication",
            ));
        }
        Ok(ClassicHealth {
            temperatures,
            voltages,
            fans,
            observed_from,
            completed_at: Instant::now(),
        })
    }
    pub async fn health_at(&self, deadline: Instant) -> Result<ClassicHealth> {
        let mut attempt = PowerAttempt {
            shared: self.shared.clone(),
            complete: false,
        };
        let mut state = self.state(deadline).await?;
        if !state.started {
            return Err(error("classic health requires started power composition"));
        }
        let health = self.health_locked(&state, deadline).await?;
        state.last_health = Some(health.observed_from);
        attempt.complete = true;
        Ok(health)
    }
    /// Work admission is observational. The caller's typed serial execution
    /// fence must additionally bind this exact owner's route/generation.
    pub async fn require_work_health_at(&self, deadline: Instant) -> Result<Instant> {
        let state = self.state(deadline).await?;
        if !state.started
            || !state
                .last_health
                .is_some_and(|last| last.elapsed() < HEALTH_MAX_AGE)
        {
            self.fence();
            return Err(error("classic work health absent or stale"));
        }
        // Return the retained observation itself. A concurrent async reporting
        // actor may not yet have delivered its watch update when this lock opens.
        Ok(state
            .last_health
            .expect("fresh started health checked above"))
    }
    pub async fn close_at(&self, deadline: Instant) -> ClassicPowerCloseReport {
        self.fence();
        let controls = self.shared.controls.clone();
        let cut = tokio::task::spawn_blocking(move || controls.cut(deadline)).await;
        let controls = cut.unwrap_or_else(|e| ClassicControlCut {
            attempted_at: None,
            rail_observed_at: None,
            rail_off: false,
            resets_held: false,
            quiet_fans: false,
            errors: vec![format!("classic cut worker: {e}")],
        });
        let mut errors = controls.errors.clone();
        let cutoff_started = controls.attempted_at;
        let cutoff_observed_at = controls.rail_observed_at;
        let pic = match self.shared.pic.close_at(deadline).await {
            Ok(report) => Some(report),
            Err(e) => {
                errors.push(e.to_string());
                None
            }
        };
        // A dropped async future may leave a blocking fan/PSU/GPIO worker
        // running. Keep custody until every submitted control closure exits.
        while self.shared.inflight.load(Ordering::SeqCst) != 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        if self.shared.inflight.load(Ordering::SeqCst) != 0 {
            errors.push("classic control workers did not quiesce; raw fabric retained".into());
            return ClassicPowerCloseReport {
                issuer: self.shared.issuer.clone(),
                cutoff_started,
                cutoff_observed_at,
                finished_at: Instant::now(),
                controls,
                pic,
                psu_closed: false,
                errors,
            };
        }
        let psu = self.shared.controls.clone();
        let closed = tokio::task::spawn_blocking(move || psu.close(deadline)).await;
        let psu_closed = match closed {
            Ok(Ok(())) => true,
            result => {
                errors.push(format!("classic PSU close: {result:?}"));
                false
            }
        };
        ClassicPowerCloseReport {
            issuer: self.shared.issuer.clone(),
            cutoff_started,
            cutoff_observed_at,
            finished_at: Instant::now(),
            controls,
            pic,
            psu_closed,
            errors,
        }
    }
}
fn validate_fans(fans: &[(u8, u32)], min_rpm: u32) -> Result<()> {
    if fans.len() != 4
        || fans
            .iter()
            .enumerate()
            .any(|(i, (slot, rpm))| *slot != i as u8 || *rpm < min_rpm)
    {
        Err(error("classic requires four credible fan tach samples"))
    } else {
        Ok(())
    }
}
fn validate_voltages(rails: &[ClassicVoltage], chains: &[u8], target: f64) -> Result<()> {
    if rails.len() != chains.len()
        || rails
            .iter()
            .zip(chains)
            .any(|(r, c)| r.chain != *c || !r.volts.is_finite() || (r.volts - target).abs() > 0.3)
    {
        Err(error(
            "classic all-selected rail ADC coverage/envelope rejected",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "classic_power_tests.rs"]
mod tests;
