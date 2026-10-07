//! Exact BM1396 source-low startup joined to retained model-specific factory data.
//! Exact source poweroff waits 1 s, caller waits 60 s, poweron waits 1 s.
//! S17e signed2020 independently calls5C06C at189A4, waits60 at189AC,
//! and calls5BE9C at189BC; GPIO identity remains captured by its native owner.
use super::*;

const OFF_SETTLE: Duration = Duration::from_secs(61);
const OBSERVATION_FRESHNESS: Duration = Duration::from_secs(1);

#[derive(Clone, Debug)]
pub struct SourceStartObservation {
    issuer: Arc<()>,
    off: PowerLineOffObservation,
    supply: SupplyTypeObservation,
    fans: FanTachSnapshot,
    attempted_at: Instant,
    low_observed_at: Option<Instant>,
    settled_at: Option<Instant>,
}
impl SourceStartObservation {
    pub fn attempted_at(&self) -> Instant {
        self.attempted_at
    }
    pub fn low_observed_at(&self) -> Option<Instant> {
        self.low_observed_at
    }
    pub fn settled_at(&self) -> Option<Instant> {
        self.settled_at
    }
    pub fn initial_off(&self) -> &PowerLineOffObservation {
        &self.off
    }
    pub fn supply(&self) -> &SupplyTypeObservation {
        &self.supply
    }
    pub fn fan_snapshot(&self) -> &FanTachSnapshot {
        &self.fans
    }
    pub fn same_owner<H: Hardware>(&self, owner: &Arc<Transport<H>>) -> bool {
        Arc::ptr_eq(&self.issuer, &owner.identity)
    }
}

impl<H: Hardware> PowerLine<H> {
    /// Actual first high observation plus the original 1+60 second source
    /// interval. The runtime waits asynchronously while supervising health;
    /// no long-held pin mutex prevents its independent terminal high.
    pub fn source_enable_not_before(&self) -> Result<Instant, String> {
        self.initial_off
            .lock()
            .map_err(|_| "BM1396 initial-off custody poisoned")?
            .as_ref()
            .ok_or("BM1396 source has no actual initial high")?
            .observed_at
            .checked_add(OFF_SETTLE)
            .ok_or_else(|| "BM1396 source settle deadline overflow".into())
    }

    pub fn source_start_observation(&self) -> Result<Option<SourceStartObservation>, String> {
        Ok(self
            .source_start
            .lock()
            .map_err(|_| "BM1396 source-start custody poisoned")?
            .clone())
    }

    /// Read-only same-owner low/settled check. The independent terminal-high
    /// path shares only this short pin gate, never ASIC or management custody.
    pub(in super::super) fn check_active_source(
        &self,
        owner: &Arc<Transport<H>>,
        deadline: Instant,
    ) -> Result<(), String> {
        if !self.same_owner(owner) {
            return Err(format!(
                "{:?} active source belongs to another owner",
                owner.model
            ));
        }
        let _gate = owner.lock(&self.gate, deadline, false)?;
        owner.check(deadline, false)?;
        if self.pin.observed_high()? {
            return Err(format!(
                "{:?} active source is not observed low",
                owner.model
            ));
        }
        let retained = self
            .source_start
            .lock()
            .map_err(|_| format!("{:?} source custody poisoned", owner.model))?;
        if !retained
            .as_ref()
            .is_some_and(|source| source.same_owner(owner) && source.settled_at().is_some())
        {
            return Err(format!(
                "{:?} active source lacks completed same-owner settle",
                owner.model
            ));
        }
        owner.check(deadline, false)
    }

    /// One exact-model source-low attempt after actual high settle, admitted supply42,
    /// complete same-owner factory calibration, five fresh PIC rounds, both
    /// quiet PWM readbacks and the shared fresh four-fan quiet30 policy.
    /// The composed runtime must already own its armed watchdog and cutoff task.
    pub async fn enable_source_after_observations(
        self: &Arc<Self>,
        app: Arc<PicApplication<H>>,
        quiet: QuietFanSetting,
        fans: FanTachSnapshot,
        deadline: Instant,
    ) -> Result<SourceStartObservation, String> {
        let line = self.clone();
        self.owner
            .worker(deadline, false, move |owner| {
                let asic = owner.lock(&owner.asic, deadline, false)?;
                if !app.same_owner(&owner)
                    || !quiet.same_owner(&owner)
                    || !fans.same_owner(&owner)
                    || asic.startup_attempted
                    || !asic.publications.is_empty()
                    || owner.hardware.read(DHASH)? & RUN != 0
                    || owner.hardware.read(BC)? & BUSY != 0
                    || owner.asic_fault.load(Ordering::SeqCst)
                    || owner.management_fault.load(Ordering::SeqCst)
                {
                    return Err("T17e source-low requires exact unused same-owner startup".into());
                }
                owner.query_presence(deadline)?;
                owner.factory_calibration_profile()?;
                app.check_health(deadline)?;
                let supply = app
                    .supply_type_observation()?
                    .filter(|receipt| receipt.admitted_type() == Some(0x42))
                    .ok_or("T17e source-low requires its admitted supply-type42")?;
                app.with_source_start_voltage_custody(deadline, || {
                    if quiet.registers() != [(0x84, 0x000f0023), (0xa0, 0x000f0023)]
                        || quiet.completed_at().elapsed() >= OBSERVATION_FRESHNESS
                        || fans.observed_from().elapsed() >= OBSERVATION_FRESHNESS
                        || fans.completed_at() < fans.observed_from()
                        || fans.raw_version() != owner.version
                    {
                        return Err(
                            "T17e source-low requires fresh exact quiet/tach observations".into(),
                        );
                    }
                    fans.require_quiet_population(&quiet)?;
                    let _fans = owner.lock(&owner.fans, deadline, false)?;
                    for (offset, expected) in quiet.registers() {
                        if owner.hardware.read(offset)? != expected {
                            return Err("T17e quiet PWM changed before source-low".into());
                        }
                    }
                    let off = line
                        .initial_off
                        .lock()
                        .map_err(|_| "BM1396 initial-off custody poisoned")?
                        .clone()
                        .ok_or("T17e source-low lacks actual initial high")?;
                    if !off.same_owner(&owner)
                        || Instant::now() < line.source_enable_not_before()?
                    {
                        return Err(
                            "T17e source-low requires the complete source61s high interval".into(),
                        );
                    }
                    {
                        let _pin = owner.lock(&line.gate, deadline, false)?;
                        app.check_health(deadline)?;
                        owner.query_presence(deadline)?;
                        if quiet.completed_at().elapsed() >= OBSERVATION_FRESHNESS
                            || fans.observed_from().elapsed() >= OBSERVATION_FRESHNESS
                            || owner.hardware.read(DHASH)? & RUN != 0
                            || owner.hardware.read(BC)? & BUSY != 0
                        {
                            return Err(
                                "T17e source-low observations changed or expired before write"
                                    .into(),
                            );
                        }
                        owner.check(deadline, false)?;
                        if !line.pin.observed_high()? {
                            return Err("T17e source changed before admitted low".into());
                        }
                        let mut retained = line
                            .source_start
                            .lock()
                            .map_err(|_| "BM1396 source-start custody poisoned")?;
                        if retained.is_some() {
                            return Err("T17e source-low attempt already spent".into());
                        }
                        *retained = Some(SourceStartObservation {
                            issuer: owner.identity.clone(),
                            off,
                            supply,
                            fans,
                            attempted_at: Instant::now(),
                            low_observed_at: None,
                            settled_at: None,
                        });
                        drop(retained);
                        // Guarded by the independent pin lane, with terminal rechecked
                        // immediately before the actual value write. An error retains
                        // this attempted record and the actual counted worker.
                        owner.check(deadline, false)?;
                        line.pin.low()?;
                        if line.pin.observed_high()? {
                            return Err("T17e source low was not observed".into());
                        }
                        line.source_start
                            .lock()
                            .map_err(|_| "BM1396 source-start custody poisoned")?
                            .as_mut()
                            .expect("retained attempt")
                            .low_observed_at = Some(Instant::now());
                    }
                    drop(_fans);
                    drop(asic);
                    owner.delay(Duration::from_secs(1), deadline, false)?;
                    {
                        let _pin = owner.lock(&line.gate, deadline, false)?;
                        app.check_health(deadline)?;
                        if line.pin.observed_high()? {
                            return Err("T17e source low changed during settling".into());
                        }
                        owner.check(deadline, false)?;
                        line.source_start
                            .lock()
                            .map_err(|_| "BM1396 source-start custody poisoned")?
                            .as_mut()
                            .expect("retained attempt")
                            .settled_at = Some(Instant::now());
                    }
                    line.source_start_observation()?
                        .ok_or_else(|| "T17e source-start custody lost".into())
                })
            })
            .await
    }
}
