//! Exact signed set_pwm497dc/4a3d0 writes BOTH +84 and +a0.
//! Quiet30 is 0x000f0023. Shared ASIC/management locks are not acquired here.
use super::*;
use dcentrald_common::bm1396_contract::{
    bm1396_decode_fan_tach, bm1396_fan_sample_passes, bm1396_quiet_fan_validation_policy,
    Bm1396FanTachReading, BM1396_QUIET_FAN_PWM_PERCENT,
};

const QUIET_WORD: u32 = 0x000f_0023;
const PWM_REGISTERS: [u32; 2] = [0x84, 0xa0];

/// Sealed same-owner observation of both PWM register readbacks. The public
/// display field does not confer mutation authority; raw observed words and
/// private identity remain attached to the producing owner.
#[derive(Debug, Clone)]
pub struct QuietFanSetting {
    pub percent: u8,
    identity: Arc<()>,
    registers: [(u32, u32); 2],
    completed_at: Instant,
}
impl QuietFanSetting {
    pub fn registers(&self) -> [(u32, u32); 2] {
        self.registers
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
    pub(super) fn same_owner<H: Hardware>(&self, owner: &Transport<H>) -> bool {
        Arc::ptr_eq(&self.identity, &owner.identity)
    }
}

#[derive(Debug, Clone)]
pub struct FanTachSnapshot {
    identity: Arc<()>,
    raw_version: u32,
    samples: Vec<(u32, Bm1396FanTachReading)>,
    observed_from: Instant,
    completed_at: Instant,
}
impl FanTachSnapshot {
    pub(super) fn same_owner<H: Hardware>(&self, owner: &Transport<H>) -> bool {
        Arc::ptr_eq(&self.identity, &owner.identity)
    }
    pub fn raw_version(&self) -> u32 {
        self.raw_version
    }
    /// One shared quiet-policy predicate for source admission and running
    /// supervision. Raw readbacks and private owner identity bind PWM30;
    /// the mutable display percentage never selects a different fan policy.
    pub fn require_quiet_population(&self, quiet: &QuietFanSetting) -> Result<(), String> {
        if !Arc::ptr_eq(&self.identity, &quiet.identity)
            || quiet.registers != [(0x84, QUIET_WORD), (0xa0, QUIET_WORD)]
            || quiet.completed_at.elapsed() >= Duration::from_secs(1)
            || self.observed_from.elapsed() >= Duration::from_secs(1)
            || self.completed_at < self.observed_from
            || self.samples.len() != 8
        {
            return Err(
                "BM1396 quiet fan policy requires fresh same-owner PWM30/tach observations".into(),
            );
        }
        let readings: Vec<_> = self.samples.iter().map(|(_, reading)| *reading).collect();
        if !bm1396_fan_sample_passes(bm1396_quiet_fan_validation_policy(), &readings) {
            return Err("BM1396 quiet30 requires four distinct fresh fans at400RPM".into());
        }
        Ok(())
    }
    pub fn samples(&self) -> &[(u32, Bm1396FanTachReading)] {
        &self.samples
    }
    pub fn observed_from(&self) -> Instant {
        self.observed_from
    }
    pub fn completed_at(&self) -> Instant {
        self.completed_at
    }
}

impl<H: Hardware> Transport<H> {
    /// Fixed quiet30, including terminal operation. This confirms both command
    /// registers, not airflow, fan population or electrical source cutoff.
    pub async fn quiet_fans(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<QuietFanSetting, String> {
        self.worker(deadline, true, move |owner| {
            owner.quiet_fans_locked(deadline)
        })
        .await
    }

    pub(super) fn quiet_fans_locked(&self, deadline: Instant) -> Result<QuietFanSetting, String> {
        let _lane = self.lock(&self.fans, deadline, true)?;
        let mut registers = [(0, 0); 2];
        for (index, offset) in PWM_REGISTERS.into_iter().enumerate() {
            self.checked_store(offset, QUIET_WORD, deadline, true)?;
            registers[index] = (offset, QUIET_WORD);
        }
        self.check(deadline, true)?;
        Ok(QuietFanSetting {
            percent: BM1396_QUIET_FAN_PWM_PERCENT,
            identity: Arc::clone(&self.identity),
            registers,
            completed_at: Instant::now(),
        })
    }

    /// Eight source tach observations. Repeated IDs and zeros remain visible;
    /// no synthetic four-fan population or physical label is inferred.
    pub async fn sample_fan_tach(
        self: &Arc<Self>,
        deadline: Instant,
    ) -> Result<FanTachSnapshot, String> {
        self.worker(deadline, false, move |owner| {
            let _lane = owner.lock(&owner.fans, deadline, false)?;
            let observed_from = Instant::now();
            let raw_version = owner.hardware.read(0)?;
            let mut samples = Vec::with_capacity(8);
            for _ in 0..8 {
                owner.check(deadline, false)?;
                let raw = owner.hardware.read(4)?;
                samples.push((raw, bm1396_decode_fan_tach(raw_version, raw)));
            }
            owner.check(deadline, false)?;
            Ok(FanTachSnapshot {
                identity: owner.identity.clone(),
                raw_version,
                samples,
                observed_from,
                completed_at: Instant::now(),
            })
        })
        .await
    }
}
