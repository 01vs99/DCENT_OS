//! Read-only API projection of actual native observations. No actuator or
//! readiness authority is produced by these display updates.
use super::dispatch::{DispatchPhase, DispatchProgress};
use anyhow::{ensure, Result};
use dcentrald_api::{ChainState, ChainTempSource, MinerState, PerFanReading};
use dcentrald_hal::platform::stock_bm1396::{
    FanTachSnapshot, NativePllObservation, QuietFanSetting, ThermalSnapshot,
};
use std::{collections::BTreeMap, time::Instant};
use tokio::sync::watch;

pub(super) fn fans(
    state: &watch::Sender<MinerState>,
    setting: &QuietFanSetting,
    observed: &FanTachSnapshot,
    started: Instant,
) {
    let mut latest = BTreeMap::new();
    for (_, sample) in observed.samples() {
        latest.insert(sample.fan_id, sample.rpm);
    }
    state.send_modify(|state| {
        state.fans.pwm = setting.percent;
        state.fans.per_fan = latest
            .iter()
            .map(|(&id, &rpm)| PerFanReading {
                id,
                rpm,
                pwm_percent: setting.percent,
            })
            .collect();
        state.fans.rpm = latest.values().next().copied().unwrap_or(0);
        state.uptime_s = started.elapsed().as_secs();
    });
}

pub(super) fn final_profile(
    state: &watch::Sender<MinerState>,
    chains: &[u8],
    actual: &NativePllObservation,
) -> Result<()> {
    ensure!(
        actual.completed_at().is_some()
            && actual.failure().is_none()
            && actual.completed_frequency_mhz().is_some(),
        "BM1396 API profile lacks actual final completion"
    );
    state.send_modify(|state| {
        state.chains = chains
            .iter()
            .map(|&id| ChainState {
                id,
                chips: actual.model().expected_chips_per_present_chain() as u8,
                frequency_mhz: actual.completed_frequency_mhz().expect("completed profile"),
                // No independent physical PSU voltage/validated work-rate unit is
                // synthesized from a commanded DAC or FPGA ticket literal0f.
                voltage_mv: 0,
                temp_c: 0.0,
                temp_source: None,
                hashrate_ghs: 0.0,
                errors: 0,
                status: "qualifying".into(),
            })
            .collect();
    });
    Ok(())
}

pub(super) fn temperatures(
    state: &watch::Sender<MinerState>,
    actual: &ThermalSnapshot,
    epoch: u64,
) -> Result<()> {
    ensure!(
        actual.epoch() == epoch
            && actual.is_fresh_at(Instant::now())
            && actual
                .samples()
                .iter()
                .all(|s| s.epoch() == epoch && !s.is_historical()),
        "BM1396 API current thermal receipt stale or historical"
    );
    let mut maximum = BTreeMap::<u8, i16>::new();
    for sample in actual.samples() {
        for (raw, value) in sample
            .raw_channels()
            .into_iter()
            .zip(sample.temperatures_c(actual.sampling_mode()))
        {
            if raw != 0 {
                maximum
                    .entry(sample.register().chain_slot)
                    .and_modify(|old| *old = (*old).max(value))
                    .or_insert(value);
            }
        }
    }
    state.send_modify(|state| {
        for chain in &mut state.chains {
            if let Some(&value) = maximum.get(&chain.id) {
                chain.temp_c = f32::from(value);
                chain.temp_source = Some(ChainTempSource::BOARD_SENSOR.into());
            }
        }
    });
    Ok(())
}

pub(super) fn progress(state: &watch::Sender<MinerState>, actual: &DispatchProgress) {
    state.send_modify(|state| {
        state.accepted = actual.accepted_shares;
        state.rejected = actual.rejected_shares;
        state.pool.status = match actual.connection {
            dcentrald_stratum::types::StratumState::Disconnected => "disconnected",
            dcentrald_stratum::types::StratumState::Connecting => "connecting",
            dcentrald_stratum::types::StratumState::Authorized => "authorized",
            dcentrald_stratum::types::StratumState::Mining => "mining",
            dcentrald_stratum::types::StratumState::Donating => "donating",
            dcentrald_stratum::types::StratumState::AuthFailed => "auth_failed",
        }
        .into();
        if let Some(value) = actual.pool_difficulty {
            state.pool.difficulty = value;
        }
        if let Some(value) = actual.latency_ms {
            state.pool.latency_ms = value;
            state.pool.latency_ms_source =
                Some(dcentrald_api::PoolQualitySource::STRATUM_STATUS.into());
        }
        if let Some(value) = actual.last_accepted_at {
            state.pool.last_share_at = value;
        }

        for chain in &mut state.chains {
            chain.status = match actual.phase {
                DispatchPhase::FirstProbe | DispatchPhase::SecondProbe => "qualifying",
                DispatchPhase::WaitingForPool => "waiting for pool",
                DispatchPhase::PoolWork => "mining",
            }
            .into();
        }
    });
}

pub(super) fn stopped(state: &watch::Sender<MinerState>) {
    state.send_modify(|state| {
        state.hashrate_ghs = 0.0;
        state.hashrate_5s_ghs = 0.0;
        state.pool.status = "stopped".into();
        for chain in &mut state.chains {
            chain.status = "stopped".into();
            chain.hashrate_ghs = 0.0;
        }
    });
}
