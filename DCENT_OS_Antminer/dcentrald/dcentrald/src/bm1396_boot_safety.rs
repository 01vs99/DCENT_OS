//! Exact S17e/T17e standalone GPIO cutoff and both source-defined quiet PWMs.
//! Independent R06 source binds GPIO907 high/off and FPGA+0x84/+0xa0.
//! It never exposes the parked mapping as a normal mining transport.
use anyhow::{Context, Result};
use dcentrald_hal::platform::stock_bm1396::{park_source_line, Model};
use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) const FLAG: &str = "--bm1396-boot-cut-only";
const OBSERVATION: &str = "/run/dcentos/bm1396-boot-cut.json";

pub(crate) fn requested(args: &[String]) -> Result<bool> {
    if !args.iter().any(|arg| arg == FLAG) {
        return Ok(false);
    }
    anyhow::ensure!(
        args.len() == 2 && args[1] == FLAG,
        "BM1396 boot source parking requires exactly one standalone flag"
    );
    Ok(true)
}

fn bounded_text(path: &str) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 64, "BM1396 boot identity exceeds its bound");
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

pub(crate) async fn run() -> Result<()> {
    let (target, boot) = tokio::task::spawn_blocking(|| -> Result<_> {
        match std::fs::remove_file(OBSERVATION) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
        Ok((
            bounded_text("/etc/dcentos/board_target")?,
            bounded_text("/proc/sys/kernel/random/boot_id")?,
        ))
    })
    .await
    .context("BM1396 boot identity worker")??;
    let model = match target.as_str() {
        "am2-s17e" => Model::S17e,
        "am2-t17e" => Model::T17e,
        _ => anyhow::bail!("BM1396 source parking requires an exact S17e/T17e target"),
    };
    let parked = park_source_line(model, Instant::now() + Duration::from_secs(5))
        .await
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        parked.observation().pin_high
            && parked.quiet_fans().percent == 30
            && parked.quiet_fans().registers() == [(0x84, 0x000f_0023), (0xa0, 0x000f_0023)],
        "BM1396 source high and both quiet PWM readbacks were not observed"
    );
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": 1, "kind": "source_gpio_high_observation", "boot_id": boot,
        "board_target": target, "gpio": 907, "raw_level": 1,
        "fan_pwm_percent": parked.quiet_fans().percent,
        "fan_pwm_registers": parked.quiet_fans().registers().map(|(offset, observed_word)|
            serde_json::json!({"offset": offset, "observed_word": observed_word})),
        "fan_airflow_measurement": false,
        "electrical_rail_measurement": false, "mining_admission": false,
    }))?;
    tokio::task::spawn_blocking(move || {
        // Keep the sealed terminal owner in this worker even if its caller
        // stops waiting while the atomic publication is still in progress.
        let _parked = parked;
        dcentrald_common::atomic_file::atomic_write(
            Path::new(OBSERVATION),
            &payload,
            dcentrald_common::atomic_file::AtomicWriteOptions::state_file(1024),
        )
        .map_err(|error| anyhow::anyhow!("BM1396 boot observation publication: {error:?}"))
    })
    .await
    .context("BM1396 boot observation worker")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_park_is_a_standalone_command_and_never_combines_with_mining_or_fan_flags() {
        let args = |values: &[&str]| {
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>()
        };
        assert!(requested(&args(&["dcentrald", FLAG])).unwrap());
        assert!(!requested(&args(&["dcentrald"])).unwrap());
        for tail in [
            FLAG,
            "--serial-mining",
            "--set-fan",
            "--get-fan",
            "--safe-off",
            "--config",
        ] {
            assert!(requested(&args(&["dcentrald", FLAG, tail])).is_err());
        }
        assert!(crate::unrecognized_cli_flags(&args(&["dcentrald", FLAG])).is_empty());
    }
}
