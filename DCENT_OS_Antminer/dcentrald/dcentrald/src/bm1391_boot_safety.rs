//! Standalone exact-source GPIO cut and quiet PWM before normal image services.
//! It never exposes the parked mapping as a normal mining transport.
use anyhow::{Context, Result};
use dcentrald_hal::platform::stock_bm1391::{park_source_line, Model};
use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) const FLAG: &str = "--bm1391-boot-cut-only";
const OBSERVATION: &str = "/run/dcentos/bm1391-boot-cut.json";

pub(crate) fn requested(args: &[String]) -> Result<bool> {
    if !args.iter().any(|arg| arg == FLAG) {
        return Ok(false);
    }
    anyhow::ensure!(
        args.len() == 2 && args[1] == FLAG,
        "BM1391 boot source parking requires exactly one standalone flag"
    );
    Ok(true)
}

fn bounded_text(path: &str) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 64, "BM1391 boot identity exceeds its bound");
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
    .context("BM1391 boot identity worker")??;
    let model = match target.as_str() {
        "am1-s15" => Model::S15,
        "am1-t15" => Model::T15,
        _ => anyhow::bail!("BM1391 source parking requires an exact S15/T15 target"),
    };
    let parked = park_source_line(model, Instant::now() + Duration::from_secs(5))
        .await
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        parked.observation().pin_high && parked.quiet_fans().percent == 30,
        "BM1391 source high and quiet PWM were not observed"
    );
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": 1, "kind": "source_gpio_high_observation", "boot_id": boot,
        "board_target": target, "gpio": 907, "raw_level": 1,
        "fan_pwm_percent": parked.quiet_fans().percent,
        "fan_pwm_register_word": parked.quiet_fans().register_word,
        "fan_airflow_measurement": false,
        "electrical_rail_measurement": false, "mining_admission": false,
    }))?;
    tokio::task::spawn_blocking(move || {
        dcentrald_common::atomic_file::atomic_write(
            Path::new(OBSERVATION),
            &payload,
            dcentrald_common::atomic_file::AtomicWriteOptions::state_file(1024),
        )
        .map_err(|error| anyhow::anyhow!("BM1391 boot observation publication: {error:?}"))
    })
    .await
    .context("BM1391 boot observation worker")??;
    drop(parked);
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
