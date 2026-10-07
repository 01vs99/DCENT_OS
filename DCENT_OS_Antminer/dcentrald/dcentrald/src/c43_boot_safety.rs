//! Exact C43 reset/PIC-off and quiet PWM before default-disabled image services.
//! It never exposes the parked mapping as a normal mining transport.
use anyhow::{Context, Result};
use dcentrald_hal::platform::c43_bm1393::transport::park_boot_source;
use std::{
    io::Read,
    path::Path,
    time::{Duration, Instant},
};

pub(crate) const FLAG: &str = "--c43-boot-cut-only";
const OBSERVATION: &str = "/run/dcentos/c43-boot-cut.json";

pub(crate) fn requested(args: &[String]) -> Result<bool> {
    if !args.iter().any(|arg| arg == FLAG) {
        return Ok(false);
    }
    anyhow::ensure!(
        args.len() == 2 && args[1] == FLAG,
        "C43 boot source parking requires exactly one standalone flag"
    );
    Ok(true)
}

fn bounded_text(path: &str) -> Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 64, "C43 boot identity exceeds its bound");
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
    .context("C43 boot identity worker")??;
    anyhow::ensure!(
        matches!(target.as_str(), "am1-s9se" | "am1-s9k"),
        "C43 boot parking requires exact S9 SE/S9k identity"
    );
    let parked = park_boot_source(Instant::now() + Duration::from_secs(12))
        .await
        .map_err(anyhow::Error::msg)?;
    anyhow::ensure!(
        parked.quiet_pwm_word() == 0x000f_0023,
        "C43 post-cut quiet PWM was not observed"
    );
    let payload = serde_json::to_vec(&serde_json::json!({
        "schema": 1, "kind": "c43_present_reset_pic_off_and_quiet_observation", "boot_id": boot,
        "board_target": target, "present_chains": parked.present_chains(),
        "observed_empty_population": parked.present_chains().is_empty(),
        "reset_pic_off_for_present_chains": true,
        "fan_pwm_percent": 30, "fan_pwm_register_offset": 0x84,
        "fan_pwm_register_word": parked.quiet_pwm_word(),
        "fan_airflow_measurement": false,
        "electrical_rail_measurement": false, "mining_admission": false,
    }))?;
    tokio::task::spawn_blocking(move || {
        // Publication retains the parked owner if its caller is cancelled.
        let _parked = parked;
        dcentrald_common::atomic_file::atomic_write(
            Path::new(OBSERVATION),
            &payload,
            dcentrald_common::atomic_file::AtomicWriteOptions::state_file(1024),
        )
        .map_err(|error| anyhow::anyhow!("C43 boot observation publication: {error:?}"))
    })
    .await
    .context("C43 boot observation worker")??;
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
