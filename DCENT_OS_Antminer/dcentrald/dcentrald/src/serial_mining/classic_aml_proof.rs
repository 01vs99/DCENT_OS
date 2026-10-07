//! Read-only boot-verifier evidence from the retained classic application.
//! This file never grants hardware mutation or watchdog disarm authority.
//! Freshness matches the existing five-second HAL health contract; a full
//! three-board source-paced scan alone requires at least3.35seconds.
use super::super::*;
use dcentrald_hal::platform::amlogic::classic_pic::ClassicHealth;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) const PATH: &str = "/run/dcentos/classic-aml-application.json";

fn monotonic_ms() -> Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: the writable timespec is valid for this read-only clock query.
    anyhow::ensure!(
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut time) } == 0,
        "classic proof monotonic query failed"
    );
    Ok(u64::try_from(time.tv_sec)? * 1000 + u64::try_from(time.tv_nsec)? / 1_000_000)
}

pub(super) fn publish(
    health: &ClassicHealth,
    chains: &[u8],
    active: impl Fn() -> bool,
) -> Result<()> {
    publish_at(Path::new(PATH), health, chains, active)
}

fn publish_at(
    path: &Path,
    health: &ClassicHealth,
    chains: &[u8],
    active: impl Fn() -> bool,
) -> Result<()> {
    anyhow::ensure!(
        !chains.is_empty()
            && chains.len() <= 3
            && chains.windows(2).all(|w| w[0] < w[1])
            && chains.iter().all(|c| (1..=3).contains(c))
            && health
                .voltages
                .iter()
                .map(|v| v.chain)
                .eq(chains.iter().copied()),
        "classic application proof must cover the exact retained population"
    );
    let parent = path.parent().context("classic proof directory missing")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    anyhow::ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0,
        "classic proof requires a protected root-owned runtime directory"
    );
    let observed_age = u64::try_from(health.observed_from.elapsed().as_millis())?;
    anyhow::ensure!(
        active() && observed_age < 5000,
        "classic proof sample is stale or terminal"
    );
    let observed_monotonic_ms = monotonic_ms()?
        .checked_sub(observed_age)
        .context("classic proof clock underflow")?;
    let process = std::fs::read_to_string("/proc/self/stat")?;
    let start_ticks = process
        .rsplit_once(')')
        .context("classic proof process stat malformed")?
        .1
        .split_whitespace()
        .nth(19)
        .context("classic proof process start missing")?
        .parse::<u64>()?;
    let proof = serde_json::json!({
        "schema": 1, "producer": "classic_aml_native", "board_target": "am3-s19jpro-aml",
        "boot_id": std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim(),
        "producer_pid": std::process::id(), "producer_start_ticks": start_ticks,
        "physical_chains": chains, "admitted_application_fw": "0x89",
        "observed_monotonic_ms": observed_monotonic_ms,
        "evidence": "retained fw89 admission with current complete PIC/thermal/rail/fan health"
    });
    let temporary = path.with_extension(format!("pending-{}", std::process::id()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    struct Pending(std::path::PathBuf);
    impl Drop for Pending {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _pending = Pending(temporary.clone());
    file.write_all(&serde_json::to_vec(&proof)?)?;
    file.write_all(b"\n")?;
    drop(file);
    anyhow::ensure!(
        active() && health.observed_from.elapsed() < Duration::from_secs(5),
        "classic proof expired or stopped before atomic publication"
    );
    std::fs::rename(temporary, path)?;
    Ok(())
}

pub(super) fn remove() -> Result<()> {
    match std::fs::remove_file(PATH) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn atomic_owner_proof_refuses_stale_partial_or_terminal_health() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory =
            std::env::temp_dir().join(format!("classic-proof-{}-{unique}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("proof.json");
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(self.0.join("proof.json"));
                let _ = std::fs::remove_file(
                    self.0.join(format!("proof.pending-{}", std::process::id())),
                );
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let _cleanup = Cleanup(directory);
        let mut health = ClassicHealth {
            temperatures: vec![],
            fans: vec![],
            voltages: vec![
                dcentrald_hal::platform::amlogic::classic_pic::ClassicVoltage {
                    chain: 2,
                    raw_be: [0, 0],
                    volts: 13.7,
                },
            ],
            observed_from: Instant::now(),
            completed_at: Instant::now(),
        };
        assert!(publish_at(&path, &health, &[1, 2], || true).is_err());
        assert!(publish_at(&path, &health, &[2], || false).is_err());
        assert!(!path.exists());
        // A three-board scan has at least3.35s of source-mandated waits.
        // Preserve that original age instead of substituting completion time.
        health.observed_from -= Duration::from_millis(3500);
        publish_at(&path, &health, &[2], || true).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let proof: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(proof["physical_chains"], serde_json::json!([2]));
        assert_eq!(proof["admitted_application_fw"], "0x89");
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        health.observed_from -= Duration::from_secs(6);
        assert!(publish_at(&path, &health, &[2], || true).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
