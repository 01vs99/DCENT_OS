// SPDX-License-Identifier: GPL-3.0-or-later
//! Bind the boot-owned FPGA load to actual kernel clock observations.
//! The .bit header date is deliberately not treated as an MMIO BUILD_ID.

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Uncompressed SYSTEM.BIT.GZ from the exact admitted am2-s17 donor.
pub(super) const BITSTREAM_SHA256: &str =
    "4e2f7a0bb5d65b8f7ad43bea1290c8646c5f7b49321c768418bdfdc9e04afe22";
const RECEIPT_PATH: &str = "/run/dcentos/s17-fabric.json";
const CLOCK_PATHS: [&str; 2] = [
    "/sys/class/fclk/fclk0/set_rate",
    "/sys/kernel/debug/clk/fclk0/clk_rate",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootReceipt {
    schema: u32,
    boot_id: String,
    bitstream_sha256: String,
    load_completed: bool,
    prog_done: u8,
}

fn validate_receipt(bytes: &[u8], current_boot: &str) -> Result<()> {
    ensure!(
        bytes.len() <= 4096,
        "S17 fabric boot receipt exceeds size limit"
    );
    let receipt: BootReceipt = serde_json::from_slice(bytes)?;
    let boot = current_boot.trim();
    ensure!(
        boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "invalid kernel boot ID"
    );
    ensure!(
        receipt.schema == 1 && receipt.boot_id == boot,
        "S17 fabric receipt belongs to another boot"
    );
    ensure!(
        receipt.bitstream_sha256 == BITSTREAM_SHA256,
        "S17 loaded bitstream is not the admitted donor fabric"
    );
    ensure!(
        receipt.load_completed && receipt.prog_done == 1,
        "S17 FPGA programming completion was not observed"
    );
    Ok(())
}

fn read_rate(file: &mut File) -> Result<u64> {
    file.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    (&mut *file).take(65).read_to_string(&mut text)?;
    ensure!(
        text.len() <= 64,
        "S17 FCLK rate observation exceeds size limit"
    );
    let rate: u64 = text.trim().parse().context("invalid kernel FCLK0 rate")?;
    // Include integer rounding of the 33.333333 MHz PS reference clock.
    // Source-known 50/100 MHz families are checked from the actual kernel;
    // selecting one by VERSION alone is insufficient.
    ensure!(
        rate.abs_diff(50_000_000) <= 50_000 || rate.abs_diff(100_000_000) <= 100_000,
        "S17 FCLK0 rate {rate} is outside source-known clock families"
    );
    Ok(rate)
}

pub(crate) struct FabricIdentity {
    clocks: Vec<(PathBuf, File)>,
    clock_hz: u64,
    observed_build: Option<u32>,
}

impl FabricIdentity {
    pub(crate) fn open() -> Result<Self> {
        let mut receipt = Vec::new();
        File::open(RECEIPT_PATH)
            .context("S17 needs this boot's successful exact FPGA load receipt")?
            .take(4097)
            .read_to_end(&mut receipt)?;
        validate_receipt(
            &receipt,
            &std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
        )?;
        Self::open_clocks(CLOCK_PATHS.iter().map(Path::new))
    }

    fn open_clocks<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<Self> {
        let mut clocks = Vec::new();
        let mut observed = None;
        for path in paths {
            let mut file = match File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("cannot observe S17 fabric clock"),
            };
            let rate = read_rate(&mut file)?;
            if let Some(previous) = observed {
                ensure!(
                    previous == rate,
                    "kernel FCLK0 observation sources disagree"
                );
            }
            observed = Some(rate);
            clocks.push((path.to_owned(), file));
        }
        let clock_hz=observed.context("kernel FCLK0 observation is unavailable; boot must export the read-only observation node")?;
        let mut identity = Self {
            clocks,
            clock_hz,
            observed_build: None,
        };
        identity.verify_clock_unchanged()?;
        Ok(identity)
    }

    pub(super) fn observe_chain(&mut self, version: u32, build: u32) -> Result<()> {
        ensure!(
            version == 0x0090_1002,
            "S17 FPGA work ABI version mismatch: {version:#010x}"
        );
        ensure!(
            build != 0 && build != u32::MAX,
            "S17 FPGA BUILD_ID is unobservable"
        );
        if let Some(previous) = self.observed_build {
            ensure!(
                previous == build,
                "S17 physical chains expose different FPGA builds"
            );
        }
        self.observed_build = Some(build);
        Ok(())
    }

    pub(super) fn verify_clock_unchanged(&mut self) -> Result<()> {
        for (path, file) in &mut self.clocks {
            ensure!(
                read_rate(file)? == self.clock_hz,
                "S17 fabric clock changed while retained: {}",
                path.display()
            );
        }
        Ok(())
    }

    pub(super) fn work_time(&self, frequency_mhz: u16) -> u32 {
        // RTL counter uses its actual AXI/FCLK source; four midstates and
        // 90% nonce-space coverage. Keep calculation in Hz, not assumed MHz.
        ((0.9 * 4.0 * 524288.0 * self.clock_hz as f64) / (f64::from(frequency_mhz) * 1_000_000.0))
            as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s17_fabric_requires_exact_loaded_payload_current_boot_and_completion() {
        let boot = "12345678-1234-1234-1234-123456789abc";
        let valid = serde_json::json!({"schema":1,"boot_id":boot,"bitstream_sha256":BITSTREAM_SHA256,"load_completed":true,"prog_done":1});
        assert!(validate_receipt(&serde_json::to_vec(&valid).unwrap(), boot).is_ok());
        for (key, value) in [
            ("schema", serde_json::json!(2)),
            (
                "boot_id",
                serde_json::json!("87654321-1234-1234-1234-123456789abc"),
            ),
            ("bitstream_sha256", serde_json::json!("0".repeat(64))),
            ("load_completed", serde_json::json!(false)),
            ("prog_done", serde_json::json!(0)),
        ] {
            let mut wrong = valid.clone();
            wrong[key] = value;
            assert!(
                validate_receipt(&serde_json::to_vec(&wrong).unwrap(), boot).is_err(),
                "{key}"
            );
        }
    }

    #[test]
    fn s17_fabric_clock_is_observed_retained_and_changes_work_duration() {
        let root = std::env::temp_dir().join(format!(
            "s17-clock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("set_rate");
        std::fs::write(&path, "50000000\n").unwrap();
        let mut clock = FabricIdentity::open_clocks([path.as_path()]).unwrap();
        assert_eq!(clock.work_time(100), 943718);
        clock.observe_chain(0x00901002, 0x63848b7b).unwrap();
        clock.observe_chain(0x00901002, 0x63848b7b).unwrap();
        assert!(clock.observe_chain(0x00901002, 0x5fca4c6e).is_err());
        std::fs::write(&path, "100000000\n").unwrap();
        assert!(clock.verify_clock_unchanged().is_err());
        let clock = FabricIdentity::open_clocks([path.as_path()]).unwrap();
        assert_eq!(clock.work_time(100), 1887436);
        std::fs::write(&path, "0\n").unwrap();
        assert!(FabricIdentity::open_clocks([path.as_path()]).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
