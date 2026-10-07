// SPDX-License-Identifier: GPL-3.0-or-later
//! This boot's verified FPGA load and retained kernel clock observations.

use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

// build_sd_s19pro.sh's admitted donor, uncompressed SYSTEM.BIT.GZ.
const BITSTREAM_SHA256: &str = "4e2f7a0bb5d65b8f7ad43bea1290c8646c5f7b49321c768418bdfdc9e04afe22";
const CLOCK_PATHS: [&str; 2] = [
    "/sys/class/fclk/fclk0/set_rate",
    "/sys/kernel/debug/clk/fclk0/clk_rate",
];

#[derive(Deserialize)]
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
        "BM1398 boot receipt exceeds size limit"
    );
    let receipt: BootReceipt = serde_json::from_slice(bytes)?;
    let boot = current_boot.trim();
    ensure!(
        boot.len() == 36 && boot.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "invalid kernel boot ID"
    );
    ensure!(
        receipt.schema == 1 && receipt.boot_id == boot,
        "BM1398 FPGA load belongs to another boot"
    );
    ensure!(
        receipt.bitstream_sha256 == BITSTREAM_SHA256
            && receipt.load_completed
            && receipt.prog_done == 1,
        "BM1398 boot did not complete the admitted FPGA load"
    );
    Ok(())
}

fn read_clock(file: &mut File) -> Result<u64> {
    file.seek(SeekFrom::Start(0))?;
    let mut text = String::new();
    (&mut *file).take(65).read_to_string(&mut text)?;
    ensure!(text.len() <= 64, "BM1398 kernel clock observation too long");
    let rate: u64 = text
        .trim()
        .parse()
        .context("invalid kernel FCLK0 observation")?;
    // Permit PS reference clock integer rounding; reject the distinct 50MHz
    // family even though it exposes the very same VERSION register.
    ensure!(
        rate.abs_diff(100_000_000) <= 100_000,
        "BM1398 requires observed 100MHz FCLK0, got {rate}"
    );
    Ok(rate)
}

pub(super) struct FabricIdentity {
    clocks: Vec<File>,
    clock_hz: u64,
    observed_build: Option<u32>,
}
impl FabricIdentity {
    pub(super) fn open() -> Result<Self> {
        let mut bytes = Vec::new();
        File::open("/run/dcentos/bm1398-fabric.json")
            .context("BM1398 needs this boot's verified FPGA load")?
            .take(4097)
            .read_to_end(&mut bytes)?;
        validate_receipt(
            &bytes,
            &std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?,
        )?;
        Self::open_clocks(CLOCK_PATHS.iter().map(Path::new))
    }

    fn open_clocks<'a>(paths: impl IntoIterator<Item = &'a Path>) -> Result<Self> {
        let mut clocks = Vec::new();
        let mut clock_hz = None;
        for path in paths {
            let mut file = match File::open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error).context("cannot observe BM1398 FCLK0"),
            };
            let rate = read_clock(&mut file)?;
            ensure!(
                clock_hz.is_none_or(|old| old == rate),
                "BM1398 kernel clock sources disagree"
            );
            clock_hz = Some(rate);
            clocks.push(file);
        }
        Ok(Self {
            clocks,
            clock_hz: clock_hz.context("kernel FCLK0 observation unavailable")?,
            observed_build: None,
        })
    }

    pub(super) fn observe_build(&mut self, build: u32) -> Result<()> {
        ensure!(
            self.observed_build.is_none_or(|old| old == build),
            "BM1398 chains expose different FPGA builds"
        );
        self.observed_build = Some(build);
        Ok(())
    }

    pub(super) fn verify_unchanged(&mut self) -> Result<()> {
        for clock in &mut self.clocks {
            ensure!(
                read_clock(clock)? == self.clock_hz,
                "BM1398 FCLK0 changed during custody"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn boot_load_and_clock_observations_are_required_and_retained() {
        let boot = "12345678-1234-1234-1234-123456789abc";
        let valid = serde_json::json!({"schema":1,"boot_id":boot,"bitstream_sha256":BITSTREAM_SHA256,"load_completed":true,"prog_done":1});
        assert!(validate_receipt(&serde_json::to_vec(&valid).unwrap(), boot).is_ok());
        let mut incomplete = valid.clone();
        incomplete["load_completed"] = serde_json::json!(false);
        assert!(validate_receipt(&serde_json::to_vec(&incomplete).unwrap(), boot).is_err());
        assert!(validate_receipt(
            &serde_json::to_vec(&valid).unwrap(),
            "87654321-1234-1234-1234-123456789abc"
        )
        .is_err());
        let path = std::env::temp_dir().join(format!(
            "bm1398-clock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&path, "100000000\n").unwrap();
        let mut clock = FabricIdentity::open_clocks([path.as_path()]).unwrap();
        clock.observe_build(0x63848b7b).unwrap();
        clock.observe_build(0x63848b7b).unwrap();
        assert!(clock.observe_build(0x5fca4c6e).is_err());
        clock.verify_unchanged().unwrap();
        std::fs::write(&path, "50000000\n").unwrap();
        assert!(clock.verify_unchanged().is_err());
        assert!(FabricIdentity::open_clocks([path.as_path()]).is_err());
        std::fs::write(&path, "99999000\n").unwrap();
        FabricIdentity::open_clocks([path.as_path()])
            .unwrap()
            .verify_unchanged()
            .unwrap();
        std::fs::remove_file(path).unwrap();
    }
}
