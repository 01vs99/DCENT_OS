#![cfg(feature = "sim-hal")]

#[path = "sim_support/share_oracle.rs"]
mod share_oracle;

use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

struct ConfigFile(std::path::PathBuf);
impl ConfigFile {
    fn new(text: &str) -> Self {
        use std::io::Write;
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!("dcent-host-sim-{}-{}.toml",
            std::process::id(), NEXT.fetch_add(1, Ordering::SeqCst)));
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
        Self(path)
    }
}
impl Drop for ConfigFile {
    fn drop(&mut self) { std::fs::remove_file(&self.0).unwrap(); }
}

fn config(url: &str) -> String {
    format!("[mining]\nenabled = false\n[pool]\nurl = {url:?}\nworker = 'dcent.host.sim'\npassword = 'private-password-never-print'\n")
}

fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_dcentos-sim"));
    // This must not activate hardware setup or noisy credential logging.
    command.env("DCENT_SIM_HAL", "1").env("RUST_LOG", "trace")
        .env("DCENT_S19K_BOOTSTRAP_CONTRACT", "invalid-for-a-miner");
    command
}

#[test]
fn default_validates_real_config_without_connecting_to_configured_pool() {
    let source = config("stratum+tcp://192.0.2.1:1");
    let file = ConfigFile::new(&source);
    let output = command().args(["--config", file.0.to_str().unwrap(), "--timeout-seconds", "2"])
        .output().unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "{log}");
    assert!(log.contains("simulated work/nonce transport passed"));
    assert!(log.contains("configured_pool_probed=false"));
    assert!(!log.contains("private-password-never-print"));
    assert_eq!(std::fs::read_to_string(&file.0).unwrap(), source);
}

#[test]
fn malformed_config_and_duplicate_or_unbounded_arguments_fail() {
    let file = ConfigFile::new("[mining]\nenabled = false\nmisspelled_safety_setting = true\n");
    assert!(!command().args(["--config", file.0.to_str().unwrap()]).output().unwrap().status.success());
    for args in [vec!["--timeout-seconds", "31"], vec!["--probe-pool", "--probe-pool"], vec!["--timeout-seconds", "0"]] {
        assert!(!command().args(args).output().unwrap().status.success());
    }
}

#[tokio::test]
async fn explicit_pool_probe_authenticates_and_receives_job_without_submitting() {
    let (addr, pool) = share_oracle::OraclePool::spawn("dcent.host.sim").await;
    let file = ConfigFile::new(&config(&format!("stratum+tcp://{addr}")));
    let path = file.0.clone();
    let output = tokio::task::spawn_blocking(move || command()
        .args(["--config", path.to_str().unwrap(), "--probe-pool", "--timeout-seconds", "2"])
        .output().unwrap()).await.unwrap();
    let log = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(output.status.success(), "{log}");
    assert!(pool.requests().iter().any(|request| request.contains("mining.authorize")));
    assert!(!pool.requests().iter().any(|request| request.contains("mining.submit")));
    assert_eq!(pool.accepted_shares(), 0);
    assert!(!log.contains("private-password-never-print"));
}
