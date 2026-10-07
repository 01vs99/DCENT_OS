#![cfg(feature = "sim-hal")]

#[path = "sim_support/share_oracle.rs"]
mod share_oracle;

use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn probe(url: &str) -> Output {
    use std::io::Write;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Config(std::path::PathBuf);
    impl Drop for Config {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).unwrap();
        }
    }
    let config = Config(std::env::temp_dir().join(format!(
        "dcent-probe-refusal-{}-{}.toml",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&config.0)
        .unwrap();
    write!(file, "[mining]\nenabled=false\n[pool]\nurl={url:?}\nworker='probe.worker'\npassword='do-not-log-this-secret'\n").unwrap();
    drop(file);
    let mut child = Command::new(env!("CARGO_BIN_EXE_dcentos-sim"))
        .args([
            "--config",
            config.0.to_str().unwrap(),
            "--probe-pool",
            "--timeout-seconds",
            "1",
        ])
        .env("RUST_LOG", "trace")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("host probe ignored its one-second deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn assert_refused(output: Output) {
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{message}");
    assert!(message.contains("Preflight failed"), "{message}");
    assert!(!message.contains("simulated work/nonce transport passed"));
    assert!(!message.contains("do-not-log-this-secret"));
}

#[tokio::test]
async fn rejected_authorization_cannot_pass_even_if_the_pool_sends_a_job() {
    // This oracle sends a notify after authorize even when the worker is wrong.
    let (address, pool) = share_oracle::OraclePool::spawn("different.worker").await;
    let output = tokio::task::spawn_blocking(move || probe(&format!("stratum+tcp://{address}")))
        .await
        .unwrap();
    assert_refused(output);
    assert!(pool
        .requests()
        .iter()
        .any(|request| request.contains("mining.authorize")));
    assert!(!pool
        .requests()
        .iter()
        .any(|request| request.contains("mining.submit")));
}

#[tokio::test]
async fn silent_pool_expires_without_detached_probe_or_share_submission() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let began = Instant::now();
    let child = tokio::task::spawn_blocking(move || probe(&format!("stratum+tcp://{address}")));
    let (mut stream, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .unwrap()
        .unwrap();
    let output = tokio::time::timeout(Duration::from_secs(5), child)
        .await
        .unwrap()
        .unwrap();
    assert_refused(output);
    assert!(began.elapsed() < Duration::from_secs(5));
    let mut requests = String::new();
    tokio::time::timeout(Duration::from_secs(1), stream.read_to_string(&mut requests))
        .await
        .unwrap()
        .unwrap();
    assert!(!requests.contains("mining.submit"));
}

#[test]
fn unsupported_pool_protocol_is_refused_before_connecting() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    assert_refused(probe(&format!(
        "stratum2+tcp://{}",
        listener.local_addr().unwrap()
    )));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
