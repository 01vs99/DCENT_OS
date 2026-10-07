//! Host-only configuration and pool preflight. Never opens miner hardware.
//! Config/model modules are the exact daemon sources; no second TOML schema.
#![allow(dead_code)]

#[path = "../autotune/mod.rs"]
mod autotune;
#[path = "../config.rs"]
mod config;
#[path = "../model.rs"]
mod model;

use anyhow::{bail, ensure, Context, Result};
use dcentrald_hal::fpga_chain::FpgaChain;
use dcentrald_hal::platform::sim::SimNoncePolicy;
use dcentrald_stratum::{MiningWork, StratumV1Client, WorkBuilder};
use dcentrald_stratum::v1::mock_pool::{MockV1Pool, MockV1PoolHandle};
use std::time::Duration;
use tokio::sync::mpsc;

const HELP: &str = "dcentos-sim --config PATH [--probe-pool] [--timeout-seconds 1..30]\n\
Validates the exact daemon configuration and exercises memory-backed work/nonce transport.\n\
Default: an isolated loopback pool; configured pool credentials are not sent.\n\
--probe-pool: explicitly connects to the configured primary Stratum V1 pool and\n\
checks authorization plus its first valid job. No shares are submitted.\n\
This does not test PSU, hashboard initialization, electrical safety, or real hashing.\n\
Support development: https://d-central.tech/fund/";

struct Options {
    config_path: String,
    probe_pool: bool,
    timeout: Duration,
}

fn options(args: impl Iterator<Item = String>) -> Result<Options> {
    let mut args = args.peekable();
    let mut config_path = None;
    let mut probe_pool = false;
    let mut timeout = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" if config_path.is_none() => config_path = Some(args.next().context("--config needs a path")?),
            "--probe-pool" if !probe_pool => probe_pool = true,
            "--timeout-seconds" if timeout.is_none() => {
                let seconds: u64 = args.next().context("missing timeout")?.parse()?;
                ensure!((1..=30).contains(&seconds), "timeout must be between 1 and 30 seconds");
                timeout = Some(Duration::from_secs(seconds));
            }
            _ => bail!("unknown or duplicate argument: {arg}"),
        }
    }
    Ok(Options {
        config_path: config_path.context("--config PATH is required")?,
        probe_pool,
        timeout: timeout.unwrap_or(Duration::from_secs(10)),
    })
}

async fn first_work(mut pool: dcentrald_stratum::types::StratumConfig, timeout: Duration) -> Result<MiningWork> {
    // One selected endpoint, no secondary route or donation connection. The
    // sender is held but never receives a share from this preflight binary.
    pool.pool2 = None;
    pool.pool3 = None;
    pool.routing_mode = "failover".into();
    let (job_tx, mut job_rx) = mpsc::channel(2);
    let (_share_tx, share_rx) = mpsc::channel(1);
    let (status_tx, _status_rx) = mpsc::channel(32);
    let client = StratumV1Client::new(pool, job_tx, share_rx, status_tx);
    let run = client.run_until_sv2_retry(timeout);
    tokio::pin!(run);
    // Dropping run closes the connection on either completion or timeout; no
    // detached reconnect task survives the result.
    let job = tokio::time::timeout(timeout, async {
        tokio::select! {
            job = job_rx.recv() => job.context("pool closed before supplying a valid job"),
            _ = &mut run => Err(anyhow::anyhow!("pool session ended before supplying a valid job")),
        }
    }).await.context("pool authorization/job deadline expired")??;
    WorkBuilder::new().next_work(&job).map_err(Into::into)
}

fn transport_round_trip(work: &MiningWork) -> Result<()> {
    // A transport smoke test, deliberately not ASIC initialization or a
    // simulated accepted share. Only explicit Vec-backed FPGA constructors.
    let chain = FpgaChain::open_sim(0)?;
    chain.set_sim_nonce_policy(SimNoncePolicy::Valid)?;
    chain.set_sim_next_nonce(0x1357_2468)?;
    let mut bytes = [0; 80];
    bytes[..4].copy_from_slice(&work.version.to_le_bytes());
    bytes[4..36].copy_from_slice(&work.prev_block_hash);
    bytes[36..68].copy_from_slice(&work.merkle_root);
    bytes[68..72].copy_from_slice(&work.ntime.to_le_bytes());
    bytes[72..76].copy_from_slice(&work.nbits.to_le_bytes());
    let words: Vec<u32> = bytes.chunks_exact(4)
        .map(|word| u32::from_le_bytes(word.try_into().expect("four bytes"))).collect();
    chain.write_work(&words);
    ensure!(chain.read_nonce().map(|result| result.0) == Some(0x1357_2468), "simulator nonce byte order mismatch");
    ensure!(chain.read_nonce().is_none(), "simulator returned an unrequested nonce");
    Ok(())
}

async fn run(options: Options) -> Result<()> {
    let config = config::DcentraldConfig::load(&options.config_path)?;
    let mut pool = config::build_stratum_config(&config, config::disabled_stratum_donation_config(), false, false);
    let loopback;
    if options.probe_pool {
        ensure!(config.has_configured_pool(), "primary pool URL and worker must be configured");
        let protocol = config.pool.protocol.as_deref().unwrap_or("v1");
        ensure!(matches!(protocol, "v1" | "sv1") && config.pool.sv2_url.is_none(),
            "pool probing currently supports an explicit Stratum V1 primary endpoint");
        dcentrald_stratum::url_validator::validate_v1_pool_url(&pool.pool1.url)
            .map_err(|_| anyhow::anyhow!("primary pool must be a valid Stratum V1 URL"))?;
    } else {
        let (addr, handle) = MockV1Pool::spawn().await?;
        loopback = handle;
        pool.pool1.url = MockV1PoolHandle::url(addr);
        pool.pool1.worker = "dcent.sim.preflight".into();
        pool.pool1.password = "x".into();
        pool.pool1.sv2_url = None;
        // Keep the isolated server alive until the socket has closed.
        let _ = &loopback;
    }
    pool.protocol = Some("v1".into());
    pool.pool1.protocol = Some("v1".into());
    let work = first_work(pool, options.timeout).await?;
    transport_round_trip(&work)?;
    tracing::info!(configured_pool_probed = options.probe_pool,
        "Configuration valid; simulated work/nonce transport passed; no shares submitted");
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    // Never consume RUST_LOG: verbose protocol logs can contain credentials.
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).with_target(false).with_ansi(false).init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.as_slice() == ["--help"] || args.as_slice() == ["-h"] {
        tracing::info!("{HELP}");
        return std::process::ExitCode::SUCCESS;
    }
    let result = match options(args.into_iter()) {
        Ok(options) => run(options).await,
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!("Preflight failed: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}
