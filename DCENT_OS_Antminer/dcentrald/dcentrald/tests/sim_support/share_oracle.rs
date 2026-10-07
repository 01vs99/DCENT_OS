//! Independent validation of the exact deterministic loopback pool job.
//! The scalar F04 oracle has no dependency on production hashing or WorkBuilder.

#[path = "../f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::{stratum_coinbase_hash, BlockHeader};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

pub const JOB_ID: &str = "dcent-genesis-0";
pub const NTIME: &str = "495fab29";
pub const VERSION_MASK: u32 = 0x1fff_e000;

fn coinb1() -> String {
    // The extranonce splice must be entirely inside the coinbase scriptSig.
    // Its original 04ffff00 prefix becomes extranonce1=04ffff and the first
    // one-byte extranonce2=00, preserving Bitcoin's exact genesis transaction.
    format!("0100000001{}ffffffff4d", "00".repeat(32))
}

fn coinb2() -> String {
    concat!(
        "1d010445",
        "5468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e20",
        "6272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73",
        "ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909",
        "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"
    ).to_string()
}

pub fn target() -> [u8; 32] {
    // Stratum pool difficulty 1: 2^224 - 1 (distinct from block nbits).
    let mut target = [0xff; 32];
    target[..4].fill(0);
    target
}

pub fn header(extranonce2: &str, nonce: u32) -> Option<BlockHeader> {
    if extranonce2.len() != 2 {
        return None;
    }
    let extranonce2 = hex::decode(extranonce2).ok()?;
    // These are the pool's literal notify/subscribe fields, deliberately
    // independent of the client's parsed Job and generated MiningWork.
    let coinb1 = hex::decode(coinb1()).ok()?;
    let coinb2 = hex::decode(coinb2()).ok()?;
    let merkle = stratum_coinbase_hash(&coinb1, &[0x04, 0xff, 0xff], &extranonce2, &coinb2);
    let mut wire = [0; 80];
    wire[..4].copy_from_slice(&1_u32.to_le_bytes());
    wire[36..68].copy_from_slice(&merkle);
    wire[68..72].copy_from_slice(&1_231_006_505_u32.to_le_bytes());
    wire[72..76].copy_from_slice(&0x1d00_ffff_u32.to_le_bytes());
    wire[76..80].copy_from_slice(&nonce.to_le_bytes());
    BlockHeader::from_wire(&wire).ok()
}

pub fn winning_nonce(extranonce2: &str) -> u32 {
    assert_eq!(extranonce2, "00");
    let nonce = 2_083_236_893;
    let genesis = header(extranonce2, nonce).expect("literal loopback job");
    assert_eq!(
        hex::encode(genesis.display_hash()),
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    );
    assert!(genesis.display_hash() <= target());
    nonce
}

/// This pool accepts only an independently valid serialized share of its
/// actual notification. It has one bounded loopback connection and no proxy,
/// remote endpoint, ambient credentials, or arbitrary accept-all policy.
pub struct OraclePool {
    accepted: Arc<AtomicU64>,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl OraclePool {
    pub async fn spawn(worker: &str) -> (std::net::SocketAddr, Self) {
        Self::spawn_with_timeout(worker, std::time::Duration::from_secs(5)).await
    }

    pub async fn spawn_with_timeout(
        worker: &str,
        lifetime: std::time::Duration,
    ) -> (std::net::SocketAddr, Self) {
        Self::spawn_with_options(worker, lifetime, None).await
    }

    pub async fn spawn_version_rolling(worker: &str) -> (std::net::SocketAddr, Self) {
        Self::spawn_with_options(
            worker,
            std::time::Duration::from_secs(5),
            Some(VERSION_MASK),
        )
        .await
    }

    async fn spawn_with_options(
        worker: &str,
        lifetime: std::time::Duration,
        version_mask: Option<u32>,
    ) -> (std::net::SocketAddr, Self) {
        assert!(
            (std::time::Duration::from_secs(1)..=std::time::Duration::from_secs(300))
                .contains(&lifetime),
            "loopback oracle lifetime must be1..300 seconds"
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicU64::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let count = accepted.clone();
        let captured = requests.clone();
        let worker = worker.to_string();
        let task = tokio::spawn(async move {
            let serving = async {
                let (stream, _) = listener.accept().await.unwrap();
                let (reader, mut writer) = stream.into_split();
                let mut lines = BufReader::new(reader.take(65_536)).lines();
                while let Some(line) = lines.next_line().await.unwrap() {
                    captured.lock().unwrap().push(line.clone());
                    let message: Value = serde_json::from_str(&line).unwrap();
                    let method = message["method"].as_str().unwrap_or_default();
                    let result = match method {
                        "mining.configure" => match version_mask {
                            Some(mask) => {
                                json!({"version-rolling":true,"version-rolling.mask":format!("{mask:08x}")})
                            }
                            None => json!({"version-rolling":false}),
                        },
                        "mining.subscribe" => json!([[], "04ffff", 1]),
                        "mining.authorize" => json!(message["params"][0] == worker),
                        "mining.submit" => {
                            let valid =
                                accepts_submission_with_mask(&message, &worker, version_mask);
                            if valid {
                                count.fetch_add(1, Ordering::SeqCst);
                            }
                            json!(valid)
                        }
                        _ => json!(true),
                    };
                    let reply = json!({"id":message["id"], "result":result, "error":null});
                    writer
                        .write_all(format!("{reply}\n").as_bytes())
                        .await
                        .unwrap();
                    if method == "mining.authorize" {
                        let difficulty =
                            json!({"id":null,"method":"mining.set_difficulty","params":[1]});
                        let notify = json!({"id":null,"method":"mining.notify","params":[
                            JOB_ID, "00".repeat(32), coinb1(), coinb2(), [],
                            "00000001", "1d00ffff", NTIME, true
                        ]});
                        writer
                            .write_all(format!("{difficulty}\n{notify}\n").as_bytes())
                            .await
                            .unwrap();
                    }
                }
            };
            let _ = tokio::time::timeout(lifetime, serving).await;
        });
        (
            addr,
            Self {
                accepted,
                requests,
                task,
            },
        )
    }

    pub fn accepted_shares(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }
    pub fn requests(&self) -> Vec<String> {
        self.requests.lock().unwrap().clone()
    }
}

impl Drop for OraclePool {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub fn accepts_submission(message: &Value, worker: &str) -> bool {
    accepts_submission_with_mask(message, worker, None)
}

fn accepts_submission_with_mask(message: &Value, worker: &str, version_mask: Option<u32>) -> bool {
    if message["method"] != "mining.submit" {
        return false;
    }
    let Some(params) = message["params"].as_array() else {
        return false;
    };
    if params.len() != if version_mask.is_some() { 6 } else { 5 }
        || params[0] != worker
        || params[1] != JOB_ID
        || params[3] != NTIME
    {
        return false;
    }
    let Some(extranonce2) = params[2].as_str() else {
        return false;
    };
    let Some(nonce) = params[4].as_str().filter(|value| value.len() == 8) else {
        return false;
    };
    let Ok(nonce) = u32::from_str_radix(nonce, 16) else {
        return false;
    };
    let Some(mut header) = header(extranonce2, nonce) else {
        return false;
    };
    if let Some(mask) = version_mask {
        let Some(bits) = params[5].as_str().filter(|bits| bits.len() == 8) else {
            return false;
        };
        let Ok(bits) = u32::from_str_radix(bits, 16) else {
            return false;
        };
        if bits & !mask != 0 {
            return false;
        }
        // BIP310 replaces the negotiated header-version bits. Reconstruct
        // from this pool's base version, not the client's claimed full header.
        header.version = (header.version & !mask) | bits;
    }
    header.display_hash() <= target()
}

#[test]
fn serialized_share_oracle_refuses_stale_job_wrong_worker_time_and_invalid_nonce() {
    let nonce = winning_nonce("00");
    let good = serde_json::json!({"method":"mining.submit", "params":[
        "dcent.sim", JOB_ID, "00", NTIME, format!("{nonce:08x}")
    ]});
    assert!(accepts_submission(&good, "dcent.sim"));
    for (index, bad) in [
        (0, "foreign"),
        (1, "stale"),
        (2, "bad"),
        (3, "00000000"),
        (4, "not-hex!"),
    ] {
        let mut changed = good.clone();
        changed["params"][index] = Value::String(bad.into());
        assert!(!accepts_submission(&changed, "dcent.sim"));
    }
    let bad_nonce = (0..65_536)
        .find(|candidate| header("00", *candidate).unwrap().display_hash() > target())
        .unwrap();
    let mut changed = good.clone();
    changed["params"][4] = Value::String(format!("{bad_nonce:08x}"));
    assert!(!accepts_submission(&changed, "dcent.sim"));

    let mut rolled = good.clone();
    rolled["params"]
        .as_array_mut()
        .unwrap()
        .push(json!("00000000"));
    assert!(accepts_submission_with_mask(
        &rolled,
        "dcent.sim",
        Some(VERSION_MASK)
    ));
    assert!(!accepts_submission(&rolled, "dcent.sim"));
    assert!(!accepts_submission_with_mask(
        &good,
        "dcent.sim",
        Some(VERSION_MASK)
    ));
    for bits in ["00000001", "20000000", "00002000", "bad-mask", "0000000"] {
        rolled["params"][5] = json!(bits);
        assert!(
            !accepts_submission_with_mask(&rolled, "dcent.sim", Some(VERSION_MASK)),
            "{bits}"
        );
    }
}
