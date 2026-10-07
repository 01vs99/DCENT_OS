//! Test-only pool verification from serialized V1 notifications/submissions.
//! SHA256d and Merkle folding use the independent scalar F04 implementation.
#![allow(dead_code)]

#[path = "../f04_oracle/bitcoin_oracle.rs"]
mod bitcoin_oracle;

use bitcoin_oracle::{merkle_root, stratum_coinbase_hash, BlockHeader};
use serde_json::Value;

pub struct StratumOracle {
    worker: String,
    job_id: String,
    coinbase1: Vec<u8>,
    coinbase2: Vec<u8>,
    extranonce1: Vec<u8>,
    extranonce2_size: usize,
    branches: Vec<[u8; 32]>,
    template: BlockHeader,
    target: [u8; 32],
}

fn bytes(value: &Value, maximum: usize) -> Result<Vec<u8>, String> {
    let value = value.as_str().ok_or("hex string required")?;
    if value.len() > maximum * 2 || value.len() % 2 != 0 {
        return Err("hex field exceeds exact byte bounds".into());
    }
    hex::decode(value).map_err(|_| "invalid hexadecimal bytes".into())
}

fn word(value: &Value) -> Result<u32, String> {
    let data: [u8; 4] = bytes(value, 4)?
        .try_into()
        .map_err(|_| "exact u32 hex required")?;
    Ok(u32::from_be_bytes(data))
}

impl StratumOracle {
    /// Version rolling is disabled for these fixtures; only five-field V1
    /// submissions are accepted. The pool's explicit target is independent
    /// of the client's WorkBuilder and its locally generated MiningWork.
    pub fn from_notify(
        notify: &Value,
        extranonce1: &str,
        extranonce2_size: usize,
        worker: &str,
        target: [u8; 32],
    ) -> Result<Self, String> {
        if notify["method"] != "mining.notify" || !(1..=8).contains(&extranonce2_size) {
            return Err("exact V1 notification and extranonce width required".into());
        }
        let params = notify["params"]
            .as_array()
            .ok_or("notification array required")?;
        if params.len() != 9 || !params[8].is_boolean() || worker.is_empty() || worker.len() > 512 {
            return Err("invalid notification shape or worker".into());
        }
        let job_id = params[0]
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .ok_or("bounded job id required")?
            .to_owned();
        let mut prev_hash: [u8; 32] = bytes(&params[1], 32)?
            .try_into()
            .map_err(|_| "exact previous hash required")?;
        // V1 serializes the previous hash with each four-byte word reversed.
        // Reverse each word here, independently of the production job parser.
        for word in prev_hash.chunks_exact_mut(4) {
            word.reverse();
        }
        let branch_values = params[4]
            .as_array()
            .filter(|values| values.len() <= 32)
            .ok_or("bounded Merkle branch array required")?;
        let branches = branch_values
            .iter()
            .map(|value| {
                bytes(value, 32)?
                    .try_into()
                    .map_err(|_| "exact Merkle sibling required".into())
            })
            .collect::<Result<Vec<[u8; 32]>, String>>()?;
        Ok(Self {
            worker: worker.into(),
            job_id,
            coinbase1: bytes(&params[2], 65_536)?,
            coinbase2: bytes(&params[3], 65_536)?,
            extranonce1: bytes(&Value::String(extranonce1.into()), 64)?,
            extranonce2_size,
            branches,
            template: BlockHeader {
                version: word(&params[5])?,
                prev_hash,
                merkle_root: [0; 32],
                timestamp: word(&params[7])?,
                nbits: word(&params[6])?,
                nonce: 0,
            },
            target,
        })
    }

    pub fn reconstruct(&self, params: &Value) -> Option<BlockHeader> {
        let params = params.as_array()?;
        if params.len() != 5
            || params[0] != self.worker
            || params[1] != self.job_id
            || word(&params[3]).ok()? != self.template.timestamp
        {
            return None;
        }
        let extranonce2 = bytes(&params[2], self.extranonce2_size).ok()?;
        if extranonce2.len() != self.extranonce2_size {
            return None;
        }
        let coinbase = stratum_coinbase_hash(
            &self.coinbase1,
            &self.extranonce1,
            &extranonce2,
            &self.coinbase2,
        );
        let mut header = self.template;
        header.merkle_root = merkle_root(&coinbase, &self.branches);
        header.nonce = word(&params[4]).ok()?;
        Some(header)
    }

    pub fn accepts(&self, params: &Value) -> bool {
        self.reconstruct(params)
            .is_some_and(|header| header.display_hash() <= self.target)
    }
}

pub fn difficulty_one_target() -> [u8; 32] {
    bitcoin_oracle::DIFF1_TARGET
}

#[test]
fn difficulty_one_oracle_refuses_hash_just_above_consensus_target() {
    // nBits 1d00ffff has a 16-bit mantissa followed by 208 zero bits.
    // Four leading zero bytes alone would admit slightly insufficient work.
    let exact: [u8; 32] = hex::decode(
        "00000000ffff0000000000000000000000000000000000000000000000000000",
    ).unwrap().try_into().unwrap();
    assert!(bitcoin_oracle::display_hash_meets_target(&exact, &difficulty_one_target()));
    let mut insufficient = exact;
    insufficient[31] = 1;
    assert!(!bitcoin_oracle::display_hash_meets_target(&insufficient, &difficulty_one_target()));
}
