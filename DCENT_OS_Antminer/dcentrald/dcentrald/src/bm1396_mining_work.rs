//! Model-bound BM1396 fixed-coinbase jobs. V1 allocation remains host-owned.
//! A packet never proves FPGA width-zero semantics; runtime physical probes
//! and complete immutable-header return validation are separate requirements.
use anyhow::{ensure, Context, Result};
use dcentrald_common::bm1396_work::{bm1396_parse_job_packet, bm1396_plan_job_fpga};
use dcentrald_stratum::{
    types::JobTemplate,
    work::{double_sha256, MiningWork, WorkBuilder},
};

// Compile retained publication/return custody after the actual HAL owner tests.
// Runtime startup and dispatcher admission remain separate.
#[path = "bm1396_mining_registry.rs"]
mod registry;
#[path = "bm1396_mining.rs"]
pub(crate) mod runtime;
#[cfg(test)]
#[path = "bm1396_mining_test_support.rs"]
mod test_support;

#[derive(Debug)]
pub(super) struct PreparedJob {
    id: u32,
    packet: Vec<u8>,
    header: [u8; 80],
    fixed_nonce2: u64,
    pool: Option<MiningWork>,
}

#[derive(Debug)]
pub(super) struct QualifiedHeader {
    pub(super) canonical_nonce: u32,
    pub(super) header_hash_be: [u8; 32],
    pub(super) meets_pool_target: bool,
}
impl PreparedJob {
    pub(super) fn id(&self) -> u32 {
        self.id
    }
    pub(super) fn packet(&self) -> &[u8] {
        &self.packet
    }
    pub(super) fn header(&self) -> &[u8; 80] {
        &self.header
    }
    pub(super) fn fixed_nonce2(&self) -> u64 {
        self.fixed_nonce2
    }
    pub(super) fn pool(&self) -> Option<&MiningWork> {
        self.pool.as_ref()
    }

    /// Pure immutable-header qualification. The registry must separately join
    /// the actual same-owner completed publication and retained return before
    /// this result can affect probe state, liveness or pool submission.
    pub(super) fn qualify_header(
        &self,
        raw_nonce: u32,
        nonce2: u64,
        version_word_wire: u32,
    ) -> Result<QualifiedHeader> {
        ensure!(
            nonce2 == self.fixed_nonce2,
            "BM1396 returned EN2 escaped issued fixed domain"
        );
        let version = u32::from_le_bytes(self.header[..4].try_into().expect("header version"));
        ensure!(
            version_word_wire.swap_bytes() == version,
            "BM1396 returned complete version differs from issued header"
        );
        let mut header = self.header;
        let canonical_nonce = raw_nonce.swap_bytes();
        header[76..80].copy_from_slice(&canonical_nonce.to_le_bytes());
        let mut hash = double_sha256(&header);
        hash.reverse();
        // Exact signed consumer's necessary SHA prefilter. This does not
        // assign an unproved unit or difficulty to FPGA ticket literal0x0f.
        ensure!(
            hash[..4] == [0; 4],
            "BM1396 return failed complete CPU header hash"
        );
        if self.pool.is_none() {
            ensure!(
                header == self.header,
                "BM1396 probe returned another header nonce"
            );
        }
        let meets_pool_target = self
            .pool
            .as_ref()
            .is_some_and(|work| hash.as_slice() <= work.share_target.as_slice());
        Ok(QualifiedHeader {
            canonical_nonce,
            header_hash_be: hash,
            meets_pool_target,
        })
    }

    pub(super) fn pool_job(builder: &mut WorkBuilder, job: &JobTemplate, id: u32) -> Result<Self> {
        ensure!(
            job.v1_work_domain.is_some() && (1..=8).contains(&job.extranonce2_size),
            "BM1396 fixed coinbase requires the original finite V1 domain"
        );
        ensure!(
            job.version_mask == 0 && job.merkle_root == [0; 32],
            "BM1396 fixed coinbase requires single-version V1 coinbase construction"
        );
        let offset = job
            .coinbase1
            .len()
            .checked_add(job.extranonce1.len())
            .context("BM1396 coinbase offset overflow")?;
        let length = offset
            .checked_add(job.extranonce2_size)
            .and_then(|n| n.checked_add(job.coinbase2.len()))
            .context("BM1396 coinbase length overflow")?;
        check_lengths(length, offset, job.merkle_branches.len())?;
        // Existing subscription+generation allocator is the sole EN2 producer.
        // A failed preparation consumes its value; no retry rewinds the domain.
        let work = builder.next_work(job)?;
        ensure!(
            work.version_mask == 0 && work.work_generation == job.work_generation,
            "BM1396 prepared work changed version or generation"
        );
        let extranonce = hex::decode(&work.extranonce2)?;
        ensure!(
            extranonce.len() == job.extranonce2_size,
            "BM1396 allocated EN2 width changed"
        );
        let mut coinbase = Vec::with_capacity(length);
        coinbase.extend_from_slice(&job.coinbase1);
        coinbase.extend_from_slice(&job.extranonce1);
        coinbase.extend_from_slice(&extranonce);
        coinbase.extend_from_slice(&job.coinbase2);
        let root = merkle_root(&coinbase, &job.merkle_branches);
        ensure!(
            root == work.merkle_root,
            "BM1396 fixed coinbase differs from allocated work"
        );
        let header = dcentrald_stratum::v1::job::build_block_header(
            work.version,
            &work.prev_block_hash,
            &root,
            work.ntime,
            work.nbits,
            0,
        );
        let packet = encode_fixed(
            id,
            work.version,
            &job.prev_block_hash,
            work.ntime,
            work.nbits,
            &coinbase,
            offset,
            &job.merkle_branches,
        )?;
        Ok(Self {
            id,
            fixed_nonce2: fixed_nonce2(&packet),
            packet,
            header,
            pool: Some(work),
        })
    }

    #[cfg(test)]
    pub(super) fn known_probe(id: u32, index: usize) -> Result<Self> {
        Self::known_probe_for_model(dcentrald_common::Bm1396Model::T17e, id, index)
    }

    pub(super) fn known_probe_for_model(
        model: dcentrald_common::Bm1396Model,
        id: u32,
        index: usize,
    ) -> Result<Self> {
        let vectors: serde_json::Value = serde_json::from_str(match model {
            dcentrald_common::Bm1396Model::T17e => include_str!("bm1396_mining_probe_vectors.json"),
            dcentrald_common::Bm1396Model::S17e => include_str!("bm1396_s17e_probe_vectors.json"),
        })?;
        let case = vectors["cases"]
            .as_array()
            .and_then(|cases| cases.get(index))
            .context("BM1396 unknown retained probe index")?;
        let coinbase = hex::decode(
            case["coinbase_hex"]
                .as_str()
                .context("BM1396 probe coinbase absent")?,
        )?;
        let header: [u8; 80] = hex::decode(
            case["header_hex"]
                .as_str()
                .context("BM1396 probe header absent")?,
        )?
        .try_into()
        .map_err(|_| anyhow::anyhow!("BM1396 probe header length"))?;
        let branches: Vec<[u8; 32]> = case["merkle_branches"]
            .as_array()
            .context("BM1396 probe Merkle branches absent")?
            .iter()
            .map(|branch| -> Result<[u8; 32]> {
                hex::decode(branch.as_str().context("BM1396 probe branch absent")?)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("BM1396 probe branch length"))
            })
            .collect::<Result<_>>()?;
        let root = merkle_root(&coinbase, &branches);
        ensure!(
            root == header[36..68],
            "BM1396 retained probe coinbase root differs"
        );
        let mut hash = double_sha256(&header);
        hash.reverse();
        ensure!(
            hex::encode(hash)
                == case["header_hash"]
                    .as_str()
                    .context("BM1396 probe hash absent")?,
            "BM1396 retained probe complete header hash differs"
        );
        let raw_nonce = u32::from_be_bytes(header[76..80].try_into().expect("header nonce"));
        let wire_address = ((raw_nonce >> 17) & 255) as u8;
        ensure!(
            wire_address % model.address_interval() == 0
                && u16::from(wire_address / model.address_interval())
                    < model.expected_chips_per_present_chain(),
            "BM1396 retained probe nonce lies outside exact model geometry"
        );
        let mut previous = [0; 32];
        previous.copy_from_slice(&header[4..36]);
        for word in previous.chunks_exact_mut(4) {
            word.reverse();
        }
        let word = |offset| {
            u32::from_le_bytes(header[offset..offset + 4].try_into().expect("header word"))
        };
        let packet = encode_fixed(
            id,
            word(0),
            &previous,
            word(68),
            word(72),
            &coinbase,
            0,
            &branches,
        )?;
        Ok(Self {
            id,
            fixed_nonce2: fixed_nonce2(&packet),
            packet,
            header,
            pool: None,
        })
    }
}

fn merkle_root(coinbase: &[u8], branches: &[[u8; 32]]) -> [u8; 32] {
    let mut root = double_sha256(coinbase);
    for branch in branches {
        let mut pair = [0; 64];
        pair[..32].copy_from_slice(&root);
        pair[32..].copy_from_slice(branch);
        root = double_sha256(&pair);
    }
    root
}

fn check_lengths(length: usize, offset: usize, branches: usize) -> Result<()> {
    ensure!(
        length <= u16::MAX as usize && branches <= 128,
        "BM1396 coinbase or Merkle population exceeds bounded packet"
    );
    ensure!(
        offset.checked_add(8).is_some_and(|end| end <= length),
        "BM1396 fixed EN2 source window is not eight complete coinbase bytes"
    );
    ensure!(
        length
            .checked_add(branches * 32)
            .is_some_and(|bytes| bytes <= 65_534),
        "BM1396 job payload exceeds retained source buffer"
    );
    Ok(())
}

#[cfg(test)]
#[path = "bm1396_mining_work_tests.rs"]
mod tests;

fn fixed_nonce2(packet: &[u8]) -> u64 {
    u64::from_le_bytes(packet[0x48..0x50].try_into().expect("fixed source packet"))
}

fn encode_fixed(
    id: u32,
    version: u32,
    previous_pool_order: &[u8; 32],
    ntime: u32,
    nbits: u32,
    coinbase: &[u8],
    offset: usize,
    branches: &[[u8; 32]],
) -> Result<Vec<u8>> {
    check_lengths(coinbase.len(), offset, branches.len())?;
    let length = 0x58 + coinbase.len() + branches.len() * 32 + 2;
    let mut bytes = vec![0; length];
    bytes[0] = 0x52;
    bytes[4..8].copy_from_slice(&((length - 8) as u32).to_le_bytes());
    bytes[9] = 3; // Original clean bit plus ticket-register flag.
    bytes[10] = 0x0f; // Exact named producer literal; no inferred hash-rate unit.
    bytes[12..16].copy_from_slice(&id.to_le_bytes());
    // Original hex2bin copies numeric pool strings directly into these fields.
    // The downstream source parser reads LE scalars for its raw FPGA stores.
    bytes[16..20].copy_from_slice(&version.to_be_bytes());
    bytes[20..52].copy_from_slice(previous_pool_order);
    bytes[52..56].copy_from_slice(&ntime.to_be_bytes());
    bytes[56..60].copy_from_slice(&nbits.to_be_bytes());
    bytes[60..62].copy_from_slice(&(coinbase.len() as u16).to_le_bytes());
    bytes[62..64].copy_from_slice(&(offset as u16).to_le_bytes());
    bytes[64] = 0; // Candidate fixed mode, requiring actual runtime qualification.
    bytes[66..68].copy_from_slice(&(branches.len() as u16).to_le_bytes());
    bytes[72..80].copy_from_slice(&coinbase[offset..offset + 8]);
    bytes[84..88].copy_from_slice(&1u32.to_le_bytes());
    bytes[88..88 + coinbase.len()].copy_from_slice(coinbase);
    for (index, branch) in branches.iter().enumerate() {
        let start = 88 + coinbase.len() + index * 32;
        bytes[start..start + 32].copy_from_slice(branch);
    }
    // Complete original CRC span is independently joined to all ten original
    // packets. This codec does not reuse an unrelated model's device protocol.
    let mut crc = 0xffffu16;
    for byte in &bytes[..length - 2] {
        crc ^= u16::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xa001 } else { 0 };
        }
    }
    bytes[length - 2..].copy_from_slice(&crc.to_le_bytes());
    let parsed = bm1396_parse_job_packet(&bytes)
        .map_err(|e| anyhow::anyhow!("BM1396 encoded packet: {e:?}"))?;
    bm1396_plan_job_fpga(&parsed, 0)
        .map_err(|e| anyhow::anyhow!("BM1396 encoded payload: {e:?}"))?;
    Ok(bytes)
}
