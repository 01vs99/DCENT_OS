//! Two distinct canonical known headers, observed IDs and full CPU hash checks.
use super::*;
use dcentrald_common::bm1391_stock_return::Bm1391StockNonceReturn;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const HEADERS: [&str; 2] = [
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c",
    "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299",
];
const HASHES: [&str; 2] = [
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
    "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048",
];
fn decode<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
pub(super) struct Probe {
    chains: Vec<u8>,
    headers: [[u8; 80]; 2],
    seen: BTreeSet<(u8, usize)>,
    published: [bool; 2],
    pub unrelated_returns: usize,
}
impl Probe {
    pub fn new(chains: &[u8]) -> Self {
        Self {
            chains: chains.to_vec(),
            headers: HEADERS.map(decode),
            seen: BTreeSet::new(),
            published: [false; 2],
            unrelated_returns: 0,
        }
    }
    fn id(chain: u8, header: usize) -> u16 {
        // Distinct high8/low7 fields, including bit14, and distinct per chain.
        (if header == 0 { 0x0101 } else { 0x4080 }) | (u16::from(chain) << 9)
    }
    pub fn frames(&self, index: usize) -> Result<Vec<Work>> {
        let canonical = self.headers[index];
        let midstate = dcentrald_stratum::work::compute_midstate_from_prefix(
            &canonical[..64].try_into().unwrap(),
        );
        let words = std::array::from_fn(|i| {
            u32::from_be_bytes(midstate[i * 4..i * 4 + 4].try_into().unwrap())
        });
        let tail = std::array::from_fn(|i| {
            u32::from_be_bytes(canonical[64 + i * 4..68 + i * 4].try_into().unwrap())
        });
        self.chains
            .iter()
            .map(|chain| {
                Work::from_sha256_words(*chain, Self::id(*chain, index), words, tail)
                    .map_err(anyhow::Error::msg)
            })
            .collect()
    }
    pub fn published(&mut self, index: usize) {
        self.published[index] = true;
    }
    pub fn offer(&mut self, found: Bm1391StockNonceReturn) {
        if found.stock_valid && self.chains.contains(&found.chain_slot) {
            for index in 0..2 {
                if !self.published[index] || found.work_id != Self::id(found.chain_slot, index) {
                    continue;
                }
                let mut canonical = self.headers[index];
                canonical[76..80].copy_from_slice(&found.nonce.swap_bytes().to_le_bytes());
                let mut hash: [u8; 32] = Sha256::digest(Sha256::digest(canonical)).into();
                hash.reverse();
                if canonical == self.headers[index] && hash == decode::<32>(HASHES[index]) {
                    self.seen.insert((found.chain_slot, index));
                    return;
                }
            }
        }
        self.unrelated_returns += 1;
    }
    pub fn complete(&self, index: usize) -> bool {
        self.chains
            .iter()
            .all(|chain| self.seen.contains(&(*chain, index)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn returned(chain: u8, index: usize) -> Bm1391StockNonceReturn {
        let header = decode::<80>(HEADERS[index]);
        Bm1391StockNonceReturn {
            chain_slot: chain,
            work_id: Probe::id(chain, index),
            nonce: u32::from_le_bytes(header[76..80].try_into().unwrap()).swap_bytes(),
            stock_valid: true,
            status_bit6_set: false,
        }
    }
    #[test]
    fn both_known_full_hashes_and_distinct_id_fields_are_required_on_every_chain() {
        let mut probe = Probe::new(&[0, 1, 2]);
        for index in 0..2 {
            probe.published(index);
            for chain in 0..2 {
                probe.offer(returned(chain, index));
            }
            assert!(!probe.complete(index));
            probe.offer(returned(2, index));
            assert!(probe.complete(index));
        }
        assert_eq!(probe.seen.len(), 6);
    }
    #[test]
    fn stale_ids_wrong_chain_wrong_nonce_and_unset_valid_bit_never_qualify() {
        for which in 0..4 {
            let mut probe = Probe::new(&[0]);
            probe.published(0);
            let mut bad = returned(0, 0);
            match which {
                0 => bad.work_id ^= 0x100,
                1 => bad.chain_slot = 1,
                2 => bad.nonce = bad.nonce.swap_bytes(),
                _ => bad.stock_valid = false,
            }
            probe.offer(bad);
            assert!(!probe.complete(0));
            assert_eq!(probe.unrelated_returns, 1);
        }
    }
    #[test]
    fn a_future_round_cannot_be_satisfied_before_its_work_is_published() {
        let mut probe = Probe::new(&[0]);
        probe.published(0);
        probe.offer(returned(0, 1));
        assert!(!probe.complete(1));
        probe.published(1);
        assert!(!probe.complete(1));
        probe.offer(returned(0, 1));
        assert!(probe.complete(1));
    }
    #[tokio::test]
    async fn cancelled_waiter_keeps_received_probe_qualification_until_worker_drain() {
        use dcentrald_hal::platform::stock_bm1391::Registers;
        struct NoIo;
        impl Registers for NoIo {
            fn read(&self, offset: u32) -> Result<u32, String> {
                Ok(match offset {
                    0 => 0xc501,
                    8 => 1,
                    _ => 0,
                })
            }
            fn write(&self, _: u32, _: u32) -> Result<(), String> {
                panic!("probe custody fixture never writes hardware")
            }
        }
        let owner = Transport::new(Arc::new(NoIo), vec![0]).unwrap();
        let workers = BlockingOwner::new(owner.clone());
        let probe = Arc::new(Mutex::new(Probe::new(&[0])));
        probe.lock().unwrap().published(0);
        let (received, ready) = tokio::sync::oneshot::channel();
        let (resume, paused) = std::sync::mpsc::channel();
        let retained = probe.clone();
        let task_workers = workers.clone();
        let waiter = tokio::spawn(async move {
            task_workers
                .run(deadline(2), move |_| {
                    // A real read has completed; its caller can disappear before
                    // the retained worker classifies the received record.
                    let nonce = returned(0, 0);
                    received.send(()).unwrap();
                    paused.recv().unwrap();
                    retained.lock().unwrap().offer(nonce);
                    Ok(())
                })
                .await
        });
        ready.await.unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(owner.terminal());
        assert!(!probe.lock().unwrap().complete(0));
        assert!(workers
            .drain(Instant::now() + Duration::from_millis(5))
            .await
            .is_err());
        resume.send(()).unwrap();
        workers.drain(deadline(1)).await.unwrap();
        assert!(probe.lock().unwrap().complete(0));
    }
}
