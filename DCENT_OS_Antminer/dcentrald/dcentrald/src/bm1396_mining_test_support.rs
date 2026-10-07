//! Mechanical shared test-only extraction of the accepted registry fixture.
//! Public HAL observation/publication/return APIs only; no final-startup token.
use super::{
    registry::{ReturnDisposition, WorkRegistry},
    PreparedJob,
};
use dcentrald_hal::platform::stock_bm1396::{
    Hardware, Model, PreservedReturn, ReturnPayload, Transport,
};
use dcentrald_stratum::work::MiningWork;
use dcentrald_stratum::work_domain::WorkGeneration;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
    time::{Duration, Instant},
};
use std::{collections::VecDeque, sync::Arc};

pub(super) struct Memory {
    pub(super) claimed: AtomicBool,
    pub(super) corrupt: AtomicBool,
    pub(super) registers: Mutex<HashMap<u32, u32>>,
    pub(super) dma: Mutex<Vec<u8>>,
    pub(super) fifo: Mutex<VecDeque<u32>>,
}
impl Memory {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            claimed: AtomicBool::new(false),
            corrupt: AtomicBool::new(false),
            registers: Mutex::new(HashMap::from([(0, 0x1234abcd), (8, 5)])),
            dma: Mutex::new(vec![0; 0x220000]),
            fifo: Mutex::new(VecDeque::new()),
        })
    }
}
impl Hardware for Memory {
    fn model(&self) -> Model {
        Model::T17e
    }
    fn validate_owner(&self) -> Result<(), String> {
        Ok(())
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.claimed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
            .map_err(|_| "already claimed".into())
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == 0x18 {
            return Ok(self.fifo.lock().unwrap().len() as u32);
        }
        if offset == 0x10 || offset == 0x14 {
            return self
                .fifo
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| "FIFO underflow".into());
        }
        Ok(*self.registers.lock().unwrap().get(&offset).unwrap_or(&0))
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.registers.lock().unwrap().insert(offset, value);
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        let data = self.dma.lock().unwrap();
        out.copy_from_slice(
            data.get(offset..offset + out.len())
                .ok_or("DMA read bound")?,
        );
        if self.corrupt.load(Ordering::SeqCst) && offset >= 0x200000 {
            out[0] ^= 1;
        }
        Ok(())
    }
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        self.dma
            .lock()
            .unwrap()
            .get_mut(offset..offset + bytes.len())
            .ok_or("DMA write bound")?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn barrier(&self) -> Result<(), String> {
        Ok(())
    }
    fn sleep(&self, _: Duration) {}
}
pub(super) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
pub(super) async fn fixture() -> (Arc<Memory>, Arc<Transport<Memory>>, WorkRegistry<Memory>) {
    let memory = Memory::new();
    let owner = Transport::observe(memory.clone(), Model::T17e, vec![0, 2])
        .await
        .unwrap();
    owner.initialize_dma(deadline()).await.unwrap();
    let registry = WorkRegistry::new(owner.clone(), "test.fixed-domain".into()).unwrap();
    (memory, owner, registry)
}
pub(super) async fn publish(
    owner: &Arc<Transport<Memory>>,
    registry: &mut WorkRegistry<Memory>,
    job: PreparedJob,
) -> Arc<PreparedJob> {
    let issued = registry.retain_issued(job).unwrap();
    let publication = owner
        .publish_job(issued.packet().to_vec(), false, 400, deadline())
        .await
        .unwrap();
    registry.join_publication(&publication).unwrap();
    issued
}
pub(super) async fn emit(
    memory: &Memory,
    owner: &Arc<Transport<Memory>>,
    job: &PreparedJob,
    chain: u8,
    defect: u8,
) -> PreservedReturn {
    let mut entry = [0; 64];
    entry[..4].copy_from_slice(&job.id().to_le_bytes());
    let version = u32::from_le_bytes(job.header()[..4].try_into().unwrap());
    entry[4..8]
        .copy_from_slice(&(version ^ if defect == 1 { 0x00100000 } else { 0 }).to_be_bytes());
    entry[8..16].copy_from_slice(&(job.fixed_nonce2() ^ u64::from(defect == 2)).to_le_bytes());
    memory.dma.lock().unwrap()[64..128].copy_from_slice(&entry);
    let raw = u32::from_be_bytes(job.header()[76..80].try_into().unwrap()) ^ u32::from(defect == 3);
    // FIFO dispatch uses bit 31, independently of byte 0's nonce-valid bit.
    // The outstanding work ID masks that high bit, leaving table slot 1.
    let header = u32::from_le_bytes([0x80 | chain, 0, 1, 0x80]);
    memory
        .fifo
        .lock()
        .unwrap()
        .extend([header, raw, 0, 0x5555aaaa]);
    assert_eq!(owner.poll_returns(1, deadline()).await.unwrap(), 1);
    let record = owner.pending_returns().unwrap().into_iter().last().unwrap();
    let ReturnPayload::Nonce { nonce, outstanding } = record.payload() else {
        panic!(
            "fixture must reach actual nonce classification: {:?}",
            record.payload()
        );
    };
    assert!(record.same_owner(owner));
    assert_eq!(nonce.chain_slot, chain);
    assert_eq!(nonce.work_id, 1);
    assert_eq!(nonce.nonce, raw);
    assert_eq!(outstanding.work_id(), 1);
    assert_eq!(outstanding.decoded().job_id, job.id());
    assert_eq!(outstanding.publication().job_id(), job.id());
    assert!(outstanding.publication().same_owner(owner));
    assert!(outstanding.publication().completed());
    record
}
pub(super) async fn probes(
    memory: &Memory,
    owner: &Arc<Transport<Memory>>,
    registry: &mut WorkRegistry<Memory>,
) {
    for index in 0..2 {
        let issued = publish(
            owner,
            registry,
            PreparedJob::known_probe(index as u32, index).unwrap(),
        )
        .await;
        for chain in [0, 2] {
            let raw = emit(memory, owner, &issued, chain, 0).await;
            assert_eq!(
                registry.qualify_return(&raw).unwrap(),
                ReturnDisposition::Probe
            );
            owner.acknowledge_return(&raw).unwrap();
        }
    }
    assert!(registry.probes_complete());
}

// Explicit test metadata seam: production V1 construction is separately
// exercised through a real loopback client; no production constructor is added.
pub(super) fn pool_fixture(id: u32, generation: WorkGeneration, target: [u8; 32]) -> PreparedJob {
    pool_fixture_index(id, 0, generation, target)
}
pub(super) fn pool_fixture_index(
    id: u32,
    index: usize,
    generation: WorkGeneration,
    target: [u8; 32],
) -> PreparedJob {
    let mut job = PreparedJob::known_probe(id, index).unwrap();
    let header = job.header;
    job.pool = Some(MiningWork {
        work_generation: generation,
        midstates: Vec::new(),
        merkle4: header[64..68].try_into().unwrap(),
        ntime: u32::from_le_bytes(header[68..72].try_into().unwrap()),
        nbits: u32::from_le_bytes(header[72..76].try_into().unwrap()),
        job_id: "immutable-pool-fixture".into(),
        extranonce2: "00".into(),
        version: u32::from_le_bytes(header[..4].try_into().unwrap()),
        version_mask: 0,
        share_target: target,
        merkle_root: header[36..68].try_into().unwrap(),
        prev_block_hash: header[4..36].try_into().unwrap(),
    });
    job
}
