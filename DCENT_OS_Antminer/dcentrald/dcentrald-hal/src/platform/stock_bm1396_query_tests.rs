use super::*;

struct QueryHardware {
    inner: Arc<Fake>,
    batches: Mutex<VecDeque<Vec<u32>>>,
    change_host: AtomicU32,
    change_presence: AtomicBool,
}
impl QueryHardware {
    fn batch(&self, records: Vec<u32>) {
        self.batches.lock().unwrap().push_back(records);
    }
}
impl Hardware for QueryHardware {
    fn model(&self) -> Model {
        self.inner.model()
    }
    fn validate_owner(&self) -> Result<(), String> {
        self.inner.validate_owner()
    }
    fn claim_transport(&self) -> Result<(), String> {
        self.inner.claim_transport()
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == 0x18 {
            // The fixture provides a stream; bounded occupancy avoids inventing
            // a wrapping hardware FIFO count from a >512-word host vector.
            return Ok(self.inner.returns.lock().unwrap().len().min(510) as u32);
        }
        self.inner.read(offset)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.inner.write(offset, value)?;
        if offset == BC && value & BUSY != 0 {
            if let Some(words) = self.batches.lock().unwrap().pop_front() {
                self.inner.words(&words);
            }
            if self.change_host.load(Ordering::SeqCst) != 0 {
                *self.inner.regs.lock().unwrap().entry(0x3c).or_default() ^=
                    self.change_host.load(Ordering::SeqCst);
            }
            if self.change_presence.load(Ordering::SeqCst) {
                self.inner.regs.lock().unwrap().insert(8, 0);
            }
        }
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        self.inner.read_dma(offset, out)
    }
    fn write_dma(&self, offset: usize, data: &[u8]) -> Result<(), String> {
        self.inner.write_dma(offset, data)
    }
    fn barrier(&self) -> Result<(), String> {
        self.inner.barrier()
    }
    fn sleep(&self, duration: Duration) {
        self.inner.sleep(duration);
    }
}
async fn query_owner(
    model: Model,
    chains: Vec<u8>,
) -> (Arc<QueryHardware>, Arc<Transport<QueryHardware>>) {
    let mask = chains.iter().fold(0, |mask, chain| mask | (1 << chain));
    let hw = Arc::new(QueryHardware {
        inner: Fake::new(model, mask),
        batches: Mutex::new(VecDeque::new()),
        change_host: AtomicU32::new(0),
        change_presence: AtomicBool::new(false),
    });
    // Preserve all six bits, including a code whose high bit would be lost by
    // a five-bit helper inherited from a different carrier.
    hw.inner.regs.lock().unwrap().insert(0x3c, 0xad6ded2d);
    let transport = Transport::observe(hw.clone(), model, chains).await.unwrap();
    (hw, transport)
}
fn register(chain: u8, chip: u8, reg: u8, value: u32) -> Vec<u32> {
    vec![
        u32::from_le_bytes([chain, reg, chip, 0x02]),
        value,
        0x11,
        0x5555aaaa,
    ]
}

#[tokio::test]
async fn assigned_population_joins_every_address_and_retains_raw_observation() {
    for model in [Model::S17e, Model::T17e] {
        let (hw, transport) = query_owner(model, vec![0, 2]).await;
        for chain in [0, 2] {
            // Deliberately reverse wire arrival order; the exact full set matters.
            let words = (0..model.expected_chips_per_present_chain())
                .rev()
                .flat_map(|index| {
                    register(
                        chain,
                        index as u8 * model.address_interval(),
                        0x18,
                        0x11223344,
                    )
                })
                .collect();
            hw.batch(words);
        }
        assert_eq!(
            transport
                .query_assigned_population(0x18, deadline())
                .await
                .unwrap(),
            1
        );
        let observations = transport.pending_register_observations().unwrap();
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].host_baud_register(), 0xad6ded2d);
        assert_eq!(observations[0].host_baud_selectors(), [0x2d; 4]);
        assert_eq!(
            observations[0].registers().count(),
            model.expected_chips_per_present_chain() as usize * 2
        );
        assert_eq!(
            observations[0].raw_records()[0].words(),
            register(0, 0, 0x18, 0x11223344)
        );
        assert!(transport.pending_returns().unwrap().is_empty());
        assert_eq!(
            hw.inner
                .writes()
                .iter()
                .filter(|(offset, _)| *offset == BC)
                .count(),
            2
        );
        transport
            .acknowledge_register_observation(&observations[0])
            .unwrap();
        assert!(transport
            .acknowledge_register_observation(&observations[0])
            .is_err());
    }
}

#[tokio::test]
async fn stale_matching_reply_never_qualifies_new_query_and_is_not_discarded() {
    let (hw, transport) = query_owner(Model::S17e, vec![0]).await;
    hw.inner.words(&register(0, 27, 0x1c, 0x0198fe55));
    assert!(transport
        .query_register(0, 27, 0x1c, deadline())
        .await
        .is_err());
    assert!(transport.is_terminal());
    assert_eq!(transport.pending_returns().unwrap().len(), 1);
    assert!(transport
        .pending_register_observations()
        .unwrap()
        .is_empty());
    assert_eq!(
        hw.inner
            .writes()
            .iter()
            .filter(|(offset, _)| *offset == BC)
            .count(),
        1
    );
}

#[tokio::test]
async fn wrong_correlation_duplicate_crc_type_and_geometry_keep_raw_custody() {
    let cases = [
        register(2, 27, 0x1c, 1),
        register(0, 28, 0x1c, 1),
        register(0, 27, 0x18, 1),
        [register(0, 27, 0x1c, 1), register(0, 27, 0x1c, 1)].concat(),
        register(0x40, 27, 0x1c, 1),
        vec![0x42421c00, 1, 0, 0x5555aaaa],
    ];
    for words in cases {
        let (hw, transport) = query_owner(Model::S17e, vec![0, 2]).await;
        hw.batch(words.clone());
        assert!(transport
            .query_register(0, 27, 0x1c, deadline())
            .await
            .is_err());
        assert!(transport.is_terminal());
        assert!(!transport.pending_returns().unwrap().is_empty());
        assert_eq!(transport.pending_returns().unwrap()[0].words(), &words[..4]);
        assert!(transport
            .pending_register_observations()
            .unwrap()
            .is_empty());
    }
    let (hw, transport) = query_owner(Model::T17e, vec![0]).await;
    assert!(transport
        .query_register(0, 17, 0x18, deadline())
        .await
        .is_err());
    assert!(hw.inner.writes().is_empty());
    assert!(!transport.is_terminal());
}

#[tokio::test]
async fn nonce_and_stale_records_survive_successful_query_transfer() {
    let (hw, transport) = query_owner(Model::S17e, vec![0]).await;
    transport.initialize_dma(deadline()).await.unwrap();
    transport
        .publish_job(packet(17), false, 400, deadline())
        .await
        .unwrap();
    hw.inner.dma.lock().unwrap()[64..68].copy_from_slice(&17u32.to_le_bytes());
    hw.inner.words(&register(0, 35, 0x18, 0xabcdef));
    hw.batch(
        [
            vec![0x80010080, 0, 0, 0x5555aaaa],
            register(0, 27, 0x1c, 0x0198fe55),
        ]
        .concat(),
    );
    transport
        .query_register(0, 27, 0x1c, deadline())
        .await
        .unwrap();
    let pending = transport.pending_returns().unwrap();
    assert_eq!(pending.len(), 2);
    assert!(matches!(pending[0].payload(), ReturnPayload::Register(_)));
    assert!(matches!(pending[1].payload(), ReturnPayload::Nonce { .. }));
    assert_eq!(
        transport.pending_register_observations().unwrap()[0]
            .registers()
            .next()
            .unwrap()
            .value,
        0x0198fe55
    );
    transport.acknowledge_return(&pending[0]).unwrap();
    transport.acknowledge_return(&pending[1]).unwrap();
}

#[tokio::test]
async fn cancelled_query_worker_is_counted_and_consumed_words_remain_retained() {
    let (hw, transport) = query_owner(Model::S17e, vec![0]).await;
    hw.batch(register(0, 27, 0x1c, 0x0198fe55));
    let block = ReadBlock::new(0x14);
    *hw.inner.block.lock().unwrap() = Some(block.clone());
    let copy = transport.clone();
    let task = tokio::spawn(async move { copy.query_register(0, 27, 0x1c, deadline()).await });
    let until = Instant::now() + Duration::from_secs(2);
    while !block.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    task.abort();
    assert!(task.await.is_err());
    assert!(transport
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    block.release();
    transport.drain(deadline()).await.unwrap();
    assert_eq!(
        transport.partial_return_words().unwrap(),
        register(0, 27, 0x1c, 0x0198fe55)[..2]
    );
    assert!(transport
        .pending_register_observations()
        .unwrap()
        .is_empty());
    assert!(transport.asic_fault.load(Ordering::SeqCst));
}

#[tokio::test]
async fn changed_host_presence_and_short_budget_refuse_without_retry() {
    for fault in 0..3 {
        let (hw, transport) = query_owner(Model::S17e, vec![0]).await;
        hw.batch(register(0, 27, 0x1c, 0x0198fe55));
        hw.change_host
            .store(u32::from(fault == 0), Ordering::SeqCst);
        hw.change_presence.store(fault == 1, Ordering::SeqCst);
        let end = if fault == 2 {
            Instant::now() + Duration::from_millis(5)
        } else {
            deadline()
        };
        assert!(transport.query_register(0, 27, 0x1c, end).await.is_err());
        assert!(transport.is_terminal());
        assert!(transport
            .pending_register_observations()
            .unwrap()
            .is_empty());
        assert!(
            hw.inner
                .writes()
                .iter()
                .filter(|(offset, _)| *offset == BC)
                .count()
                <= 1
        );
    }
}

#[tokio::test]
async fn observations_require_same_owner_order_and_bound_capacity_before_io() {
    let (hw, transport) = query_owner(Model::S17e, vec![0]).await;
    let (_, other) = query_owner(Model::S17e, vec![0]).await;
    for _ in 0..64 {
        hw.batch(register(0, 27, 0x1c, 0x0198fe55));
        transport
            .query_register(0, 27, 0x1c, deadline())
            .await
            .unwrap();
    }
    let observations = transport.pending_register_observations().unwrap();
    assert!(other
        .acknowledge_register_observation(&observations[0])
        .is_err());
    assert!(transport
        .acknowledge_register_observation(&observations[1])
        .is_err());
    let writes = hw.inner.writes().len();
    assert!(transport
        .query_register(0, 27, 0x1c, deadline())
        .await
        .is_err());
    assert_eq!(hw.inner.writes().len(), writes);
    assert_eq!(transport.pending_register_observations().unwrap().len(), 64);
}

#[tokio::test]
async fn exact_baud_register_all_four_lanes_and_preserved_bits_are_watched() {
    for bit in [0, 7, 8, 15, 16, 23, 24, 31] {
        let (hw, transport) = query_owner(Model::S17e, vec![0]).await;
        hw.inner.regs.lock().unwrap().insert(BC, 0x12);
        hw.change_host.store(1 << bit, Ordering::SeqCst);
        hw.batch(register(0, 27, 0x18, 1));
        assert!(transport
            .query_register(0, 27, 0x18, deadline())
            .await
            .is_err());
        assert!(transport.is_terminal());
        assert!(transport
            .pending_register_observations()
            .unwrap()
            .is_empty());
        assert_eq!(hw.inner.regs.lock().unwrap()[&BC] & 0x3f, 0x12);
    }
}
