use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicU32;
use std::sync::Condvar;

#[path = "stock_bm1396_closeout_tests.rs"]
mod closeout_tests;
#[path = "stock_bm1396_cold_pll_tests.rs"]
mod cold_pll_tests;
#[path = "stock_bm1396_preparation_tests.rs"]
mod preparation_tests;
#[path = "stock_bm1396_reset_tests.rs"]
mod reset_tests;
#[path = "stock_bm1396_source_tests.rs"]
mod source_tests;
#[path = "stock_bm1396_supply_tests.rs"]
mod supply_tests;

#[path = "stock_bm1396_factory_tests.rs"]
mod factory_tests;
#[path = "stock_bm1396_query_tests.rs"]
mod query_tests;
#[path = "stock_bm1396_rail_tests.rs"]
mod rail_tests;
#[path = "stock_bm1396_startup_tests.rs"]
mod startup_tests;
#[path = "stock_bm1396_thermal_tests.rs"]
mod thermal_tests;
#[path = "stock_bm1396_verifier_tests.rs"]
mod verifier_tests;
#[path = "stock_bm1396_voltage_tests.rs"]
mod voltage_tests;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Event {
    SourceHigh,
    SourceLow,
    Read(u32),
    Write(u32, u32),
    DmaRead(usize, usize),
    DmaWrite(usize, usize),
    Barrier,
    Sleep(u64),
}
struct ReadBlock {
    offset: u32,
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}
impl ReadBlock {
    fn new(offset: u32) -> Arc<Self> {
        Arc::new(Self {
            offset,
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }
}

pub(super) struct Fake {
    model: Model,
    claimed: AtomicBool,
    regs: Mutex<BTreeMap<u32, u32>>,
    dma: Mutex<Vec<u8>>,
    pub(super) events: Mutex<Vec<Event>>,
    returns: Mutex<VecDeque<u32>>,
    tachs: Mutex<VecDeque<u32>>,
    replies: Mutex<VecDeque<u8>>,
    management_timeout: AtomicBool,
    bc_timeout: AtomicBool,
    pub(super) fail_write: AtomicU32,
    corrupt_dma: AtomicBool,
    tear_dma: AtomicBool,
    late_final_reply: AtomicBool,
    block: Mutex<Option<Arc<ReadBlock>>>,
    sleep_block: Mutex<Option<(Duration, Arc<ReadBlock>)>>,
}
impl Fake {
    pub(super) fn new(model: Model, mask: u32) -> Arc<Self> {
        Arc::new(Self {
            model,
            claimed: AtomicBool::new(false),
            regs: Mutex::new(BTreeMap::from([(0, 0x1234_abcd), (8, mask)])),
            dma: Mutex::new(vec![0; DMA_BYTES]),
            events: Mutex::new(Vec::new()),
            returns: Mutex::new(VecDeque::new()),
            tachs: Mutex::new(VecDeque::new()),
            replies: Mutex::new(VecDeque::new()),
            management_timeout: AtomicBool::new(false),
            bc_timeout: AtomicBool::new(false),
            fail_write: AtomicU32::new(u32::MAX),
            corrupt_dma: AtomicBool::new(false),
            tear_dma: AtomicBool::new(false),
            late_final_reply: AtomicBool::new(false),
            block: Mutex::new(None),
            sleep_block: Mutex::new(None),
        })
    }
    fn words(&self, words: &[u32]) {
        self.returns.lock().unwrap().extend(words);
    }
    fn reply(&self, bytes: &[u8]) {
        self.replies.lock().unwrap().extend(bytes);
    }
    pub(super) fn writes(&self) -> Vec<(u32, u32)> {
        self.events
            .lock()
            .unwrap()
            .iter()
            .filter_map(|e| {
                if let Event::Write(a, v) = e {
                    Some((*a, *v))
                } else {
                    None
                }
            })
            .collect()
    }
}
impl Hardware for Fake {
    fn model(&self) -> Model {
        self.model
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
        self.events.lock().unwrap().push(Event::Read(offset));
        let value = match offset {
            4 => self
                .tachs
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| self.regs.lock().unwrap().get(&4).copied().unwrap_or(0)),
            0x10 | 0x14 => self
                .returns
                .lock()
                .unwrap()
                .pop_front()
                .ok_or("FIFO empty")?,
            0x18 => self.returns.lock().unwrap().len() as u32,
            0x30 => {
                if self.management_timeout.load(Ordering::SeqCst) {
                    0
                } else if self.regs.lock().unwrap().get(&offset).copied().unwrap_or(0) & 0x02000000
                    != 0
                {
                    let mut replies = self.replies.lock().unwrap();
                    let byte = replies.pop_front().ok_or("reply empty")?;
                    let final_byte = replies.is_empty();
                    drop(replies);
                    if final_byte && self.late_final_reply.swap(false, Ordering::SeqCst) {
                        std::thread::sleep(Duration::from_millis(700));
                    }
                    BUSY | u32::from(byte)
                } else {
                    BUSY
                }
            }
            _ => self.regs.lock().unwrap().get(&offset).copied().unwrap_or(0),
        };
        let block = self.block.lock().unwrap().clone();
        if let Some(block) =
            block.filter(|b| b.offset == offset && !b.entered.swap(true, Ordering::SeqCst))
        {
            let released = block.released.lock().unwrap();
            let (_released, result) = block
                .condition
                .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                .unwrap();
            if result.timed_out() {
                return Err("test read block timed out".into());
            }
        }
        Ok(value)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Write(offset, value));
        if self.fail_write.load(Ordering::SeqCst) == offset {
            return Err("injected store failure".into());
        }
        let saved = if offset == BC && !self.bc_timeout.load(Ordering::SeqCst) {
            value & !BUSY
        } else {
            value
        };
        self.regs.lock().unwrap().insert(offset, saved);
        Ok(())
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> Result<(), String> {
        self.events
            .lock()
            .unwrap()
            .push(Event::DmaRead(offset, out.len()));
        let mut dma = self.dma.lock().unwrap();
        out.copy_from_slice(
            dma.get(offset..offset + out.len())
                .ok_or("DMA read bounds")?,
        );
        if self.corrupt_dma.load(Ordering::SeqCst) && offset >= 0x200000 {
            out[0] ^= 1;
        }
        if self.tear_dma.load(Ordering::SeqCst) && offset < 0x200000 {
            dma[offset] ^= 1;
        }
        Ok(())
    }
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> Result<(), String> {
        self.events
            .lock()
            .unwrap()
            .push(Event::DmaWrite(offset, bytes.len()));
        self.dma
            .lock()
            .unwrap()
            .get_mut(offset..offset + bytes.len())
            .ok_or("DMA write bounds")?
            .copy_from_slice(bytes);
        Ok(())
    }
    fn barrier(&self) -> Result<(), String> {
        self.events.lock().unwrap().push(Event::Barrier);
        Ok(())
    }
    fn sleep(&self, duration: Duration) {
        self.events
            .lock()
            .unwrap()
            .push(Event::Sleep(duration.as_micros() as u64));
        let block = self.sleep_block.lock().unwrap().clone();
        if let Some((_, block)) = block.filter(|(selected, block)| {
            *selected == duration && !block.entered.swap(true, Ordering::SeqCst)
        }) {
            let released = block.released.lock().unwrap();
            let (_released, result) = block
                .condition
                .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
                .unwrap();
            assert!(!result.timed_out(), "test source wait block timed out");
        }
    }
}
fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(30)
}
pub(super) async fn owner(model: Model) -> (Arc<Fake>, Arc<Transport<Fake>>) {
    let fake = Fake::new(model, 1);
    let owner = Transport::observe(fake.clone(), model, vec![0])
        .await
        .unwrap();
    (fake, owner)
}
fn packet(id: u32) -> Vec<u8> {
    // Independent fixed-format fixture, patterned from the original parser's
    // source offsets rather than invoking a production serialization helper.
    let mut bytes = vec![0u8; 0x58 + 64];
    bytes[0] = 0x52;
    let body = bytes.len() as u32 - 8;
    bytes[4..8].copy_from_slice(&body.to_le_bytes());
    bytes[9] = 1;
    bytes[10] = 6;
    bytes[0x0c..0x10].copy_from_slice(&id.to_le_bytes());
    bytes[0x10..0x14].copy_from_slice(&0x20000000u32.to_le_bytes());
    bytes[0x34..0x38].copy_from_slice(&0x65000000u32.to_le_bytes());
    bytes[0x38..0x3c].copy_from_slice(&0x1d00ffffu32.to_le_bytes());
    bytes[0x3c..0x3e].copy_from_slice(&64u16.to_le_bytes());
    bytes[0x3e..0x40].copy_from_slice(&8u16.to_le_bytes());
    bytes[0x40] = 8;
    bytes[0x58..].fill(0x42);
    bytes
}

#[tokio::test]
async fn exact_population_model_and_single_mapping_claim() {
    let fake = Fake::new(Model::S17e, 1);
    assert!(Transport::observe(fake.clone(), Model::T17e, vec![0])
        .await
        .is_err());
    assert!(fake.events.lock().unwrap().is_empty());
    assert!(Transport::observe(fake.clone(), Model::S17e, vec![1])
        .await
        .is_err());
    let observed = Transport::observe(fake.clone(), Model::S17e, vec![0])
        .await
        .unwrap();
    assert_eq!(observed.observed_version(), 0x1234abcd); // No C501/B025 gate.
    assert!(Transport::observe(fake, Model::S17e, vec![0])
        .await
        .is_err());
    let alias = Fake::new(Model::T17e, 0x101);
    assert!(Transport::observe(alias.clone(), Model::T17e, vec![0, 8])
        .await
        .is_err());
    assert!(alias.events.lock().unwrap().is_empty());
}

#[tokio::test]
async fn original_bc_read_and_write_words_and_completion_polarity() {
    for model in [Model::S17e, Model::T17e] {
        let (fake, owner) = owner(model).await;
        owner
            .request_register(0, Some(0x42), 0x18, deadline())
            .await
            .unwrap();
        assert_eq!(
            fake.writes(),
            vec![
                (0xc4, 0x42054218),
                (0xc8, 0x02000000),
                (0xcc, 0),
                (0xc0, 0x80800000)
            ]
        );
        fake.events.lock().unwrap().clear();
        owner
            .write_register(0, Some(0), 0x18, 0x12345678, deadline())
            .await
            .unwrap();
        let frame = dcentrald_common::bm1396_contract::bm1396_write_register_frame(
            false, 0, 0x18, 0x12345678,
        );
        assert_eq!(fake.writes()[0], (0xc4, 0x41090018));
        assert_eq!(fake.writes()[1], (0xc8, 0x12345678));
        assert_eq!(fake.writes()[2], (0xcc, u32::from(frame[8]) << 24));
    }
}

#[tokio::test]
async fn bc_partial_store_and_busy_timeout_never_publish_again() {
    for failure in [0xc8, 0xc0] {
        let (fake, owner) = owner(Model::S17e).await;
        fake.fail_write.store(failure, Ordering::SeqCst);
        assert!(owner
            .request_register(0, None, 0, deadline())
            .await
            .is_err());
        assert!(owner.is_terminal() && owner.asic_fault.load(Ordering::SeqCst));
        let writes = fake.writes();
        assert!(owner
            .request_register(0, None, 0, deadline())
            .await
            .is_err());
        assert_eq!(fake.writes(), writes);
        assert!(!writes.iter().any(|(offset, _)| *offset == BC) || failure == BC);
    }
    let (fake, owner) = owner(Model::T17e).await;
    fake.bc_timeout.store(true, Ordering::SeqCst);
    assert!(owner
        .request_register(0, None, 0, deadline())
        .await
        .is_err());
    assert_eq!(
        fake.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == Event::Read(BC))
            .count(),
        3002
    );
    assert_eq!(
        fake.writes()
            .iter()
            .filter(|(offset, _)| *offset == BC)
            .count(),
        1
    );
}

#[tokio::test]
async fn retained_register_carry_invalid_marker_and_ack_identity() {
    let (fake, owner) = owner(Model::S17e).await;
    // Normal register bytes [chain0,reg18,chip42,crc02], value11223344.
    fake.words(&[0x02421800, 0x11223344, 0x11, 0x5555aaaa]);
    assert_eq!(owner.poll_returns(1, deadline()).await.unwrap(), 1);
    let record = owner.pending_returns().unwrap().remove(0);
    match record.payload() {
        ReturnPayload::Register(r) => {
            assert_eq!(r.chip_address, 0x42);
            assert_eq!(r.register, 0x18);
            assert_eq!(r.value, 0x11223344);
        }
        other => panic!("{other:?}"),
    }
    let (_, foreign) = self::owner(Model::S17e).await;
    assert!(foreign.acknowledge_return(&record).is_err());
    owner.acknowledge_return(&record).unwrap();
    assert!(owner.acknowledge_return(&record).is_err());
    // First-marker carry is not synthesized from zeros.
    let (fake, owner) = self::owner(Model::S17e).await;
    fake.words(&[0, 0x5555aaaa]);
    assert!(owner.poll_returns(1, deadline()).await.is_err());
    assert_eq!(
        owner.pending_returns().unwrap()[0].words(),
        &[0, 0x5555aaaa]
    );
    assert!(owner.is_terminal());
}

#[tokio::test]
async fn cancelled_fifo_worker_keeps_partial_words_until_actual_drain() {
    let (fake, owner) = owner(Model::S17e).await;
    fake.words(&[0x02421800, 0x11223344, 0, 0x5555aaaa]);
    let block = ReadBlock::new(0x10);
    *fake.block.lock().unwrap() = Some(block.clone());
    let copy = owner.clone();
    let task = tokio::spawn(async move { copy.poll_returns(1, deadline()).await });
    let until = Instant::now() + Duration::from_secs(2);
    while !block.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    task.abort();
    let _ = task.await;
    assert!(owner.is_terminal());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(5))
        .await
        .is_err());
    block.release();
    owner.drain(deadline()).await.unwrap();
    assert_eq!(owner.partial_return_words().unwrap(), vec![0x02421800]);
    assert_eq!(fake.returns.lock().unwrap().len(), 3);
    assert!(owner.poll_returns(1, deadline()).await.is_err());
}

#[tokio::test]
async fn exact_dma_order_alternates_buffers_and_retains_cancelled_or_failed_jobs() {
    let (fake, owner) = owner(Model::S17e).await;
    owner.initialize_dma(deadline()).await.unwrap();
    assert_eq!(
        fake.writes(),
        vec![(0x100, 0), (0x110, DMA_BASE), (0x118, DMA_BASE + 0x200000)]
    );
    fake.events.lock().unwrap().clear();
    let first = owner
        .publish_job(packet(7), false, 400, deadline())
        .await
        .unwrap();
    assert!(first.completed());
    assert_eq!(first.buffer(), 0);
    let events = fake.events.lock().unwrap().clone();
    let copy = events
        .iter()
        .position(|e| matches!(e, Event::DmaWrite(0x200000, _)))
        .unwrap();
    let verify = events
        .iter()
        .position(|e| matches!(e, Event::DmaRead(0x200000, _)))
        .unwrap();
    let address = events
        .iter()
        .position(|e| *e == Event::Write(0x118, DMA_BASE + 0x200000))
        .unwrap();
    assert!(copy < verify && verify < address);
    assert_eq!(fake.regs.lock().unwrap()[&0x100] & !0x80, 0x8160);
    let second = owner
        .publish_job(packet(8), false, 400, deadline())
        .await
        .unwrap();
    assert_eq!(second.buffer(), 1);
    assert_eq!(fake.regs.lock().unwrap()[&0x118], DMA_BASE + 0x210000);
    fake.corrupt_dma.store(true, Ordering::SeqCst);
    assert!(owner
        .publish_job(packet(9), false, 400, deadline())
        .await
        .is_err());
    let saved = owner.publications().unwrap();
    assert_eq!(saved.len(), 3);
    assert!(!saved[2].completed());
    assert_eq!(saved[2].packet(), packet(9));
    assert_eq!(fake.regs.lock().unwrap()[&0x118], DMA_BASE + 0x210000);
    assert!(owner.is_terminal());
}

#[tokio::test]
async fn dma_table_nonce_requires_stable_copies_and_retained_job() {
    for tear in [false, true] {
        let (fake, owner) = owner(Model::S17e).await;
        owner.initialize_dma(deadline()).await.unwrap();
        owner
            .publish_job(packet(17), false, 400, deadline())
            .await
            .unwrap();
        fake.dma.lock().unwrap()[64..68].copy_from_slice(&17u32.to_le_bytes());
        fake.tear_dma.store(tear, Ordering::SeqCst);
        fake.words(&[0x80010080, 0, 0, 0x5555aaaa]);
        let result = owner.poll_returns(1, deadline()).await;
        assert_eq!(result.is_err(), tear);
        let records = owner.pending_returns().unwrap();
        assert_eq!(records.len(), 1);
        if !tear {
            match records[0].payload() {
                ReturnPayload::Nonce { nonce, outstanding } => {
                    assert_eq!(nonce.work_id, 1);
                    assert_eq!(outstanding.publication().job_id(), 17);
                }
                other => panic!("{other:?}"),
            }
        } else {
            assert!(matches!(
                records[0].payload(),
                ReturnPayload::Unclassified(_)
            ));
        }
    }
}

#[tokio::test]
async fn work_and_return_owner_seals_distinguish_identical_foreign_and_partial_publications() {
    let (fake, owner) = owner(Model::T17e).await;
    let (other_fake, other) = self::owner(Model::T17e).await;
    owner.initialize_dma(deadline()).await.unwrap();
    other.initialize_dma(deadline()).await.unwrap();
    let first = owner
        .publish_job(packet(0), false, 400, deadline())
        .await
        .unwrap();
    let foreign = other
        .publish_job(packet(0), false, 400, deadline())
        .await
        .unwrap();
    assert_eq!(first.packet(), foreign.packet());
    assert_eq!(first.job_id(), foreign.job_id());
    assert_eq!(first.sequence(), foreign.sequence());
    assert!(first.completed() && foreign.completed());
    assert!(first.same_owner(&owner) && first.clone().same_owner(&owner));
    assert!(!first.same_owner(&other) && !foreign.same_owner(&owner));
    for hardware in [&fake, &other_fake] {
        hardware.dma.lock().unwrap()[64..68].copy_from_slice(&0u32.to_le_bytes());
        hardware.words(&[0x80010080, 0, 0, 0x5555aaaa]);
    }
    owner.poll_returns(1, deadline()).await.unwrap();
    other.poll_returns(1, deadline()).await.unwrap();
    let raw = owner.pending_returns().unwrap().remove(0);
    let foreign_raw = other.pending_returns().unwrap().remove(0);
    assert_eq!(raw.words(), foreign_raw.words());
    assert!(raw.same_owner(&owner) && raw.clone().same_owner(&owner));
    assert!(!raw.same_owner(&other) && !foreign_raw.same_owner(&owner));
    let ReturnPayload::Nonce { outstanding, .. } = raw.payload() else {
        panic!("actual nonce expected")
    };
    assert!(outstanding.publication().same_owner(&owner));
    assert!(!outstanding.publication().same_owner(&other));
    assert!(other.acknowledge_return(&raw).is_err());
    fake.corrupt_dma.store(true, Ordering::SeqCst);
    assert!(owner
        .publish_job(packet(1), false, 400, deadline())
        .await
        .is_err());
    let incomplete = owner.publications().unwrap().pop().unwrap();
    assert!(incomplete.same_owner(&owner) && !incomplete.same_owner(&other));
    assert!(!incomplete.completed());
}

async fn application() -> (Arc<Fake>, Arc<Transport<Fake>>, Arc<PicApplication<Fake>>) {
    let (fake, owner) = owner(Model::S17e).await;
    let app = PicApplication::claim(owner.clone()).unwrap();
    fake.reply(&[5, 0x17, 0x89, 0, 0]);
    app.observe_versions(deadline()).await.unwrap();
    (fake, owner, app)
}
async fn qualify(fake: &Fake, app: &Arc<PicApplication<Fake>>) {
    for _ in 0..5 {
        fake.reply(&[6, 0x16, 1, 0, 0, 0]);
        app.heartbeat_round(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn pic_application_five_whole_rounds_voltage_frame_and_opaque_reply() {
    let (fake, owner, app) = application().await;
    assert!(PicApplication::claim(owner).is_err());
    // Rejected envelope parameters perform no I/O and preserve qualification.
    let before = fake.writes();
    assert!(app.command_voltage_cv(1799, deadline()).await.is_err());
    assert_eq!(fake.writes(), before);
    qualify(&fake, &app).await;
    fake.events.lock().unwrap().clear();
    fake.reply(&[0x55, 0xaa, 6, 0x83, 12, 0, 0x95, 0]);
    let voltage = app.command_voltage_cv(1800, deadline()).await.unwrap();
    assert_eq!(voltage.dac(), 120);
    assert_eq!(voltage.response()[4], 12);
    assert_eq!(
        fake.writes(),
        [
            vec![
                (0x30, 0x05201155),
                (0x30, 0x052011aa),
                (0x30, 0x05201106),
                (0x30, 0x05201183),
                (0x30, 0x05201178),
                (0x30, 0x05201100),
                (0x30, 0x05201101),
                (0x30, 0x05201101)
            ],
            vec![(0x30, 0x06200000); 8]
        ]
        .concat()
    );
    assert_eq!(app.last_commanded_voltage().unwrap(), Some(voltage));
}

#[tokio::test]
async fn incomplete_management_byte_quarantines_and_refuses_terminal_off() {
    let (fake, owner) = owner(Model::T17e).await;
    let app = PicApplication::claim(owner.clone()).unwrap();
    fake.management_timeout.store(true, Ordering::SeqCst);
    fake.reply(&[5, 0x17, 0x89, 0, 0]); // Later ACK cannot repair first-byte ambiguity.
    assert!(app.observe_versions(deadline()).await.is_err());
    assert_eq!(fake.writes(), vec![(0x30, 0x00400055)]);
    assert_eq!(
        fake.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| **e == Event::Read(0x30))
            .count(),
        102
    );
    assert!(owner.management_fault.load(Ordering::SeqCst));
    assert!(app.disable_all(deadline(), true).await.is_err());
    assert_eq!(fake.writes().len(), 1);
}

#[tokio::test]
async fn complete_rejected_frame_does_not_invent_portal_ambiguity() {
    let (fake, owner) = owner(Model::S17e).await;
    let app = PicApplication::claim(owner.clone()).unwrap();
    fake.reply(&[5, 0x18, 0x89, 0, 0]);
    assert!(app.observe_versions(deadline()).await.is_err());
    assert!(owner.is_terminal());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
    fake.reply(&[0x15, 1]);
    assert_eq!(
        app.disable_all(deadline(), true).await.unwrap()[0].bytes(),
        &[0x15, 1]
    );
}

#[tokio::test]
async fn late_final_response_is_terminal_but_complete_frame_allows_fixed_off() {
    let (fake, owner) = owner(Model::S17e).await;
    let app = PicApplication::claim(owner.clone()).unwrap();
    fake.reply(&[5, 0x17, 0x89, 0, 0]);
    fake.late_final_reply.store(true, Ordering::SeqCst);
    assert!(app
        .observe_versions(Instant::now() + Duration::from_millis(600))
        .await
        .is_err());
    assert!(owner.is_terminal());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
    assert_eq!(fake.writes().len(), 11);
    fake.reply(&[0x15, 1]);
    assert!(app.disable_all(deadline(), true).await.is_ok());
}

#[tokio::test]
async fn admitted_heartbeat_finishes_after_cut_without_refresh_or_sibling_frame() {
    let (fake, owner, app) = application().await;
    fake.events.lock().unwrap().clear();
    fake.reply(&[6, 0x16, 1, 0, 0, 0]);
    let block = ReadBlock::new(0x30);
    *fake.block.lock().unwrap() = Some(block.clone());
    let copy = app.clone();
    let task = tokio::spawn(async move { copy.heartbeat_round(deadline()).await });
    let until = Instant::now() + Duration::from_secs(2);
    while !block.entered.load(Ordering::SeqCst) {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    owner.begin_terminal();
    block.release();
    assert!(task.await.unwrap().is_err());
    assert_eq!(fake.writes().len(), 12);
    assert!(!owner.management_fault.load(Ordering::SeqCst));
    fake.reply(&[0x15, 1]);
    assert!(app.disable_all(deadline(), true).await.is_ok());
}
