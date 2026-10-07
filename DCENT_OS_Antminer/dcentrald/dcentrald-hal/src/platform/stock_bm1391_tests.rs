use super::*;
use std::collections::VecDeque;

#[derive(Default)]
pub(super) struct Recorded {
    pub(super) writes: Vec<(u32, u32)>,
    pub(super) events: Vec<serde_json::Value>,
    pub(super) returns: VecDeque<(u32, u32)>,
    pub(super) fail_at: Option<usize>,
}
pub(super) struct RecordingRegisters {
    pub(super) version: u32,
    pub(super) present: u32,
    pub(super) space: u32,
    pub(super) command_stuck: bool,
    pub(super) iic_stuck: bool,
    pub(super) state: Mutex<Recorded>,
}
impl Default for RecordingRegisters {
    fn default() -> Self {
        Self {
            version: 0xc501,
            present: 7,
            space: 7,
            command_stuck: false,
            iic_stuck: false,
            state: Mutex::default(),
        }
    }
}
impl Registers for RecordingRegisters {
    fn read(&self, offset: u32) -> Result<u32, String> {
        let mut state = self.state.lock().unwrap();
        match offset {
            0x30 => {
                let command = state
                    .writes
                    .iter()
                    .rev()
                    .find(|(offset, _)| *offset == 0x30)
                    .unwrap()
                    .1;
                Ok(if self.iic_stuck {
                    0
                } else {
                    0x8000_0000 | (((command >> 8) & 0xff) ^ ((command >> 16) & 7))
                })
            }
            VERSION => Ok(self.version),
            PRESENCE => Ok(self.present),
            WORK_SPACE => Ok(self.space),
            COMMAND_CONTROL => Ok(
                if self.command_stuck
                    && state
                        .writes
                        .iter()
                        .any(|(offset, _)| *offset == COMMAND_CONTROL)
                {
                    0x8000_0000
                } else {
                    0
                },
            ),
            RETURN_COUNT => Ok(state.returns.len() as u32),
            RETURN0 => Ok(state.returns.front().unwrap().0),
            RETURN1 => Ok(state.returns.pop_front().unwrap().1),
            _ => Err(format!("unexpected fixture read {offset:x}")),
        }
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        if state.fail_at == Some(state.writes.len()) {
            return Err("injected FIFO write failure".into());
        }
        state.writes.push((offset, value));
        state
            .events
            .push(serde_json::json!({"offset": offset, "value": value}));
        Ok(())
    }
}
fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    std::array::from_fn(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap())
}
pub(super) fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}
pub(super) fn sample_work(chain: u8) -> Work {
    Work::from_wire_parts(chain, 0x7fff, [1; 12], [2; 32]).unwrap()
}

#[derive(Default)]
struct ClaimedRegisters {
    inner: RecordingRegisters,
    claimed: AtomicBool,
    reads: std::sync::atomic::AtomicUsize,
    dropped: Arc<AtomicBool>,
}
impl Registers for ClaimedRegisters {
    fn claim_transport(&self) -> Result<(), String> {
        // The actual NativeMmio claim uses this same atomic operation. The
        // scripted register values avoid opening devmem or a physical lease.
        claim_mapping_transport(&self.claimed)
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.read(offset)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.inner.write(offset, value)
    }
}
impl Drop for ClaimedRegisters {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn cloned_mapping_cannot_create_a_second_transport_or_release_the_first_claim() {
    for version in [0xc501, 0xc502] {
        let mut fixture = ClaimedRegisters::default();
        fixture.inner.version = version;
        let registers = Arc::new(fixture);
        let dropped = registers.dropped.clone();
        assert!(Transport::new(registers.clone(), vec![]).is_err());
        assert!(!registers.claimed.load(Ordering::SeqCst));
        assert_eq!(registers.reads.load(Ordering::SeqCst), 0);
        let first = Transport::new(registers.clone(), vec![0]);
        assert_eq!(first.is_ok(), version == 0xc501);
        let observed_reads = registers.reads.load(Ordering::SeqCst);
        assert!(observed_reads > 0);
        assert!(Transport::new(registers.clone(), vec![0]).is_err());
        assert_eq!(registers.reads.load(Ordering::SeqCst), observed_reads);
        drop(first);
        assert!(!dropped.load(Ordering::SeqCst));
        // Neither validation failure nor dropping the first transport resets
        // custody while another Arc still retains that exact mapping.
        assert!(Transport::new(registers.clone(), vec![0]).is_err());
        assert_eq!(registers.reads.load(Ordering::SeqCst), observed_reads);
        drop(registers);
        assert!(dropped.load(Ordering::SeqCst));
    }
}

#[test]
fn concurrent_constructors_share_one_mapping_claim_and_one_register_observation() {
    let registers = Arc::new(ClaimedRegisters::default());
    let ready = Arc::new(std::sync::Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let registers = registers.clone();
        let ready = ready.clone();
        workers.push(std::thread::spawn(move || {
            ready.wait();
            Transport::new(registers, vec![0])
        }));
    }
    ready.wait();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(registers.reads.load(Ordering::SeqCst), 2);
}

#[test]
fn unsuccessful_asic_guard_publishes_terminal_before_releasing_a_waiting_peer() {
    let registers = Arc::new(RecordingRegisters::default());
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let transaction = owner.begin_asic_transaction(deadline()).unwrap();
    let (waiting, ready) = std::sync::mpsc::channel();
    let peer_owner = owner.clone();
    let peer = std::thread::spawn(move || {
        assert!(peer_owner.lane.try_lock().is_err());
        waiting.send(()).unwrap();
        let lane = peer_owner.lock_until(deadline()).unwrap();
        // There is no later caller-side latch in this test. The unsuccessful
        // transaction's Drop must publish it before releasing this exact lane.
        assert!(peer_owner.terminal());
        drop(lane);
        assert!(peer_owner
            .publish_work(&sample_work(0), deadline())
            .is_err());
    });
    ready.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(!owner.terminal());
    drop(transaction);
    peer.join().unwrap();
    assert!(registers.state.lock().unwrap().writes.is_empty());
}

#[test]
fn partial_work_failure_cannot_admit_the_already_waiting_next_frame() {
    struct FailingRegisters {
        inner: RecordingRegisters,
        writes: std::sync::atomic::AtomicUsize,
        reached: std::sync::mpsc::Sender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Registers for FailingRegisters {
        fn read(&self, offset: u32) -> Result<u32, String> {
            self.inner.read(offset)
        }
        fn write(&self, offset: u32, value: u32) -> Result<(), String> {
            if self.writes.fetch_add(1, Ordering::SeqCst) == 3 {
                self.reached.send(()).unwrap();
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(1))
                    .unwrap();
                return Err("injected partial frame with another producer waiting".into());
            }
            self.inner.write(offset, value)
        }
    }
    let (reached, in_failure) = std::sync::mpsc::channel();
    let (release, wait_release) = std::sync::mpsc::channel();
    let registers = Arc::new(FailingRegisters {
        inner: RecordingRegisters::default(),
        writes: std::sync::atomic::AtomicUsize::new(0),
        reached,
        release: Mutex::new(wait_release),
    });
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let first_owner = owner.clone();
    let first = std::thread::spawn(move || first_owner.publish_work(&sample_work(0), deadline()));
    in_failure.recv_timeout(Duration::from_secs(1)).unwrap();
    let (waiting, ready) = std::sync::mpsc::channel();
    let peer_owner = owner.clone();
    let peer = std::thread::spawn(move || {
        assert!(peer_owner.lane.try_lock().is_err());
        waiting.send(()).unwrap();
        peer_owner.publish_work(&sample_work(0), deadline())
    });
    ready.recv_timeout(Duration::from_secs(1)).unwrap();
    release.send(()).unwrap();
    assert!(first.join().unwrap().is_err());
    assert!(peer.join().unwrap().is_err());
    assert!(owner.terminal());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 3);
    assert_eq!(registers.writes.load(Ordering::SeqCst), 4);
}

#[test]
fn complete_asic_operation_keeps_lane_usable_but_unwind_latches_terminal() {
    let registers = Arc::new(RecordingRegisters::default());
    let owner = Transport::new(registers, vec![0]).unwrap();
    owner.with_asic_lane(deadline(), || Ok(())).unwrap();
    assert!(!owner.terminal());
    owner.publish_work(&sample_work(0), deadline()).unwrap();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        owner.with_asic_lane(deadline(), || -> Result<(), String> {
            panic!("unexpected injected backend panic");
        })
    }));
    assert!(unwound.is_err());
    assert!(owner.terminal());
    assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
}

#[tokio::test]
async fn aborting_each_async_asic_initializer_stops_its_detached_worker() {
    struct PausedRegisters {
        inner: RecordingRegisters,
        reached: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Registers for PausedRegisters {
        fn read(&self, offset: u32) -> Result<u32, String> {
            self.inner.read(offset)
        }
        fn write(&self, offset: u32, value: u32) -> Result<(), String> {
            self.inner.write(offset, value)?;
            if offset == COMMAND_CONTROL {
                if let Some(reached) = self.reached.lock().unwrap().take() {
                    reached.send(()).unwrap();
                    self.release
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(1))
                        .unwrap();
                }
            }
            Ok(())
        }
    }
    for operation in ["addresses", "census", "cores"] {
        let (reached, in_command) = tokio::sync::oneshot::channel();
        let (release, wait_release) = std::sync::mpsc::channel();
        let registers = Arc::new(PausedRegisters {
            inner: RecordingRegisters::default(),
            reached: Mutex::new(Some(reached)),
            release: Mutex::new(wait_release),
        });
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        let worker_owner = owner.clone();
        let worker = tokio::spawn(async move {
            match operation {
                "addresses" => {
                    worker_owner
                        .configure_addresses(Model::S15, 0, deadline())
                        .await
                }
                "census" => worker_owner
                    .census(Model::S15, 0, deadline())
                    .await
                    .map(|_| ()),
                "cores" => worker_owner.initialize_cores(0, deadline()).await,
                _ => unreachable!(),
            }
        });
        tokio::time::timeout(Duration::from_secs(1), in_command)
            .await
            .unwrap()
            .unwrap();
        assert!(!owner.terminal());
        assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 4);
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        assert!(
            owner.terminal(),
            "{operation} cancellation detached an active worker"
        );
        release.send(()).unwrap();
        owner.terminal_drain(deadline()).unwrap();
        assert_eq!(
            registers.inner.state.lock().unwrap().writes.len(),
            4,
            "{operation} issued another command after its async caller was cancelled"
        );
        assert!(owner.publish_work(&sample_work(0), deadline()).is_err());
    }
}

#[test]
fn actual_mmio_publication_matches_all_original_arm_serializers() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut vectors = 0;
    let mut written = 0;
    let mut rejected_physical_slots = 0;
    for release in oracle["releases"].as_array().unwrap() {
        assert!(matches!(
            release["source_sha256"].as_str().unwrap(),
            "3cf4302b87d5c5588f3c6cbfb2eb3e46dc7545da4d62f715651e84e0dde119c8"
                | "fdeaf71ab1d8e1613e9dd0353621cd07c349179d450999d51e31e0df308cdf01"
        ));
        for vector in release["vectors"].as_array().unwrap() {
            let registers = Arc::new(RecordingRegisters::default());
            let transport = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
            let chain = vector["chain"].as_u64().unwrap() as u8;
            let id = vector["work_id"].as_u64().unwrap() as u16;
            let work = Work::from_wire_parts(
                chain,
                id,
                hex(vector["tail_hex"].as_str().unwrap()),
                hex(vector["midstate_hex"].as_str().unwrap()),
            )
            .unwrap();
            let expected: Vec<_> = vector["writes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|write| {
                    (
                        write["offset"].as_u64().unwrap() as u32,
                        write["value"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            assert_eq!(
                work.words.as_slice(),
                expected.iter().map(|(_, value)| *value).collect::<Vec<_>>()
            );
            if chain > 2 {
                // The original serializer accepts a four-bit protocol slot.
                // These two boundary vectors do not create physical slot15.
                assert!(transport.publish_work(&work, deadline()).is_err());
                assert!(registers.state.lock().unwrap().writes.is_empty());
                vectors += 1;
                rejected_physical_slots += 1;
                continue;
            }
            transport.publish_work(&work, deadline()).unwrap();
            assert_eq!(registers.state.lock().unwrap().writes, expected);
            assert_eq!(work.id(), id);
            assert_eq!(work.chain(), chain);
            assert_eq!(expected.len(), 13);
            vectors += 1;
            written += expected.len();
        }
    }
    assert_eq!((vectors, written, rejected_physical_slots), (8, 78, 2));
}

#[test]
fn actual_register_publication_matches_sixty_original_encodings_and_crc5() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut vectors = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for vector in release["vectors"].as_array().unwrap() {
            let registers = Arc::new(RecordingRegisters::default());
            let transport = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
            transport
                .write_register(
                    vector["chain"].as_u64().unwrap() as u8,
                    vector["address"].as_u64().unwrap() as u8,
                    vector["broadcast"].as_bool().unwrap(),
                    vector["register"].as_u64().unwrap() as u8,
                    vector["payload"].as_u64().unwrap() as u32,
                    deadline(),
                )
                .unwrap();
            let expected: Vec<_> = vector["writes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|write| {
                    (
                        write["offset"].as_u64().unwrap() as u32,
                        write["value"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            assert_eq!(registers.state.lock().unwrap().writes, expected);
            assert_eq!(expected.len(), 4);
            transport.terminal_drain(deadline()).unwrap();
            assert!(transport
                .write_register(0, 0, true, 8, 0x40780111, deadline())
                .is_err());
            assert_eq!(registers.state.lock().unwrap().writes, expected);
            vectors += 1;
        }
    }
    assert_eq!(vectors, 60);
}

#[test]
fn actual_address_publication_matches_original_vil_encodings() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut vectors = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for vector in release["vectors"].as_array().unwrap() {
            let registers = Arc::new(RecordingRegisters::default());
            let transport = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
            let chain = vector["chain"].as_u64().unwrap() as u8;
            let address = vector["address"].as_u64().unwrap() as u8;
            match vector["operation"].as_str().unwrap() {
                "inactive" => transport.chain_inactive(chain, deadline()),
                "assign_address" => transport.assign_address(chain, address, deadline()),
                "address_register" => transport.write_address_register(chain, address, deadline()),
                other => panic!("unexpected original operation {other}"),
            }
            .unwrap();
            let expected: Vec<_> = vector["writes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    (
                        row["offset"].as_u64().unwrap() as u32,
                        row["value"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            assert_eq!(registers.state.lock().unwrap().writes, expected, "{vector}");
            assert_eq!(expected.len(), 4);
            vectors += 1;
        }
    }
    assert_eq!(vectors, 54);
}

#[test]
fn actual_read_requests_match_both_original_releases() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut vectors = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for vector in release["vectors"].as_array().unwrap() {
            let registers = Arc::new(RecordingRegisters::default());
            let transport = Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
            transport
                .request_register(
                    vector["chain"].as_u64().unwrap() as u8,
                    vector["address"].as_u64().unwrap() as u8,
                    vector["broadcast"].as_bool().unwrap(),
                    vector["register"].as_u64().unwrap() as u8,
                    deadline(),
                )
                .unwrap();
            let expected: Vec<_> = vector["writes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| {
                    (
                        row["offset"].as_u64().unwrap() as u32,
                        row["value"].as_u64().unwrap() as u32,
                    )
                })
                .collect();
            assert_eq!(registers.state.lock().unwrap().writes, expected, "{vector}");
            assert_eq!(expected.len(), 4);
            // These fixtures prove request publication and do not synthesize
            // chip responses or claim discovery from command completion.
            assert!(transport.read_return(deadline()).unwrap().is_none());
            vectors += 1;
        }
    }
    assert_eq!(vectors, 180);
}

#[test]
fn complete_address_sequences_match_original_command_and_delay_order() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut writes = 0;
    for release in oracle["releases"].as_array().unwrap() {
        let model = match release["model"].as_str().unwrap() {
            "s15" => Model::S15,
            "t15" => Model::T15,
            _ => unreachable!(),
        };
        for vector in release["vectors"].as_array().unwrap() {
            let registers = Arc::new(RecordingRegisters::default());
            let chain = vector["chain"].as_u64().unwrap() as u8;
            let transport = Transport::new(registers.clone(), vec![chain]).unwrap();
            transport
                .configure_addresses_with_delay(model, chain, deadline(), |delay_ms| {
                    registers
                        .state
                        .lock()
                        .unwrap()
                        .events
                        .push(serde_json::json!({"delay_ms": delay_ms}));
                    Ok(())
                })
                .unwrap();
            let state = registers.state.lock().unwrap();
            assert_eq!(&state.events, vector["events"].as_array().unwrap());
            writes += state.writes.len();
            assert_eq!(
                model.address_interval(),
                vector["address_interval"].as_u64().unwrap() as u8
            );
        }
    }
    assert_eq!(writes, 3648);
}

#[test]
fn address_sequence_failure_never_advances_to_a_later_command() {
    for model in [Model::S15, Model::T15] {
        let last_store = (3 + 2 * (256 / usize::from(model.address_interval()))) * 4 - 1;
        for failure in [0, 3, 4, 11, 12, 15, 16, last_store] {
            let registers = Arc::new(RecordingRegisters::default());
            registers.state.lock().unwrap().fail_at = Some(failure);
            let transport = Transport::new(registers.clone(), vec![0]).unwrap();
            assert!(transport
                .configure_addresses_with_delay(model, 0, deadline(), |_| Ok(()))
                .is_err());
            assert!(transport.terminal());
            assert!(transport.publish_work(&sample_work(0), deadline()).is_err());
            assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
        }
        let registers = Arc::new(RecordingRegisters::default());
        let transport = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(transport
            .configure_addresses_with_delay(model, 0, deadline(), |_| Err(
                "settling interrupted".into()
            ))
            .is_err());
        assert!(transport.terminal());
        assert_eq!(registers.state.lock().unwrap().writes.len(), 4);
    }
}

#[test]
fn terminal_drain_interrupts_address_settling_without_interleaving_work() {
    let registers = Arc::new(RecordingRegisters::default());
    let transport = Transport::new(registers.clone(), vec![0]).unwrap();
    let worker = transport.clone();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        worker.configure_addresses_with_delay(Model::S15, 0, deadline(), |_| {
            entered_tx.send(()).unwrap();
            resume_rx.recv_timeout(Duration::from_secs(1)).unwrap();
            Ok(())
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(transport
        .terminal_drain(Instant::now() + Duration::from_millis(5))
        .is_err());
    assert!(transport.terminal());
    assert!(transport
        .publish_work(&sample_work(0), Instant::now())
        .is_err());
    resume_tx.send(()).unwrap();
    assert!(thread.join().unwrap().is_err());
    transport.terminal_drain(deadline()).unwrap();
    assert_eq!(registers.state.lock().unwrap().writes.len(), 4);
}

#[tokio::test]
async fn asynchronous_address_setup_stops_at_its_real_deadline() {
    let registers = Arc::new(RecordingRegisters::default());
    let transport = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(transport
        .configure_addresses(Model::T15, 0, Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    assert!(transport.terminal());
    // Scheduling may expire before the first frame. It cannot reach a second
    // command before the original 30ms settling interval.
    assert!(matches!(
        registers.state.lock().unwrap().writes.len(),
        0 | 4
    ));
}

#[test]
fn short_commands_refuse_absent_chains_expiry_and_partial_publication() {
    let registers = Arc::new(RecordingRegisters::default());
    let transport = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(transport.chain_inactive(1, deadline()).is_err());
    assert!(transport.assign_address(2, 0, deadline()).is_err());
    assert!(transport.write_address_register(2, 0, deadline()).is_err());
    assert!(registers.state.lock().unwrap().writes.is_empty());
    for failure in 0..4 {
        let registers = Arc::new(RecordingRegisters::default());
        registers.state.lock().unwrap().fail_at = Some(failure);
        let transport = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(transport.assign_address(0, 3, deadline()).is_err());
        assert!(transport.terminal());
        assert!(transport.chain_inactive(0, deadline()).is_err());
        assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
    }
    assert!(transport.chain_inactive(0, Instant::now()).is_err());
    assert!(transport.terminal());
    assert!(registers.state.lock().unwrap().writes.is_empty());
}

#[test]
fn stock_pattern_work_and_fifo_nonce_qualify_against_independent_sha256_oracle() {
    use dcentrald_common::bm1391_share_qualification::{
        bm1391_stock_double_sha256_from_midstate, Bm1391StockPrecomputedHashInput,
    };
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut count = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for pattern in release["patterns"].as_array().unwrap() {
            let fields: Vec<_> = pattern["line"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .collect();
            let wire_midstate = hex::<32>(fields[1]);
            let wire_tail = hex::<12>(fields[3]);
            let nonce = u32::from_str_radix(fields[5], 16).unwrap();
            let midstate = std::array::from_fn(|i| {
                u32::from_be_bytes(wire_midstate[(7 - i) * 4..(8 - i) * 4].try_into().unwrap())
            });
            let tail = std::array::from_fn(|i| {
                u32::from_be_bytes(wire_tail[(2 - i) * 4..(3 - i) * 4].try_into().unwrap())
            });
            let chain = (count % 3) as u8;
            let id = 0x7ff0 + count;
            let work = Work::from_sha256_words(chain, id, midstate, tail).unwrap();
            assert_eq!(
                work,
                Work::from_wire_parts(chain, id, wire_tail, wire_midstate).unwrap()
            );
            let registers = Arc::new(RecordingRegisters::default());
            let transport = Transport::new(registers.clone(), vec![chain]).unwrap();
            transport.publish_work(&work, deadline()).unwrap();
            registers.state.lock().unwrap().returns.push_back((
                0x8000_0080 | (u32::from(id) << 16) | u32::from(chain),
                nonce,
            ));
            let Some(Bm1391StockFpgaReturn::Nonce(found)) =
                transport.read_return(deadline()).unwrap()
            else {
                panic!("missing FIFO nonce");
            };
            assert_eq!(
                (found.work_id, found.chain_slot, found.nonce),
                (id, chain, nonce)
            );
            assert!(found.stock_binding_eligible(true));
            let digest =
                bm1391_stock_double_sha256_from_midstate(Bm1391StockPrecomputedHashInput {
                    midstate_words: midstate,
                    tail_words: tail,
                    nonce3: found.nonce,
                });
            let display: String = digest
                .into_iter()
                .flat_map(u32::to_be_bytes)
                .rev()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(
                display,
                pattern["qualification"]["display_hash"].as_str().unwrap()
            );
            assert!(transport.read_return(deadline()).unwrap().is_none());
            count += 1;
        }
    }
    assert_eq!(count, 8);
}

#[test]
fn wrong_identity_population_and_work_bounds_cannot_publish() {
    assert_eq!(
        Model::S15.board_target(),
        dcentrald_common::BoardDesc::am1_s15().board_target
    );
    assert_eq!(
        Model::T15.board_target(),
        dcentrald_common::BoardDesc::am1_t15().board_target
    );
    assert_eq!(
        (Model::S15.expected_chips(), Model::T15.expected_chips()),
        (72, 60)
    );
    for registers in [
        RecordingRegisters {
            version: 0xb031,
            ..Default::default()
        },
        RecordingRegisters {
            present: 1,
            ..Default::default()
        },
    ] {
        let registers = Arc::new(registers);
        assert!(Transport::new(registers.clone(), vec![0, 1]).is_err());
        assert!(registers.state.lock().unwrap().writes.is_empty());
    }
    for chains in [vec![], vec![0, 0], vec![1, 0], vec![3]] {
        assert!(Transport::new(Arc::new(RecordingRegisters::default()), chains).is_err());
    }
    assert!(Work::from_wire_parts(16, 1, [0; 12], [0; 32]).is_err());
    assert!(Work::from_wire_parts(0, 0x8000, [0; 12], [0; 32]).is_err());
    let registers = Arc::new(RecordingRegisters::default());
    let transport = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(transport.publish_work(&sample_work(1), deadline()).is_err());
    assert!(registers.state.lock().unwrap().writes.is_empty());
}

#[test]
fn fifo_timeout_or_partial_write_latches_without_retrying_a_frame() {
    let registers = Arc::new(RecordingRegisters {
        space: 0,
        ..Default::default()
    });
    let transport = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(transport
        .publish_work(&sample_work(0), Instant::now() + Duration::from_millis(10))
        .is_err());
    assert!(transport.terminal());
    assert!(registers.state.lock().unwrap().writes.is_empty());
    for failure in 0..13 {
        let registers = Arc::new(RecordingRegisters::default());
        registers.state.lock().unwrap().fail_at = Some(failure);
        let transport = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(transport.publish_work(&sample_work(0), deadline()).is_err());
        assert!(transport.terminal());
        registers.state.lock().unwrap().fail_at = None;
        assert!(transport.publish_work(&sample_work(0), deadline()).is_err());
        assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
    }
}

#[test]
fn register_partial_publication_and_missing_completion_stop_all_later_work() {
    for failure in 0..4 {
        let registers = Arc::new(RecordingRegisters::default());
        registers.state.lock().unwrap().fail_at = Some(failure);
        let transport = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(transport
            .write_register(0, 0, true, 8, 0x40780111, deadline())
            .is_err());
        assert!(transport.terminal());
        registers.state.lock().unwrap().fail_at = None;
        assert!(transport.publish_work(&sample_work(0), deadline()).is_err());
        assert_eq!(registers.state.lock().unwrap().writes.len(), failure);
    }
    let registers = Arc::new(RecordingRegisters {
        command_stuck: true,
        ..Default::default()
    });
    let transport = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(transport
        .write_register(
            0,
            0,
            true,
            8,
            0x40780111,
            Instant::now() + Duration::from_millis(10)
        )
        .is_err());
    assert!(transport.terminal());
    assert_eq!(registers.state.lock().unwrap().writes.len(), 4);
    assert!(transport.publish_work(&sample_work(0), deadline()).is_err());
    assert_eq!(registers.state.lock().unwrap().writes.len(), 4);
}

#[test]
fn terminal_barrier_waits_for_complete_inflight_frame_and_blocks_later_writes() {
    struct PausingRegisters {
        inner: RecordingRegisters,
        entered: std::sync::mpsc::Sender<()>,
        resume: Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl Registers for PausingRegisters {
        fn read(&self, offset: u32) -> Result<u32, String> {
            self.inner.read(offset)
        }
        fn write(&self, offset: u32, value: u32) -> Result<(), String> {
            self.inner.write(offset, value)?;
            if offset == TW_FIRST {
                self.entered.send(()).unwrap();
                self.resume
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(2))
                    .unwrap();
            }
            Ok(())
        }
    }
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (resume_tx, resume_rx) = std::sync::mpsc::channel();
    let registers = Arc::new(PausingRegisters {
        inner: RecordingRegisters::default(),
        entered: entered_tx,
        resume: Mutex::new(resume_rx),
    });
    let transport = Transport::new(registers.clone(), vec![0]).unwrap();
    let writer = transport.clone();
    let task = std::thread::spawn(move || writer.publish_work(&sample_work(0), deadline()));
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!(transport
        .terminal_drain(Instant::now() + Duration::from_millis(10))
        .is_err());
    assert!(transport.terminal());
    resume_tx.send(()).unwrap();
    task.join().unwrap().unwrap();
    transport.terminal_drain(deadline()).unwrap();
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 13);
    assert!(transport.publish_work(&sample_work(0), deadline()).is_err());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 13);
}
