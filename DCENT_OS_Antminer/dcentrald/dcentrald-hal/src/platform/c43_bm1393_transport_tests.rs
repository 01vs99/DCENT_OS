use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;

struct Registers {
    values: Mutex<BTreeMap<u32, u32>>,
    writes: Mutex<Vec<(u32, u32)>>,
    pic_reply: Mutex<VecDeque<u8>>,
    iic_writes: AtomicUsize,
    fail_iic_write: usize,
    nack: tokio::sync::Notify,
    fail_work_word: AtomicUsize,
    work_words: AtomicUsize,
    fail_read_offset: AtomicUsize,
}
impl Registers {
    fn new(fail_iic_write: usize) -> Arc<Self> {
        Arc::new(Self {
            values: Mutex::new(BTreeMap::from([(8, 3), (12, 3), (0x34, 0x1000)])),
            writes: Mutex::new(Vec::new()),
            pic_reply: Mutex::new(VecDeque::from([5, 0x17, 1, 0, 0x1d])),
            iic_writes: AtomicUsize::new(0),
            fail_iic_write,
            nack: tokio::sync::Notify::new(),
            fail_work_word: AtomicUsize::new(0),
            work_words: AtomicUsize::new(0),
            fail_read_offset: AtomicUsize::new(usize::MAX),
        })
    }
}
impl C43Registers for Registers {
    fn read(&self, offset: u32) -> Result<u32, String> {
        if self.fail_read_offset.load(Ordering::SeqCst) == offset as usize {
            return Err("injected shared MMIO read failure".into());
        }
        Ok(*self.values.lock().unwrap().get(&offset).unwrap_or(&0))
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.writes.lock().unwrap().push((offset, value));
        if (offset == 0x40 || offset == 0x44)
            && self.work_words.fetch_add(1, Ordering::SeqCst) + 1
                == self.fail_work_word.load(Ordering::SeqCst)
        {
            return Err("injected partial work frame".into());
        }
        let stored = if offset == 0x30 {
            if self.iic_writes.fetch_add(1, Ordering::SeqCst) + 1 == self.fail_iic_write {
                self.nack.notify_one();
                std::thread::sleep(Duration::from_millis(50));
                return Err("injected IIC MMIO write failure".into());
            }
            let data = if value & reg::IIC_READ_BIT == 0 {
                0
            } else if value & reg::IIC_REG_VALID_BIT != 0 {
                ((value >> 8) & 255) as u8
            } else {
                self.pic_reply
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or("unexpected PIC read")?
            };
            0x8000_0000 | u32::from(data)
        } else if offset == 0xc0 {
            value & !0x8000_0000
        } else {
            value
        };
        self.values.lock().unwrap().insert(offset, stored);
        Ok(())
    }
}

#[tokio::test]
async fn protected_eeprom_emits_only_fixed_read_words_for_every_offset() {
    let registers = Registers::new(0);
    let owner = C43Transport::new(registers.clone(), vec![1]).unwrap();
    let image = owner.read_factory(1).await.unwrap();
    assert_eq!(*image, std::array::from_fn(|i| i as u8));
    let writes = registers.writes.lock().unwrap();
    assert_eq!(writes.len(), 256);
    for (offset, &(register, command)) in writes.iter().enumerate() {
        assert_eq!(register, 0x30);
        // read+registervalid, address0x51 split by actual stock packer.
        assert_eq!(command, 0x03a1_0000 | (offset as u32) << 8);
        assert_eq!(command & 255, 0);
    }
}

#[tokio::test]
async fn cancelled_shared_iic_failure_fences_globally_and_flushes_before_fixed_off() {
    let registers = Registers::new(3);
    *registers.pic_reply.lock().unwrap() = VecDeque::from([0x15, 1]);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    let first = owner.clone();
    let caller = tokio::spawn(async move { first.pic(0, Bm1393PicCommand::Version).await });
    registers.nack.notified().await;
    caller.abort();
    assert!(caller.await.unwrap_err().is_cancelled());
    assert!(owner.pic(1, Bm1393PicCommand::Version).await.is_err());
    assert!(owner.terminal());
    assert_eq!(
        owner.pic(1, Bm1393PicCommand::Enable(false)).await.unwrap(),
        [0x15, 1]
    );
    let writes = registers.writes.lock().unwrap();
    let data: Vec<_> = writes
        .iter()
        .filter(|(_, word)| word & reg::IIC_READ_BIT == 0)
        .map(|(_, word)| *word)
        .collect();
    assert_eq!(data.len(), 3 + 16 + 7);
    assert_eq!(&data[..3], &[0x0040_0055, 0x0040_00aa, 0x0040_0004]);
    assert_eq!(&data[3..19], &[0x0040_0000; 16]);
    assert_eq!(
        &data[19..],
        &[
            0x0041_0055,
            0x0041_00aa,
            0x0041_0005,
            0x0041_0015,
            0x0041_0000,
            0x0041_0000,
            0x0041_001a
        ]
    );
}

#[tokio::test]
async fn iic_mmio_read_error_is_shared_even_if_a_later_local_cut_acks() {
    let registers = Registers::new(0);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    registers.fail_read_offset.store(0x30, Ordering::SeqCst);
    assert!(owner.pic(1, Bm1393PicCommand::Version).await.is_err());
    assert!(owner.terminal());
    registers
        .fail_read_offset
        .store(usize::MAX, Ordering::SeqCst);
    *registers.pic_reply.lock().unwrap() = VecDeque::from([0x15, 1]);
    let proof = owner.isolate_chain(1).await.unwrap();
    assert!(!owner.accepts_isolation(&proof));
    assert!(owner.try_work_batch(batch(&[0])).await.is_err());
}

#[tokio::test]
async fn full_work_records_do_not_interleave_between_selected_chains() {
    let registers = Registers::new(0);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    let a = dcentrald_common::bm1393_native::encode_bm1393_work(0, 1, &[0x11; 12], &[0x22; 32])
        .unwrap();
    let b = dcentrald_common::bm1393_native::encode_bm1393_work(1, 32767, &[0x33; 12], &[0x44; 32])
        .unwrap();
    let (left, right) = tokio::join!(owner.work(0, a), owner.work(1, b));
    left.unwrap();
    right.unwrap();
    let writes = registers.writes.lock().unwrap();
    assert_eq!(writes.len(), 26);
    for frame in writes.chunks_exact(13) {
        assert_eq!(frame[0].0, 0x40);
        assert!(frame[1..].iter().all(|(offset, _)| *offset == 0x44));
        let words = frame.iter().map(|(_, word)| *word).collect::<Vec<_>>();
        assert!(words == a || words == b);
    }
}

#[tokio::test]
async fn reset_is_asserted_high_with_readback_and_terminal_blocks_release() {
    let registers = Registers::new(0);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    owner.reset(1, true).await.unwrap();
    assert_eq!(registers.read(0x34).unwrap(), 0x1002);
    owner.reset(1, false).await.unwrap();
    assert_eq!(registers.read(0x34).unwrap(), 0x1000);
    owner.latch_terminal();
    assert!(owner.reset(0, false).await.is_err());
    owner.reset(0, true).await.unwrap();
    assert_eq!(registers.read(0x34).unwrap(), 0x1001);
    assert!(owner.work(0, [0; 13]).await.is_err());
}

#[tokio::test]
async fn no_fifo_capacity_prevents_any_partial_work_and_times_out() {
    let registers = Registers::new(0);
    registers.values.lock().unwrap().insert(12, 0);
    let owner = C43Transport::new(registers.clone(), vec![0]).unwrap();
    let work =
        dcentrald_common::bm1393_native::encode_bm1393_work(0, 1, &[0; 12], &[0; 32]).unwrap();
    let error = owner.work(0, work).await.unwrap_err();
    assert!(error.contains("timed out"));
    assert!(registers.writes.lock().unwrap().is_empty());
}

#[tokio::test]
async fn fan_uses_actual_stock_pwm_word_and_rejects_above_home_ceiling() {
    let registers = Registers::new(0);
    registers.values.lock().unwrap().insert(4, 0x0118);
    let owner = C43Transport::new(registers.clone(), vec![0]).unwrap();
    assert_eq!(owner.fan(30).await.unwrap(), vec![(1, 24 * 120)]);
    assert_eq!(registers.read(0x84).unwrap(), 0x000f_0023);
    assert!(owner.fan(31).await.is_err());
}

#[tokio::test]
async fn terminal_receipts_require_full_off_ack_and_cannot_cross_owner() {
    let first = Registers::new(0);
    *first.pic_reply.lock().unwrap() = VecDeque::from([0x15, 1]);
    let owner = C43Transport::new(first, vec![0]).unwrap();
    let cut = owner.terminal_cut().await;
    assert!(cut.completed(), "{:?}", cut.errors());
    let (barrier, power) = cut.into_parts();
    assert!(barrier.completed());
    assert_eq!(power.chain_outcomes(), &[(0, true, true)]);
    assert!(power.same_owner(&barrier));
    let partial = Registers::new(0);
    *partial.pic_reply.lock().unwrap() = VecDeque::from([0x15]);
    let other = C43Transport::new(partial, vec![0]).unwrap();
    let failed = other.terminal_cut().await;
    assert!(!failed.completed());
    let (other_barrier, other_power) = failed.into_parts();
    assert!(!power.same_owner(&other_barrier));
    assert!(!other_power.completed());
    assert!(other.terminal());
}

fn batch(chains: &[u8]) -> Vec<(u8, [u32; 13])> {
    (0..8)
        .flat_map(|id| {
            chains.iter().map(move |&chain| {
                (
                    chain,
                    dcentrald_common::bm1393_native::encode_bm1393_work(
                        chain,
                        id,
                        &[id as u8; 12],
                        &[chain; 32],
                    )
                    .unwrap(),
                )
            })
        })
        .collect()
}

#[tokio::test]
async fn batch_backpressure_preserves_healthy_chain_progress_and_whole_frames() {
    let registers = Registers::new(0);
    registers.values.lock().unwrap().insert(8, 7);
    registers.values.lock().unwrap().insert(12, 5);
    let owner = C43Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
    let items = batch(&[0, 1, 2]);
    let accepted = owner.try_work_batch(items.clone()).await.unwrap();
    assert_eq!(accepted, [true, false, true].repeat(8));
    let writes = registers.writes.lock().unwrap();
    let frames: Vec<_> = writes
        .chunks_exact(13)
        .map(|frame| frame.iter().map(|(_, value)| *value).collect::<Vec<_>>())
        .collect();
    let expected: Vec<_> = items
        .iter()
        .filter(|(chain, _)| *chain != 1)
        .map(|(_, words)| words.to_vec())
        .collect();
    assert_eq!(frames, expected);
    assert!(!owner.terminal());
}

#[tokio::test]
async fn partial_batch_frame_fences_all_chains_immediately() {
    let registers = Registers::new(0);
    registers.fail_work_word.store(7, Ordering::SeqCst);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    assert!(owner.try_work_batch(batch(&[0, 1])).await.is_err());
    assert!(owner.terminal());
    assert_eq!(registers.work_words.load(Ordering::SeqCst), 7);
    assert!(owner.try_work_batch(batch(&[1])).await.is_err());
    assert_eq!(registers.work_words.load(Ordering::SeqCst), 7);
}

#[tokio::test]
async fn shared_command_busy_timeout_cannot_be_reclassified_as_one_bad_board() {
    let registers = Registers::new(0);
    registers.values.lock().unwrap().insert(0xc0, 0x8000_0000);
    *registers.pic_reply.lock().unwrap() = VecDeque::from([0x15, 1]);
    let owner = C43Transport::new(registers, vec![0, 1]).unwrap();
    assert!(owner
        .asic(
            1,
            dcentrald_common::s9se_vil::pack_chain_inactive_vil().to_vec()
        )
        .await
        .is_err());
    assert!(owner.terminal());
    let proof = owner.isolate_chain(1).await.unwrap();
    assert!(!owner.accepts_isolation(&proof));
    assert!(owner.try_work_batch(batch(&[0])).await.is_err());
}

#[tokio::test]
async fn checked_chain_cut_is_permanent_and_cannot_disarm_or_cross_owner() {
    let registers = Registers::new(0);
    *registers.pic_reply.lock().unwrap() = VecDeque::from([0x15, 1]);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    let proof = owner.isolate_chain(1).await.unwrap();
    assert!(owner.accepts_isolation(&proof));
    assert!(!C43Transport::new(Registers::new(0), vec![0, 1])
        .unwrap()
        .accepts_isolation(&proof));
    assert_eq!(owner.active_chains(), [0]);
    assert_eq!(registers.read(0x34).unwrap() & 2, 2);
    assert!(owner.reset(1, false).await.is_err());
    assert!(owner.pic(1, Bm1393PicCommand::Enable(true)).await.is_err());
    assert_eq!(
        owner.try_work_batch(batch(&[0, 1])).await.unwrap(),
        [true, false].repeat(8)
    );
    assert!(!owner.terminal());
    // A later whole-owner cut still needs a fresh complete off reply for BOTH
    // original chains. A local receipt cannot stand in for terminal closure.
    *registers.pic_reply.lock().unwrap() = VecDeque::from([0x15, 1, 0x15]);
    assert!(!owner.terminal_cut().await.completed());
}

#[tokio::test]
async fn cancelled_failed_isolation_still_latches_global_terminal() {
    let registers = Registers::new(3);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    let retained = owner.clone();
    let task = tokio::spawn(async move { retained.isolate_chain(1).await });
    registers.nack.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    // Drain the retained lane; cancellation cannot discard its failed cut.
    let _ = owner.isolate_chain(1).await;
    assert!(owner.terminal());
    assert!(owner.chain_is_fenced(1));
    assert!(owner.active_chains().contains(&1));
}

struct ObservedCustody {
    live: std::sync::atomic::AtomicBool,
}
impl crate::platform::c43_bm1393::C43Custody<Registers> for ObservedCustody {
    async fn start(&self, _transport: Arc<C43Transport<Registers>>) -> Result<(), String> {
        self.live.store(true, Ordering::SeqCst);
        Ok(())
    }
    async fn check_health(&self) -> Result<(), String> {
        if self.live.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err("injected shared fan/watchdog fault".into())
        }
    }
    async fn stop(&self) -> Result<(), String> {
        self.live.store(false, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn actual_heartbeat_worker_isolates_bad_ack_and_keeps_two_healthy_schedules() {
    use crate::platform::c43_bm1393::C43Bm1393Adapter;
    use dcentrald_common::bm1393_native::{Bm1393Action, Bm1393Io};
    let registers = Registers::new(0);
    registers.values.lock().unwrap().insert(8, 7);
    let good = [6, 0x16, 1, 0, 0, 0x1d];
    let bad = [6, 0x16, 1, 0, 0, 0];
    let off = [0x15, 1];
    *registers.pic_reply.lock().unwrap() = [
        good.as_slice(),
        &bad,
        &off,
        &good,
        &good,
        &good,
        &off,
        &off,
        &off,
    ]
    .concat()
    .into();
    let owner = C43Transport::new(registers.clone(), vec![0, 1, 2]).unwrap();
    let custody = Arc::new(ObservedCustody {
        live: std::sync::atomic::AtomicBool::new(false),
    });
    let mut adapter = C43Bm1393Adapter::new(owner.clone(), custody.clone());
    adapter
        .execute(&Bm1393Action::StartCustody {
            chains: vec![0, 1, 2],
        })
        .await
        .unwrap();
    for chain in [0, 1, 2] {
        adapter
            .execute(&Bm1393Action::MaintainPicHeartbeat { chain })
            .await
            .unwrap();
    }
    tokio::time::timeout(Duration::from_secs(7), async {
        loop {
            let count = registers
                .writes
                .lock()
                .unwrap()
                .iter()
                .filter(|&&(offset, word)| offset == 0x30 && word == 0x0042_0016)
                .count();
            if count >= 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(owner.active_chains(), [0, 2]);
    assert!(!owner.terminal());
    adapter.execute(&Bm1393Action::CheckHealth).await.unwrap();
    let failed_chain_beats = registers
        .writes
        .lock()
        .unwrap()
        .iter()
        .filter(|&&(offset, word)| offset == 0x30 && word == 0x0041_0016)
        .count();
    assert_eq!(failed_chain_beats, 1);
    custody.live.store(false, Ordering::SeqCst);
    assert!(adapter.execute(&Bm1393Action::CheckHealth).await.is_err());
    adapter.execute(&Bm1393Action::StopCustody).await.unwrap();
    assert!(owner.terminal());
}

#[tokio::test]
async fn sensor_exclusion_requires_checked_cut_and_does_not_reappear_next_sample() {
    let registers = Registers::new(0);
    *registers.pic_reply.lock().unwrap() = VecDeque::from([0x15, 1]);
    let owner = C43Transport::new(registers.clone(), vec![0, 1]).unwrap();
    // Empty configured sites is a real sample_inner failure, never a healthy
    // temperature. The owner must cut it before omitting it from later reads.
    owner.sensors.lock().unwrap().push((1, Vec::new()));
    assert!(owner.temperatures().await.unwrap().is_empty());
    assert_eq!(owner.active_chains(), [0]);
    assert!(owner.temperatures().await.unwrap().is_empty());
    assert!(!owner.terminal());
    assert_eq!(owner.try_work_batch(batch(&[0])).await.unwrap(), [true; 8]);
}
