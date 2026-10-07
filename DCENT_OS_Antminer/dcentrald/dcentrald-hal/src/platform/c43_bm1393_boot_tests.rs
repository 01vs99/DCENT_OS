use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::AtomicUsize;

struct Registers {
    values: Mutex<BTreeMap<u32, u32>>,
    writes: Mutex<Vec<(u32, u32)>>,
    replies: Mutex<VecDeque<u8>>,
    wrong_ack: bool,
    wrong_pwm: bool,
}
impl Registers {
    fn new(presence: u32, wrong_ack: bool, wrong_pwm: bool) -> Arc<Self> {
        Arc::new(Self {
            values: Mutex::new(BTreeMap::from([(8, presence), (0x34, 0)])),
            writes: Mutex::new(Vec::new()),
            replies: Mutex::new(VecDeque::from([0x15, 1, 0x15, 1, 0x15, 1])),
            wrong_ack,
            wrong_pwm,
        })
    }
}
impl C43Registers for Registers {
    fn read(&self, offset: u32) -> Result<u32, String> {
        Ok(*self.values.lock().unwrap().get(&offset).unwrap_or(&0))
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.writes.lock().unwrap().push((offset, value));
        let observed = if offset == 0x30 {
            let byte = if value & reg::IIC_READ_BIT != 0 {
                let reply = self
                    .replies
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or("extra reply")?;
                if self.wrong_ack {
                    0
                } else {
                    reply
                }
            } else {
                0
            };
            0x8000_0000 | u32::from(byte)
        } else if offset == reg::FAN_CONTROL.byte_offset && self.wrong_pwm {
            value ^ 1
        } else {
            value
        };
        self.values.lock().unwrap().insert(offset, observed);
        Ok(())
    }
}

#[tokio::test]
async fn boot_parks_all_present_chains_before_quiet_and_zero_chain_has_no_pic() {
    for presence in [0, 1, 7] {
        let registers = Registers::new(presence, false, false);
        let parked = park_registers(registers.clone(), Instant::now() + Duration::from_secs(8))
            .await
            .unwrap();
        assert_eq!(
            parked.present_chains().len(),
            presence.count_ones() as usize
        );
        assert_eq!(parked.quiet_pwm_word(), 0x000f_0023);
        let writes = registers.writes.lock().unwrap();
        assert_eq!(writes.last(), Some(&(0x84, 0x000f_0023)));
        if presence == 0 {
            assert_eq!(writes.len(), 1);
        } else {
            assert_eq!(registers.read(0x34).unwrap() & presence, presence);
            assert!(
                registers.replies.lock().unwrap().len() == 6 - 2 * presence.count_ones() as usize
            );
            assert!(writes
                .iter()
                .all(|(offset, _)| [0x34, 0x30, 0x84].contains(offset)));
        }
    }
}

#[tokio::test]
async fn boot_refuses_bad_population_ack_pwm_or_expired_deadline() {
    for (presence, ack, pwm, expired) in [
        (15, false, false, false),
        (0x101, false, false, false),
        (1, true, false, false),
        (0, false, true, false),
        (0, false, false, true),
    ] {
        let registers = Registers::new(presence, ack, pwm);
        let deadline = if expired {
            Instant::now()
        } else {
            Instant::now() + Duration::from_secs(8)
        };
        assert!(park_registers(registers.clone(), deadline).await.is_err());
        if !pwm {
            assert!(!registers
                .writes
                .lock()
                .unwrap()
                .iter()
                .any(|(offset, _)| *offset == 0x84));
        }
    }
}

#[tokio::test]
async fn cancelled_boot_waiter_cannot_stop_between_present_pic_cutoffs() {
    let registers = Registers::new(7, false, false);
    let caller = {
        let registers = registers.clone();
        tokio::spawn(async move {
            park_registers(registers, Instant::now() + Duration::from_secs(8)).await
        })
    };
    tokio::time::timeout(Duration::from_secs(2), async {
        while !registers
            .writes
            .lock()
            .unwrap()
            .iter()
            .any(|(offset, _)| *offset == 0x30)
        {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    caller.abort();
    assert!(matches!(caller.await, Err(error) if error.is_cancelled()));
    tokio::time::timeout(Duration::from_secs(5), async {
        while !registers
            .writes
            .lock()
            .unwrap()
            .iter()
            .any(|(offset, _)| *offset == 0x84)
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(registers.read(0x34).unwrap() & 7, 7);
    assert!(registers.replies.lock().unwrap().is_empty());
}

struct ChangingRegisters {
    inner: Arc<Registers>,
    next_presence: Option<(usize, u32)>,
    presence_reads: AtomicUsize,
    fail_first_reset: bool,
    reset_writes: AtomicUsize,
    fail_first_pic: bool,
    pic_reads: AtomicUsize,
}
impl ChangingRegisters {
    fn new(presence: u32) -> Self {
        Self {
            inner: Registers::new(presence, false, false),
            next_presence: None,
            presence_reads: AtomicUsize::new(0),
            fail_first_reset: false,
            reset_writes: AtomicUsize::new(0),
            fail_first_pic: false,
            pic_reads: AtomicUsize::new(0),
        }
    }
}
impl C43Registers for ChangingRegisters {
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == reg::HASH_ON_PLUG.byte_offset {
            let index = self.presence_reads.fetch_add(1, Ordering::SeqCst);
            if let Some((after, value)) = self.next_presence {
                if index >= after {
                    return Ok(value);
                }
            }
        }
        self.inner.read(offset)
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        if offset == reg::RESET_HASHBOARD.byte_offset
            && self.reset_writes.fetch_add(1, Ordering::SeqCst) == 0
            && self.fail_first_reset
        {
            return Err("injected first reset failure".into());
        }
        self.inner.write(offset, value)?;
        if offset == 0x30
            && value & reg::IIC_READ_BIT != 0
            && self.pic_reads.fetch_add(1, Ordering::SeqCst) == 0
            && self.fail_first_pic
        {
            self.inner
                .values
                .lock()
                .unwrap()
                .insert(offset, 0x8000_0000);
        }
        Ok(())
    }
}

#[tokio::test]
async fn boot_presence_change_including_empty_carrier_never_quiets() {
    for (presence, after, changed) in [(0, 1, 1), (1, 2, 3), (7, 2, 3)] {
        let mut registers = ChangingRegisters::new(presence);
        registers.next_presence = Some((after, changed));
        let registers = Arc::new(registers);
        let result =
            park_registers(registers.clone(), Instant::now() + Duration::from_secs(8)).await;
        assert!(matches!(result, Err(error) if error.contains("presence changed")));
        assert!(!registers
            .inner
            .writes
            .lock()
            .unwrap()
            .iter()
            .any(|(offset, _)| *offset == 0x84));
        if presence != 0 {
            assert_eq!(registers.inner.read(0x34).unwrap() & presence, presence);
            assert_eq!(
                registers.inner.replies.lock().unwrap().len(),
                6 - 2 * presence.count_ones() as usize
            );
        }
    }
}

#[tokio::test]
async fn boot_first_reset_or_pic_failure_still_cuts_later_chains_and_never_quiets() {
    for reset_failure in [true, false] {
        let mut registers = ChangingRegisters::new(7);
        registers.fail_first_reset = reset_failure;
        registers.fail_first_pic = !reset_failure;
        let registers = Arc::new(registers);
        let result =
            park_registers(registers.clone(), Instant::now() + Duration::from_secs(8)).await;
        assert!(matches!(result, Err(error) if error.contains("reset/PIC off incomplete")));
        assert_eq!(registers.reset_writes.load(Ordering::SeqCst), 3);
        assert_eq!(registers.pic_reads.load(Ordering::SeqCst), 6);
        assert!(registers.inner.replies.lock().unwrap().is_empty());
        assert_eq!(registers.inner.read(0x34).unwrap() & 6, 6);
        assert!(!registers
            .inner
            .writes
            .lock()
            .unwrap()
            .iter()
            .any(|(offset, _)| *offset == 0x84));
    }
}

#[tokio::test]
async fn boot_deadline_expiring_during_cut_drains_all_chains_without_quiet() {
    let registers = Registers::new(7, false, false);
    let result = park_registers(
        registers.clone(),
        Instant::now() + Duration::from_millis(250),
    )
    .await;
    assert!(matches!(result, Err(error) if error.contains("deadline elapsed after cutoff")));
    assert_eq!(registers.read(0x34).unwrap() & 7, 7);
    assert!(registers.replies.lock().unwrap().is_empty());
    assert!(!registers
        .writes
        .lock()
        .unwrap()
        .iter()
        .any(|(offset, _)| *offset == 0x84));
}
