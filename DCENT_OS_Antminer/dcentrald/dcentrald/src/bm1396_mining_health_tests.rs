//! Real elapsed source waits: a fast sleep fixture would conceal the rejected
//! three-second whole-population heartbeat budget. No MMIO or device is opened.
use super::*;
use crate::bm1396_mining_work::test_support::Memory;
use dcentrald_hal::platform::stock_bm1396::{Hardware, Model};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};

struct TimedPic {
    memory: Arc<Memory>,
    reply: Mutex<VecDeque<u8>>,
    waits: Mutex<Vec<Duration>>,
    real: AtomicBool,
}
impl Hardware for TimedPic {
    fn model(&self) -> Model {
        Model::T17e
    }
    fn claim_transport(&self) -> std::result::Result<(), String> {
        self.memory.claim_transport()
    }
    fn validate_owner(&self) -> std::result::Result<(), String> {
        self.memory.validate_owner()
    }
    fn read(&self, offset: u32) -> std::result::Result<u32, String> {
        if offset == 0x30 {
            let request = *self
                .memory
                .registers
                .lock()
                .unwrap()
                .get(&offset)
                .unwrap_or(&0);
            return if request & 0x02000000 != 0 {
                Ok(0x80000000
                    | u32::from(
                        self.reply
                            .lock()
                            .unwrap()
                            .pop_front()
                            .ok_or("actual response script exhausted")?,
                    ))
            } else {
                Ok(0x80000000)
            };
        }
        self.memory.read(offset)
    }
    fn write(&self, offset: u32, value: u32) -> std::result::Result<(), String> {
        self.memory.write(offset, value)
    }
    fn read_dma(&self, offset: usize, out: &mut [u8]) -> std::result::Result<(), String> {
        self.memory.read_dma(offset, out)
    }
    fn write_dma(&self, offset: usize, bytes: &[u8]) -> std::result::Result<(), String> {
        self.memory.write_dma(offset, bytes)
    }
    fn barrier(&self) -> std::result::Result<(), String> {
        self.memory.barrier()
    }
    fn sleep(&self, duration: Duration) {
        self.waits.lock().unwrap().push(duration);
        if self.real.load(Ordering::SeqCst) {
            std::thread::sleep(duration);
        }
    }
}
impl TimedPic {
    fn replies(&self, bytes: &[u8]) {
        self.reply.lock().unwrap().extend(bytes);
    }
}

#[tokio::test]
async fn real_three_chain_round_rejects_old_three_seconds_and_completes_five_new_budget_rounds() {
    for old_budget in [true, false] {
        let memory = Memory::new();
        memory.registers.lock().unwrap().insert(8, 7);
        let hw = Arc::new(TimedPic {
            memory,
            reply: Mutex::new(VecDeque::new()),
            waits: Mutex::new(Vec::new()),
            real: AtomicBool::new(true),
        });
        let owner = Transport::observe(hw.clone(), Model::T17e, vec![0, 1, 2])
            .await
            .unwrap();
        let pic = PicApplication::claim(owner.clone()).unwrap();
        for _ in 0..3 {
            hw.replies(&[5, 0x17, 0x89, 0, 0]);
        }
        let versions_started = Instant::now();
        let actual = pic
            .observe_versions(Instant::now() + HEARTBEAT_ROUND_BUDGET)
            .await
            .unwrap();
        assert!(versions_started.elapsed() >= Duration::from_secs(3));
        assert_eq!(
            actual.iter().map(|v| v.chain()).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        hw.waits.lock().unwrap().clear();
        let rounds = if old_budget { 1 } else { 5 };
        for _ in 0..rounds {
            for _ in 0..3 {
                hw.replies(&[6, 0x16, 1, 0, 0, 0]);
            }
            let started = Instant::now();
            let result = pic
                .heartbeat_round(
                    started
                        + if old_budget {
                            Duration::from_secs(3)
                        } else {
                            HEARTBEAT_ROUND_BUDGET
                        },
                )
                .await;
            if old_budget {
                let error = result.unwrap_err();
                assert!(
                    matches!(
                        error.as_str(),
                        "BM1396 remaining absolute budget cannot contain source delay"
                            | "BM1396 absolute deadline elapsed"
                    ),
                    "actual old-budget failure: {error}"
                );
                // Source-derived expected path: the final 500 ms delay is
                // refused after 2520 ms of source waits. The v3 assertion did
                // not print its actual error; scheduling lateness may instead
                // trip the same original absolute deadline after a prior wait.
                assert!(
                    hw.waits.lock().unwrap().iter().sum::<Duration>() < Duration::from_millis(3030),
                    "the old budget cannot execute one complete three-chain round"
                );
                assert!(pic
                    .check_health(Instant::now() + Duration::from_secs(1))
                    .is_err());
            } else {
                result.unwrap();
                assert!(started.elapsed() >= Duration::from_millis(3030));
            }
        }
        let actual_waits = hw.waits.lock().unwrap().clone();
        if !old_budget {
            assert_eq!(
                actual_waits,
                vec![
                    Duration::from_millis(500),
                    Duration::from_millis(500),
                    Duration::from_millis(10)
                ]
                .repeat(15)
            );
            pic.check_health(Instant::now() + Duration::from_secs(1))
                .unwrap();
            assert!(hw.reply.lock().unwrap().is_empty());
        }
        owner
            .drain(Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
    }
}
