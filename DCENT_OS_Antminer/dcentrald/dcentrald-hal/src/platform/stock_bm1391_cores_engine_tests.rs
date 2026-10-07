use super::super::tests::{deadline, RecordingRegisters};
use super::*;
use std::sync::atomic::AtomicU32;

struct EngineRegisters {
    inner: RecordingRegisters,
    mode: AtomicU32,
    read_xor: AtomicU32,
    hcn_stuck: AtomicBool,
}
impl EngineRegisters {
    fn new(mode: u32) -> Self {
        Self {
            inner: RecordingRegisters::default(),
            mode: AtomicU32::new(mode),
            read_xor: AtomicU32::new(0),
            hcn_stuck: AtomicBool::new(false),
        }
    }
}
impl Registers for EngineRegisters {
    fn read(&self, offset: u32) -> Result<u32, String> {
        match offset {
            0x100 => Ok(self.mode.load(Ordering::SeqCst) ^ self.read_xor.load(Ordering::SeqCst)),
            0x90 => Ok(u32::from(self.hcn_stuck.load(Ordering::SeqCst))),
            _ => self.inner.read(offset),
        }
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        self.inner.write(offset, value)?;
        if offset == 0x100 {
            self.mode.store(value, Ordering::SeqCst);
        }
        Ok(())
    }
}

#[test]
fn cold_wrappers_match_all24_complete_original_functions_with_one_guard() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut stores = 0;
    for release in oracle["releases"].as_array().unwrap() {
        for vector in release["vectors"].as_array().unwrap() {
            let chain = vector["chain"].as_u64().unwrap() as u8;
            let mode = vector["initial_dhash"].as_u64().unwrap() as u32;
            let registers = Arc::new(EngineRegisters::new(mode));
            let owner = Transport::new(registers.clone(), vec![chain]).unwrap();
            owner
                .initialize_cores_cold_with_delay(chain, deadline(), |ms| {
                    assert!(owner.lane.try_lock().is_err());
                    registers
                        .inner
                        .state
                        .lock()
                        .unwrap()
                        .events
                        .push(serde_json::json!({"delay_us": ms * 1000}));
                    Ok(())
                })
                .unwrap();
            let state = registers.inner.state.lock().unwrap();
            assert_eq!(state.events, *vector["events"].as_array().unwrap());
            assert_eq!(state.writes.len(), 2011);
            assert_eq!(registers.mode.load(Ordering::SeqCst), mode);
            assert!(!owner.terminal());
            stores += state.writes.len();
        }
    }
    assert_eq!(stores, 16088);
}

#[test]
fn noncold_run_ddr_or_missing_mode_is_rejected_before_any_store() {
    for mode in [0, 0x8000, 0x8200, 0x8120, 0x8140, 0x8160] {
        let registers = Arc::new(EngineRegisters::new(mode));
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(owner
            .initialize_cores_cold_with_delay(0, deadline(), |_| Ok(()))
            .is_err());
        assert!(owner.terminal());
        assert!(registers.inner.state.lock().unwrap().writes.is_empty());
    }
    // Original DHASH comparisons ignore bit7; the native precondition must too.
    let registers = Arc::new(EngineRegisters::new(0x8100));
    registers.read_xor.store(0x80, Ordering::SeqCst);
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    owner
        .initialize_cores_cold_with_delay(0, deadline(), |_| Ok(()))
        .unwrap();
    assert!(!owner.terminal());
}

#[test]
fn partial_controls_frames_or_hcn_mismatch_latch_without_restore_or_retry() {
    for failure in [
        0, 1, 2, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 2010,
    ] {
        let registers = Arc::new(EngineRegisters::new(0x8100));
        registers.inner.state.lock().unwrap().fail_at = Some(failure);
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        assert!(owner
            .initialize_cores_cold_with_delay(0, deadline(), |_| Ok(()))
            .is_err());
        assert!(owner.terminal());
        assert_eq!(registers.inner.state.lock().unwrap().writes.len(), failure);
        assert!(owner
            .initialize_cores_cold_with_delay(0, deadline(), |_| Ok(()))
            .is_err());
        assert_eq!(registers.inner.state.lock().unwrap().writes.len(), failure);
    }
    let registers = Arc::new(EngineRegisters::new(0x8100));
    registers.hcn_stuck.store(true, Ordering::SeqCst);
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    assert!(owner
        .initialize_cores_cold_with_delay(0, deadline(), |_| Ok(()))
        .is_err());
    assert_eq!(
        registers.inner.state.lock().unwrap().writes,
        [(0x100, 0x8100), (0x90, 0)]
    );
    assert!(owner.terminal());
}

#[test]
fn mode_change_during_settle_and_panicking_delay_cannot_publish_later_work() {
    for panic_delay in [false, true] {
        let registers = Arc::new(EngineRegisters::new(0x8100));
        let owner = Transport::new(registers.clone(), vec![0]).unwrap();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            owner.initialize_cores_cold_with_delay(0, deadline(), |_| {
                if panic_delay {
                    panic!("injected core settle panic");
                }
                registers.mode.store(0x8140, Ordering::SeqCst);
                Ok(())
            })
        }));
        assert!(outcome.is_err() || outcome.unwrap().is_err());
        assert!(owner.terminal());
        let state = registers.inner.state.lock().unwrap();
        assert_eq!(state.writes.len(), 6); // two engine controls, one four-word VIL frame
        assert!(!state.writes.iter().any(|(offset, _)| *offset == TW_FIRST));
    }
}

#[tokio::test]
async fn canceled_cold_worker_finishes_under_guard_before_final_drain() {
    let registers = Arc::new(EngineRegisters::new(0x8100));
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let worker_owner = owner.clone();
    let task = tokio::spawn(async move {
        worker_owner
            .initialize_cores_in_cold_engine(0, deadline())
            .await
    });
    let limit = deadline();
    while registers.inner.state.lock().unwrap().writes.len() < 6 {
        assert!(Instant::now() < limit);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(owner.terminal());
    let _drained = owner.lock_until(deadline()).unwrap();
    let state = registers.inner.state.lock().unwrap();
    assert!(!state.writes.iter().any(|(offset, _)| *offset == TW_FIRST));
    assert!(!state
        .writes
        .iter()
        .any(|(offset, value)| *offset == 0x100 && value & 0x40 != 0));
}
