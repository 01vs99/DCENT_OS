use super::*;
use std::collections::BTreeMap;

#[derive(Default)]
struct State {
    words: BTreeMap<u32, u32>,
    events: Vec<&'static str>,
    reply_index: usize,
    fail_gpio: bool,
    fail_engine: bool,
}
struct Mmio(Arc<Mutex<State>>);
impl Registers for Mmio {
    fn read(&self, offset: u32) -> Result<u32, String> {
        let mut state = self.0.lock().unwrap();
        match offset {
            0 => Ok(0xc501),
            8 => Ok(7),
            0x30 => {
                let last = *state.words.get(&offset).unwrap();
                let byte = if last & 0x0200_0000 != 0 {
                    let byte = [0x15, 1][state.reply_index % 2];
                    state.reply_index += 1;
                    byte
                } else {
                    0
                };
                Ok(0x8000_0000 | byte)
            }
            _ => Ok(*state.words.get(&offset).unwrap_or(&0)),
        }
    }
    fn write(&self, offset: u32, value: u32) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        state
            .events
            .push(if offset == 0x30 { "pic" } else { "engine" });
        if state.fail_engine && offset == COMMAND_CONTROL {
            return Err("engine fault".into());
        }
        state.words.insert(offset, value);
        Ok(())
    }
}
struct Pin(Arc<Mutex<State>>);
impl gpio::Pin for Pin {
    fn high(&self) -> Result<(), String> {
        let mut state = self.0.lock().unwrap();
        state.events.push("high");
        if state.fail_gpio {
            Err("cut fixture failed".into())
        } else {
            Ok(())
        }
    }
    fn low(&self) -> Result<(), String> {
        panic!("terminal closeout must never enable")
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(!self.0.lock().unwrap().fail_gpio)
    }
}
fn fixture(
    chains: Vec<u8>,
) -> (
    Arc<Mutex<State>>,
    Arc<Transport<Mmio>>,
    Arc<PowerLine<Mmio>>,
    Arc<PicApplication<Mmio>>,
) {
    let state = Arc::new(Mutex::new(State::default()));
    state
        .lock()
        .unwrap()
        .words
        .extend([(COMMAND_CONTROL, 0x0040_001a), (0x100, 0x8160)]);
    let owner = Transport::new(Arc::new(Mmio(state.clone())), chains).unwrap();
    let line = PowerLine::from_test_pin(owner.clone(), Box::new(Pin(state.clone())));
    let pic = PicApplication::from_test_routes(owner.clone(), Model::S15, 0x101);
    (state, owner, line, pic)
}
fn deadlines() -> (Instant, Instant) {
    let now = Instant::now();
    (now + Duration::from_secs(2), now + Duration::from_secs(6))
}

#[test]
fn queued_gpio_worker_records_its_actual_attempt_after_the_request_time() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let (state, owner, line, pic) = fixture(vec![0]);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let occupied = tokio::task::spawn_blocking(move || {
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        started_rx.await.unwrap();
        let requested_at = Instant::now();
        let start_limit = requested_at + Duration::from_millis(20);
        let complete_limit = requested_at + Duration::from_secs(2);
        let task_owner = owner.clone();
        let close = tokio::spawn(async move {
            task_owner
                .close_terminal_controls(
                    line,
                    pic,
                    complete_limit,
                    requested_at + Duration::from_secs(5),
                )
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(owner.terminal());
        assert!(state.lock().unwrap().events.is_empty());
        release_tx.send(()).unwrap();
        occupied.await.unwrap();
        let receipt = close.await.unwrap().unwrap();
        assert!(receipt.controls_completed());
        // A caller timestamp would hide this missed CutoffStart, even though
        // the later CutoffComplete is met. The worker-issued value exposes it.
        assert!(requested_at < start_limit);
        assert!(receipt.cutoff_attempted_at().unwrap() > start_limit);
        assert!(receipt.cutoff_observed_at().unwrap() < complete_limit);
    });
}

#[tokio::test]
async fn terminal_receipt_binds_owner_retains_controls_and_cuts_before_blocked_asic_lane() {
    let (state, owner, line, pic) = fixture(vec![0, 1, 2]);
    let weak_line = Arc::downgrade(&line);
    let weak_pic = Arc::downgrade(&pic);
    let lane = owner.lane.lock().unwrap();
    let (cutoff, cleanup) = deadlines();
    let task_owner = owner.clone();
    let mut task = tokio::spawn(async move {
        task_owner
            .close_terminal_controls(line, pic, cutoff, cleanup)
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if !state.lock().unwrap().events.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(state.lock().unwrap().events, ["high"]);
    assert!(owner.terminal());
    assert!(!task.is_finished());
    drop(lane);
    let receipt = (&mut task).await.unwrap().unwrap();
    assert!(receipt.controls_completed());
    assert!(receipt.same_owner(&owner));
    assert!(receipt.cutoff_observed_at().unwrap() < cutoff);
    assert!(receipt.cutoff_attempted_at().unwrap() <= receipt.cutoff_observed_at().unwrap());
    assert!(receipt.finished_at() < cleanup);
    assert_eq!(receipt.pic().as_ref().unwrap().chains.len(), 3);
    assert!(weak_line.upgrade().is_some());
    assert!(weak_pic.upgrade().is_some());
    let (_, foreign, _, _) = fixture(vec![0]);
    assert!(!receipt.same_owner(&foreign));
    drop(receipt);
    assert!(weak_line.upgrade().is_none());
    assert!(weak_pic.upgrade().is_none());
}

#[tokio::test]
async fn failed_gpio_or_engine_does_not_skip_remaining_cuts_or_issue_completion() {
    for failed_gpio in [false, true] {
        let (state, owner, line, pic) = fixture(vec![0]);
        state.lock().unwrap().fail_gpio = failed_gpio;
        state.lock().unwrap().fail_engine = !failed_gpio;
        let (cutoff, cleanup) = deadlines();
        let receipt = owner
            .close_terminal_controls(line, pic, cutoff, cleanup)
            .await
            .unwrap();
        assert!(!receipt.controls_completed());
        assert_eq!(receipt.cutoff_observed_at().is_none(), failed_gpio);
        assert!(receipt.pic().as_ref().unwrap().all_acknowledged());
        assert!(receipt.drain().is_ok());
        assert!(receipt.engine().dhash_bit6_clear);
        let state = state.lock().unwrap();
        assert_eq!(state.events[0], "high");
        assert_eq!(
            state.events.iter().filter(|&&event| event == "pic").count(),
            9
        );
    }
}

#[tokio::test]
async fn mismatched_owner_cannot_cut_an_unrelated_line_or_pic() {
    let (state, owner, line, _) = fixture(vec![0]);
    let (foreign_state, _, _, foreign_pic) = fixture(vec![0]);
    // Clear fixture-owned temporary-line Drop observations before the action.
    foreign_state.lock().unwrap().events.clear();
    let (cutoff, cleanup) = deadlines();
    let line_custody = line.clone();
    assert!(owner
        .close_terminal_controls(line, foreign_pic, cutoff, cleanup)
        .await
        .is_err());
    assert!(owner.terminal());
    assert!(state.lock().unwrap().events.is_empty());
    assert!(foreign_state.lock().unwrap().events.is_empty());
    drop(line_custody);
}
