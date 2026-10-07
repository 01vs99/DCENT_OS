use super::*;

struct CutPin {
    fake: Arc<Fake>,
    fail: bool,
}
impl gpio::Pin for CutPin {
    fn high(&self) -> Result<(), String> {
        self.fake.events.lock().unwrap().push(Event::SourceHigh);
        if self.fail {
            Err("injected independent cutoff failure".into())
        } else {
            Ok(())
        }
    }
    fn observed_high(&self) -> Result<bool, String> {
        Ok(!self.fail)
    }
}
fn line(fake: &Arc<Fake>, owner: &Arc<Transport<Fake>>, fail: bool) -> Arc<PowerLine<Fake>> {
    PowerLine::from_test_pin(
        owner.clone(),
        Box::new(CutPin {
            fake: fake.clone(),
            fail,
        }),
    )
}
fn deadlines() -> (Instant, Instant) {
    (
        Instant::now() + Duration::from_secs(1),
        Instant::now() + Duration::from_secs(3),
    )
}

#[tokio::test]
async fn terminal_receipt_joins_actual_independent_cut_engine_pic_and_worker_drain_once() {
    let (fake, owner) = owner(Model::T17e).await;
    let line = line(&fake, &owner, false);
    let pic = PicApplication::claim(owner.clone()).unwrap();
    fake.regs.lock().unwrap().insert(DHASH, RUN | 0x8100);
    fake.reply(&[0x15, 1]);
    let (cutoff, cleanup) = deadlines();
    // Initial Transport::observe reads presence/version; scope the ordering
    // assertion to the actual closeout rather than that earlier acquisition.
    fake.events.lock().unwrap().clear();
    let receipt = owner
        .close_terminal_controls(line.clone(), pic.clone(), cutoff, cleanup)
        .await
        .unwrap();
    assert!(receipt.same_owner(&owner) && receipt.controls_completed());
    assert_eq!(receipt.cutoff_deadline(), cutoff);
    assert_eq!(receipt.cleanup_deadline(), cleanup);
    assert!(receipt.cutoff_attempted_at().unwrap() <= receipt.cutoff_observed_at().unwrap());
    let events = fake.events.lock().unwrap().clone();
    assert_eq!(events[0], Event::SourceHigh);
    assert!(
        events
            .iter()
            .position(|e| matches!(e, Event::Write(DHASH, _)))
            .unwrap()
            < events
                .iter()
                .position(|e| matches!(e, Event::Write(0x30, _)))
                .unwrap()
    );
    assert_eq!(fake.regs.lock().unwrap()[&DHASH], 0x8100);
    assert!(owner
        .close_terminal_controls(line, pic, cutoff, cleanup)
        .await
        .is_err());
    assert_eq!(*fake.events.lock().unwrap(), events);
    assert!(owner.workers.lock().unwrap().closed);
}

#[tokio::test]
async fn terminal_receipt_rejects_foreign_line_pic_and_transport_before_actuation() {
    for foreign_line in [true, false] {
        let (fake, owner) = owner(Model::T17e).await;
        let (other_fake, other) = super::owner(Model::T17e).await;
        let line = if foreign_line {
            line(&other_fake, &other, false)
        } else {
            line(&fake, &owner, false)
        };
        let pic = PicApplication::claim(if foreign_line {
            owner.clone()
        } else {
            other.clone()
        })
        .unwrap();
        let (cutoff, cleanup) = deadlines();
        assert!(owner
            .close_terminal_controls(line.clone(), pic, cutoff, cleanup)
            .await
            .is_err());
        assert!(fake.writes().is_empty() && other_fake.writes().is_empty());
        assert!(!fake.events.lock().unwrap().contains(&Event::SourceHigh));
        assert!(!other_fake
            .events
            .lock()
            .unwrap()
            .contains(&Event::SourceHigh));
    }
    let (fake, owner) = owner(Model::T17e).await;
    let line = line(&fake, &owner, false);
    let pic = PicApplication::claim(owner.clone()).unwrap();
    fake.reply(&[0x15, 1]);
    let (cutoff, cleanup) = deadlines();
    let receipt = owner
        .close_terminal_controls(line, pic, cutoff, cleanup)
        .await
        .unwrap();
    let (_, other) = super::owner(Model::T17e).await;
    assert!(!receipt.same_owner(&other));
}

#[tokio::test]
async fn failed_cut_engine_pic_or_expired_deadline_never_complete_but_attempt_other_controls() {
    for defect in 0..4 {
        let (fake, owner) = owner(Model::T17e).await;
        let line = line(&fake, &owner, defect == 0);
        let pic = PicApplication::claim(owner.clone()).unwrap();
        if defect == 1 {
            fake.fail_write.store(DHASH, Ordering::SeqCst);
        }
        fake.reply(if defect == 2 { &[0x15, 0] } else { &[0x15, 1] });
        let (mut cutoff, cleanup) = deadlines();
        if defect == 3 {
            cutoff = Instant::now();
        }
        let receipt = owner
            .close_terminal_controls(line, pic, cutoff, cleanup)
            .await
            .unwrap();
        assert!(!receipt.controls_completed());
        assert!(receipt.drain().is_ok() && owner.is_terminal());
        assert!(fake.writes().iter().any(|(offset, _)| *offset == DHASH));
        assert!(fake.writes().iter().any(|(offset, _)| *offset == 0x30));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_closeout_keeps_blocked_asic_worker_and_independent_cut_then_actual_drain() {
    let (fake, owner) = owner(Model::T17e).await;
    let line = line(&fake, &owner, false);
    let pic = PicApplication::claim(owner.clone()).unwrap();
    let block = ReadBlock::new(DHASH);
    *fake.block.lock().unwrap() = Some(block.clone());
    let task_owner = owner.clone();
    let (cutoff, cleanup) = deadlines();
    fake.events.lock().unwrap().clear();
    let task = tokio::spawn(async move {
        task_owner
            .close_terminal_controls(line, pic, cutoff, cleanup)
            .await
    });
    while !block.entered.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
    assert_eq!(fake.events.lock().unwrap()[0], Event::SourceHigh);
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(owner.is_terminal());
    assert!(owner
        .drain(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    assert!(owner.workers.lock().unwrap().count > 0);
    block.release();
    owner
        .drain(Instant::now() + Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(owner.workers.lock().unwrap().count, 0);
}
