use super::super::tests::{deadline, sample_work, RecordingRegisters};
use super::*;
use std::collections::VecDeque;

#[derive(Default)]
struct PicRegisters {
    inner: RecordingRegisters,
    replies: Mutex<VecDeque<u8>>,
    pages: Mutex<Vec<[u8; 256]>>,
    model: Option<Model>,
    delay_last_reply_until: Option<Instant>,
}
impl Registers for PicRegisters {
    fn model(&self) -> Option<Model> {
        self.model
    }
    fn read(&self, offset: u32) -> Result<u32, String> {
        if offset == IIC {
            let word = self.inner.state.lock().unwrap().writes.last().unwrap().1;
            if self.inner.iic_stuck {
                return Ok(0);
            }
            if word & 0xfff0_0000 == 0x03a0_0000 {
                let pages = self.pages.lock().unwrap();
                let page = pages
                    .get(((word >> 16) & 7) as usize)
                    .ok_or("missing EEPROM fixture")?;
                return Ok(0x8000_0000 | u32::from(page[((word >> 8) & 255) as usize]));
            }
            let byte = if word & 0x0200_0000 != 0 {
                let mut replies = self.replies.lock().unwrap();
                let byte = replies.pop_front().ok_or("no queued PIC reply")?;
                if replies.is_empty() {
                    if let Some(until) = self.delay_last_reply_until {
                        std::thread::sleep(until.saturating_duration_since(Instant::now()));
                    }
                }
                byte
            } else {
                0
            };
            return Ok(0x8000_0000 | u32::from(byte));
        }
        self.inner.read(offset)
    }
    fn write(&self, offset: u32, word: u32) -> Result<(), String> {
        self.inner.write(offset, word)
    }
}
fn fixture(
    model: Model,
    chains: Vec<u8>,
    revision: u16,
) -> (Arc<PicRegisters>, Arc<PicApplication<PicRegisters>>) {
    let registers = Arc::new(PicRegisters {
        model: Some(model),
        ..Default::default()
    });
    let owner = Transport::new(registers.clone(), chains.clone()).unwrap();
    let app = Arc::new(PicApplication {
        owner,
        routes: chains
            .into_iter()
            .map(|chain| Route::new(model, chain, revision))
            .collect(),
        health: Mutex::default(),
        enable_attempted: AtomicBool::new(false),
        heartbeat_finishing: AtomicBool::new(false),
        observed_pages: Vec::new(),
    });
    (registers, app)
}

#[test]
fn terminal_cut_finishes_only_the_inflight_heartbeat_then_allows_fixed_off() {
    let (registers, app) = fixture(Model::S15, vec![0, 1, 2], 0x101);
    registers
        .replies
        .lock()
        .unwrap()
        .extend([0, 0x16, 1, 0, 0, 0]);
    let mut cut = false;
    assert!(app
        .batch_with_delay(Operation::Heartbeat, deadline(), |ms| {
            if ms == 5 && !cut {
                // First request byte has issued. A different GPIO owner cuts now;
                // no ASIC or management lock is needed to latch normal traffic.
                assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 1);
                app.owner.latch_terminal();
                cut = true;
            }
            app.check(deadline(), false)
        })
        .is_err());
    assert!(cut);
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 12);
    assert!(registers.replies.lock().unwrap().is_empty());
    assert!(!app.owner.management_fault.load(Ordering::SeqCst));
    assert!(!app.heartbeat_finishing.load(Ordering::SeqCst));
    assert_eq!(app.health.lock().unwrap().last, [None; 3]);
    assert!(app
        .batch_with_delay(Operation::Heartbeat, deadline(), |_| Ok(()))
        .is_err());
    assert!(app
        .batch_with_delay(Operation::Enable, deadline(), |_| Ok(()))
        .is_err());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 12);
    registers
        .replies
        .lock()
        .unwrap()
        .extend([0x15, 1, 0x15, 1, 0x15, 1]);
    assert!(app
        .terminal_off_with_delay(deadline(), |_| Ok(()))
        .unwrap()
        .all_acknowledged());
}

#[test]
fn terminal_during_preframe_wait_issues_nothing_and_inflight_deadline_still_quarantines() {
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    assert!(app
        .batch_with_delay(Operation::Heartbeat, deadline(), |_| {
            app.owner.latch_terminal();
            Ok(())
        })
        .is_err());
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
    assert!(!app.owner.management_fault.load(Ordering::SeqCst));
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    let limit = Instant::now() + Duration::from_millis(10);
    assert!(app
        .batch_with_delay(Operation::Heartbeat, limit, |ms| {
            if ms == 5 {
                app.owner.latch_terminal();
                std::thread::sleep(limit.saturating_duration_since(Instant::now()));
            }
            app.check(limit, false)
        })
        .is_err());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 1);
    assert!(app.owner.management_fault.load(Ordering::SeqCst));
    assert!(!app.heartbeat_finishing.load(Ordering::SeqCst));
}

#[test]
fn final_off_ack_completed_after_deadline_is_not_success_or_an_unresolved_portal() {
    let limit = Instant::now() + Duration::from_millis(100);
    let registers = Arc::new(PicRegisters {
        model: Some(Model::S15),
        delay_last_reply_until: Some(limit + Duration::from_millis(2)),
        ..Default::default()
    });
    registers.replies.lock().unwrap().extend([0x15, 1]);
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let app = PicApplication::from_test_routes(owner.clone(), Model::S15, 0x101);
    let report = app.terminal_off_with_delay(limit, |_| Ok(())).unwrap();
    assert!(!report.all_acknowledged());
    assert!(report.chains[0].1.as_ref().unwrap_err().contains("expired"));
    assert!(owner.terminal());
    assert!(!owner.management_fault.load(Ordering::SeqCst));
    assert!(registers.replies.lock().unwrap().is_empty());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 9);
}

fn page(format: u8, revision: u16) -> [u8; 256] {
    let mut page = std::array::from_fn(|i| i as u8);
    page[0] = format;
    page[250..252].copy_from_slice(&revision.to_be_bytes());
    let crc = dcentrald_common::bm1391_stock_work::bm1391_stock_job_crc16(&page[..254]);
    page[254..].copy_from_slice(&crc.to_le_bytes());
    page
}

#[test]
fn population_enable_services_all_pic_heartbeats_between_each_enable() {
    let (registers, app) = fixture(Model::T15, vec![0, 1, 2], 0x100);
    {
        let mut health = app.health.lock().unwrap();
        health.stable_rounds = 5;
        health.last = [1120, 560, 0].map(|ms| Some(Instant::now() - Duration::from_millis(ms)));
    }
    let mut expected = Vec::new();
    for selector in [0, 2, 1] {
        registers.replies.lock().unwrap().extend([0x15, 1]);
        expected.push((selector, 0x15));
        for heartbeat_selector in [0, 2, 1] {
            registers
                .replies
                .lock()
                .unwrap()
                .extend([0, 0x16, 1, 0, 0, 0]);
            expected.push((heartbeat_selector, 0x16));
        }
    }
    let mut elapsed_ms = 0;
    let mut maximum_age = Duration::ZERO;
    app.enable_with_heartbeats_with_delay(deadline(), |ms| {
        elapsed_ms += ms;
        // Advance heartbeat ages without sleeping. The real transaction
        // records Instant::now at each complete accepted heartbeat response.
        let mut health = app.health.lock().unwrap();
        for at in health.last.iter_mut().flatten() {
            *at -= Duration::from_millis(ms);
            maximum_age = maximum_age.max(at.elapsed());
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(elapsed_ms, 6675);
    assert!(maximum_age < Duration::from_millis(2300), "{maximum_age:?}");
    assert!(!app.owner.terminal());
    assert_eq!(app.health.lock().unwrap().stable_rounds, 8);
    let writes = registers.inner.state.lock().unwrap().writes.clone();
    let mut cursor = 0;
    for (selector, opcode) in expected {
        assert_eq!(
            writes[cursor + 3],
            (IIC, 0x0040_0000 | (selector << 16) | opcode)
        );
        cursor += if opcode == 0x15 { 9 } else { 12 };
    }
    assert_eq!(cursor, writes.len());
}

#[test]
fn delayed_enable_settle_cannot_outlive_a_sibling_heartbeat() {
    let (registers, app) = fixture(Model::S15, vec![0, 1, 2], 0x101);
    {
        let mut health = app.health.lock().unwrap();
        health.stable_rounds = 1;
        health.last = [Some(Instant::now()); 3];
    }
    assert!(app
        .enable_with_heartbeats_with_delay(deadline(), |ms| {
            if ms == 400 {
                app.health.lock().unwrap().last =
                    [Some(Instant::now() - Duration::from_secs(4)); 3];
            }
            Ok(())
        })
        .is_err());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 7);
    assert!(app.owner.terminal());
    assert!(app.owner.management_fault.load(Ordering::SeqCst));
    assert!(!app
        .terminal_off_with_delay(deadline(), |_| Ok(()))
        .unwrap()
        .all_acknowledged());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 7);
}

#[test]
fn startup_disable_keeps_complete_cold_population_live_but_cannot_reopen_after_enable() {
    let (registers, app) = fixture(Model::T15, vec![0, 1, 2], 0x100);
    registers
        .replies
        .lock()
        .unwrap()
        .extend([0x15, 1].repeat(3));
    app.batch_with_delay(Operation::Disable, deadline(), |_| Ok(()))
        .unwrap();
    assert!(!app.owner.terminal());
    assert!(!app.enable_attempted.load(Ordering::SeqCst));
    let stores = registers.inner.state.lock().unwrap().writes.clone();
    for (writes, selector) in stores.chunks_exact(9).zip([0, 2, 1]) {
        let prefix = 0x0040_0000 | (selector << 16);
        assert_eq!(
            writes[..7]
                .iter()
                .map(|(_, word)| *word)
                .collect::<Vec<_>>(),
            [0x55, 0xaa, 5, 0x15, 0, 0, 0x1a].map(|byte| prefix | byte)
        );
        assert_eq!(writes[7..], [(IIC, prefix | 0x0200_0000); 2]);
    }
    app.enable_attempted.store(true, Ordering::SeqCst);
    assert!(app
        .batch_with_delay(Operation::Disable, deadline(), |_| Ok(()))
        .is_err());
    assert!(app.owner.terminal());
    assert_eq!(registers.inner.state.lock().unwrap().writes, stores);
    registers
        .replies
        .lock()
        .unwrap()
        .extend([0x15, 1].repeat(3));
    assert!(app
        .terminal_off_with_delay(deadline(), |_| Ok(()))
        .unwrap()
        .all_acknowledged());
}

#[test]
fn route_accepts_only_checked_original_formats_and_rejects_every_single_byte_corruption() {
    for format in [0x7e, 0x7f] {
        for revision in [0x100, 0x101] {
            let original = page(format, revision);
            for chain in 0..3 {
                let route = Route::from_page(Model::T15, chain, &original).unwrap();
                assert_eq!(
                    route.selector,
                    if revision == 0x100 && chain != 0 {
                        3 - chain
                    } else {
                        chain
                    }
                );
                assert_eq!(
                    Route::from_page(Model::S15, chain, &original)
                        .unwrap()
                        .selector,
                    chain
                );
            }
            for offset in 0..256 {
                let mut corrupt = original;
                corrupt[offset] ^= 1;
                assert!(
                    Route::from_page(Model::T15, 1, &corrupt).is_err(),
                    "byte{offset}"
                );
            }
        }
    }
    for format in [0, 0x7d, 0xff] {
        assert!(Route::from_page(Model::T15, 1, &page(format, 0x100)).is_err());
    }
}

#[tokio::test]
async fn actual_read_only_eeprom_observation_binds_one_owner_and_rejects_selector_alias() {
    let registers = Arc::new(PicRegisters {
        model: Some(Model::T15),
        ..Default::default()
    });
    *registers.pages.lock().unwrap() = vec![page(0x7f, 0x100); 3];
    let owner = Transport::new(registers.clone(), vec![1]).unwrap();
    let app = PicApplication::observe(
        owner.clone(),
        Model::T15,
        Instant::now() + Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(app.routes[0].selector, 2);
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 256);
    assert!(
        PicApplication::observe(owner.clone(), Model::T15, deadline())
            .await
            .is_err()
    );
    assert!(!owner.terminal());
    // Mixed revisions would direct two logical populations to PIC selector2.
    let registers = Arc::new(PicRegisters {
        model: Some(Model::T15),
        ..Default::default()
    });
    *registers.pages.lock().unwrap() =
        vec![page(0x7f, 0x100), page(0x7f, 0x100), page(0x7f, 0x101)];
    let owner = Transport::new(registers.clone(), vec![1, 2]).unwrap();
    assert!(PicApplication::observe(
        owner.clone(),
        Model::T15,
        Instant::now() + Duration::from_secs(5)
    )
    .await
    .is_err());
    assert!(owner.terminal());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 512);
    assert!(registers
        .inner
        .state
        .lock()
        .unwrap()
        .writes
        .iter()
        .all(|(_, word)| word & 0xfff0_0000 == 0x03a0_0000));
}

#[test]
fn incomplete_fpga_byte_has_bounded_polls_and_no_following_pic_byte() {
    let registers = Arc::new(PicRegisters {
        inner: RecordingRegisters {
            iic_stuck: true,
            ..Default::default()
        },
        ..Default::default()
    });
    let owner = Transport::new(registers.clone(), vec![0]).unwrap();
    let app = PicApplication {
        owner,
        routes: vec![Route::new(Model::S15, 0, 0x100)],
        health: Mutex::default(),
        enable_attempted: AtomicBool::new(false),
        heartbeat_finishing: AtomicBool::new(false),
        observed_pages: Vec::new(),
    };
    let mut polls = 0;
    assert!(app
        .transaction(
            app.routes[0],
            Operation::Heartbeat,
            deadline(),
            false,
            &mut |ms| {
                if ms == 5 {
                    polls += 1;
                }
                Ok(())
            }
        )
        .is_err());
    assert_eq!(polls, 101);
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 1);
    assert!(app.owner.terminal());
    let report = app.terminal_off_with_delay(deadline(), |_| Ok(())).unwrap();
    assert!(!report.all_acknowledged());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 1);
}

#[tokio::test]
async fn mapping_model_mismatch_rejects_before_eeprom_or_pic_io() {
    let (registers, app) = fixture(Model::S15, vec![1], 0x100);
    assert!(
        PicApplication::observe(app.owner.clone(), Model::T15, deadline())
            .await
            .is_err()
    );
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
    assert!(!app.owner.pic_claimed.load(Ordering::SeqCst));
}

#[test]
fn unresolved_terminal_transaction_cannot_overwrite_controller_for_a_sibling() {
    let (registers, app) = fixture(Model::S15, vec![0, 1, 2], 0x101);
    registers.inner.state.lock().unwrap().fail_at = Some(3);
    let report = app.terminal_off_with_delay(deadline(), |_| Ok(())).unwrap();
    assert!(report.chains.iter().all(|(_, result)| result.is_err()));
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 3);
    assert!(app.owner.management_fault.load(Ordering::SeqCst));
}

#[test]
fn application_transactions_match_every_original_mmio_store_and_delay() {
    let oracle: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../"
    )).unwrap();
    let mut compared = 0;
    for release in oracle["releases"].as_array().unwrap() {
        let model = if release["model"] == "s15" {
            Model::S15
        } else {
            Model::T15
        };
        for vector in release["vectors"].as_array().unwrap() {
            let chain = vector["chain"].as_u64().unwrap() as u8;
            let revision = vector["revision"].as_u64().unwrap() as u16;
            let (registers, app) = fixture(model, vec![chain], revision);
            registers.replies.lock().unwrap().extend(
                vector["response"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8),
            );
            let operation = match vector["operation"].as_str().unwrap() {
                "heartbeat" => Operation::Heartbeat,
                "enable" => Operation::Enable,
                "disable" => Operation::Disable,
                _ => unreachable!(),
            };
            let _management = app.owner.lock_management_until(deadline()).unwrap();
            if matches!(operation, Operation::Enable) {
                let mut health = app.health.lock().unwrap();
                health.last[usize::from(chain)] = Some(Instant::now());
                health.stable_rounds = 1;
            }
            app.transaction(app.routes[0], operation, deadline(), false, &mut |ms| {
                registers
                    .inner
                    .state
                    .lock()
                    .unwrap()
                    .events
                    .push(serde_json::json!({"delay_us":ms*1000}));
                Ok(())
            })
            .unwrap();
            assert_eq!(
                registers.inner.state.lock().unwrap().events,
                *vector["events"].as_array().unwrap(),
                "{model:?} chain{chain} rev{revision}"
            );
            assert!(registers.replies.lock().unwrap().is_empty());
            compared += 1;
        }
    }
    assert_eq!(compared, 36);
}

#[test]
fn whole_population_heartbeat_precedes_enable_and_continues_with_asic_lane_held() {
    let (registers, app) = fixture(Model::T15, vec![0, 1, 2], 0x100);
    let _asic = app.owner.lock_until(deadline()).unwrap();
    for _ in 0..3 {
        registers
            .replies
            .lock()
            .unwrap()
            .extend([4, 0x16, 1, 0, 0, 0x1b]);
    }
    app.batch_with_delay(Operation::Heartbeat, deadline(), |_| Ok(()))
        .unwrap();
    for _ in 0..3 {
        registers.replies.lock().unwrap().extend([0x15, 1]);
    }
    app.batch_with_delay(Operation::Enable, deadline(), |_| Ok(()))
        .unwrap();
    let state = registers.inner.state.lock().unwrap();
    assert_eq!(state.writes.len(), 3 * 12 + 3 * 9);
    assert_eq!((state.writes[12].1 >> 16) & 7, 2);
    assert_eq!((state.writes[24].1 >> 16) & 7, 1);
}

#[test]
fn missing_or_stale_heartbeat_cannot_enable_and_emits_no_frame() {
    for stale in [None, Some(Instant::now() - Duration::from_secs(4))] {
        let (registers, app) = fixture(Model::S15, vec![0], 0x101);
        app.health.lock().unwrap().last = [stale; 3];
        assert!(app
            .batch_with_delay(Operation::Enable, deadline(), |_| Ok(()))
            .is_err());
        assert!(registers.inner.state.lock().unwrap().writes.is_empty());
        assert!(app.owner.terminal());
    }
}

#[test]
fn every_partial_application_request_or_reply_failure_stops_without_replay() {
    for operation in [Operation::Heartbeat, Operation::Enable, Operation::Disable] {
        let count = if matches!(operation, Operation::Heartbeat) {
            12
        } else {
            9
        };
        for failure in 0..count {
            let (registers, app) = fixture(Model::S15, vec![0], 0x101);
            if matches!(operation, Operation::Enable) {
                let mut health = app.health.lock().unwrap();
                health.last[0] = Some(Instant::now());
                health.stable_rounds = 1;
            }
            registers.inner.state.lock().unwrap().fail_at = Some(failure);
            registers
                .replies
                .lock()
                .unwrap()
                .extend([4, 0x16, 1, 0, 0, 0x1b]);
            assert!(app
                .transaction(app.routes[0], operation, deadline(), false, &mut |_| Ok(()))
                .is_err());
            assert!(app.owner.terminal());
            assert!(app.owner.publish_work(&sample_work(0), deadline()).is_err());
            assert_eq!(registers.inner.state.lock().unwrap().writes.len(), failure);
        }
    }
}

#[test]
fn terminal_off_runs_after_normal_work_closes_and_keeps_sibling_failures_explicit() {
    let (registers, app) = fixture(Model::T15, vec![0, 1, 2], 0x100);
    // Rejected middle ACK must not stop the final populated endpoint's off.
    registers
        .replies
        .lock()
        .unwrap()
        .extend([0x15, 1, 0x15, 0, 0x15, 1]);
    app.owner.latch_terminal();
    let report = app.terminal_off_with_delay(deadline(), |_| Ok(())).unwrap();
    assert!(!report.all_acknowledged());
    assert!(report.chains[0].1.is_ok());
    assert!(report.chains[1].1.is_err());
    assert!(report.chains[2].1.is_ok());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), 27);
    assert!(app.owner.publish_work(&sample_work(0), deadline()).is_err());
    assert!(app
        .batch_with_delay(Operation::Heartbeat, deadline(), |_| Ok(()))
        .is_err());
}

#[test]
fn terminal_off_deadline_and_lock_contention_never_mint_acknowledgment() {
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    let held = app.owner.lock_management_until(deadline()).unwrap();
    assert!(app
        .terminal_off_with_delay(Instant::now() + Duration::from_millis(5), |_| Ok(()))
        .is_err());
    drop(held);
    assert!(app.owner.terminal());
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
    let report = app
        .terminal_off_with_delay(Instant::now(), |_| Ok(()))
        .unwrap();
    assert!(!report.all_acknowledged());
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
}

#[tokio::test]
async fn actual_async_heartbeat_expiry_and_cancellation_close_the_worker() {
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    assert!(app
        .heartbeat(Instant::now() + Duration::from_millis(10))
        .await
        .is_err());
    assert!(app.owner.terminal());
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    let worker_app = app.clone();
    let worker = tokio::spawn(async move { worker_app.heartbeat(deadline()).await });
    tokio::time::sleep(Duration::from_millis(10)).await;
    worker.abort();
    let _ = worker.await;
    assert!(app.owner.terminal());
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
}

#[tokio::test]
async fn real_apw_entry_requires_five_continuous_whole_population_rounds() {
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    for round in 1..=5 {
        registers
            .replies
            .lock()
            .unwrap()
            .extend([4, 0x16, 1, 0, 0, 0x1b]);
        app.batch_with_delay(Operation::Heartbeat, deadline(), |_| Ok(()))
            .unwrap();
        assert_eq!(app.require_voltage_health(deadline()).is_ok(), round == 5);
    }
    let value = app.set_apw8_voltage(18.3, deadline()).await.unwrap();
    assert_eq!(value.requested_volts, 18.3);
    assert_eq!(
        registers
            .inner
            .state
            .lock()
            .unwrap()
            .writes
            .last()
            .unwrap()
            .1,
        0x0520_0200 | u32::from(value.dac_code)
    );
    app.health.lock().unwrap().last[0] = Some(Instant::now() - Duration::from_secs(4));
    registers
        .replies
        .lock()
        .unwrap()
        .extend([4, 0x16, 1, 0, 0, 0x1b]);
    app.batch_with_delay(Operation::Heartbeat, deadline(), |_| Ok(()))
        .unwrap();
    assert_eq!(app.health.lock().unwrap().stable_rounds, 1);
    assert!(app.require_voltage_health(deadline()).is_err());
}

#[test]
fn enable_settle_rechecks_liveness_before_first_pic_byte() {
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    {
        let mut health = app.health.lock().unwrap();
        health.last[0] = Some(Instant::now());
        health.stable_rounds = 1;
    }
    assert!(app
        .batch_with_delay(Operation::Enable, deadline(), |ms| {
            assert_eq!(ms, 100);
            app.health.lock().unwrap().last[0] = Some(Instant::now() - Duration::from_secs(4));
            Ok(())
        })
        .is_err());
    assert!(registers.inner.state.lock().unwrap().writes.is_empty());
    assert!(!app.owner.management_fault.load(Ordering::SeqCst));
    assert!(app.owner.terminal());
}

#[test]
fn stale_heartbeat_after_enable_cannot_reestablish_normal_traffic() {
    let (registers, app) = fixture(Model::S15, vec![0], 0x101);
    registers
        .replies
        .lock()
        .unwrap()
        .extend([4, 0x16, 1, 0, 0, 0x1b, 0x15, 1]);
    app.batch_with_delay(Operation::Heartbeat, deadline(), |_| Ok(()))
        .unwrap();
    app.batch_with_delay(Operation::Enable, deadline(), |_| Ok(()))
        .unwrap();
    let written = registers.inner.state.lock().unwrap().writes.len();
    app.health.lock().unwrap().last[0] = Some(Instant::now() - Duration::from_secs(4));
    assert!(app
        .batch_with_delay(Operation::Heartbeat, deadline(), |_| Ok(()))
        .is_err());
    assert!(app.owner.terminal());
    assert_eq!(registers.inner.state.lock().unwrap().writes.len(), written);
}
