//! Nine detached, uncompiled groups using the actual owned I2C service.
use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::HalError;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Condvar;
use std::task::Poll;
use std::time::Duration;

const VALID_REPLY: [u8; 5] = [0x05, 0x17, 0x89, 0x00, 0xa5];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Page(u8, Vec<u8>, usize),
    Write(u8, Vec<u8>),
    Read(u8, usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Block {
    Page(u8),
    PicRead(u8),
}

struct Backend {
    identity: usize,
    pages: BTreeMap<u8, Vec<u8>>,
    replies: BTreeMap<u8, [u8; 5]>,
    positions: Mutex<BTreeMap<u8, usize>>,
    events: Mutex<Vec<Event>>,
    fail_page: Option<u8>,
    short_read: Option<u8>,
    blocked: Option<Block>,
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}

impl Backend {
    fn new(sku: &str) -> Arc<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0xbcfb_0000);
        Arc::new(Self {
            identity: NEXT.fetch_add(1, Ordering::SeqCst),
            pages: (0x50..=0x52).map(|addr| (addr, fixture(sku))).collect(),
            replies: (0x20..=0x22).map(|addr| (addr, VALID_REPLY)).collect(),
            positions: Mutex::new(BTreeMap::new()),
            events: Mutex::new(Vec::new()),
            fail_page: None,
            short_read: None,
            blocked: None,
            entered: AtomicBool::new(false),
            released: Mutex::new(false),
            condition: Condvar::new(),
        })
    }

    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.condition.notify_all();
    }

    async fn wait_entered(&self) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }

    fn wait_if_blocked(&self, block: Block, bus: u8, addr: u8) -> crate::Result<()> {
        if self.blocked != Some(block) {
            return Ok(());
        }
        self.entered.store(true, Ordering::SeqCst);
        let until = Instant::now() + Duration::from_secs(8);
        let mut released = self.released.lock().unwrap();
        while !*released {
            let Some(left) = until.checked_duration_since(Instant::now()) else {
                return Err(HalError::I2cEndpointNotReady {
                    bus,
                    addr,
                    detail: "fixture block deadline".into(),
                });
            };
            released = self.condition.wait_timeout(released, left).unwrap().0;
        }
        Ok(())
    }

    fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }
}

impl I2cSimBackend for Backend {
    fn service_identity(&self) -> Option<usize> {
        Some(self.identity)
    }

    fn write(&self, bus: u8, addr: u8, bytes: &[u8]) -> crate::Result<usize> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Write(addr, bytes.to_vec()));
        if bus != 0 || !(0x20..=0x22).contains(&addr) || bytes != bb_pic_application::REQUEST {
            return Err(HalError::I2cEndpointRefused {
                bus,
                addr,
                detail: "fixture only permits exact native application query".into(),
            });
        }
        self.positions.lock().unwrap().insert(addr, 0);
        Ok(bytes.len())
    }

    fn read(&self, bus: u8, addr: u8, output: &mut [u8]) -> crate::Result<usize> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Read(addr, output.len()));
        if output.len() != 1 || !(0x20..=0x22).contains(&addr) {
            return Err(HalError::I2cEndpointRefused {
                bus,
                addr,
                detail: "fixture requires each one-byte PIC read".into(),
            });
        }
        self.wait_if_blocked(Block::PicRead(addr), bus, addr)?;
        if self.short_read == Some(addr) {
            return Ok(0);
        }
        let mut positions = self.positions.lock().unwrap();
        let position = positions
            .get_mut(&addr)
            .ok_or_else(|| HalError::I2cEndpointNotReady {
                bus,
                addr,
                detail: "PIC read without prior query".into(),
            })?;
        if *position >= 5 {
            return Err(HalError::I2cEndpointNotReady {
                bus,
                addr,
                detail: "extra PIC byte requested".into(),
            });
        }
        output[0] = self.replies[&addr][*position];
        *position += 1;
        Ok(1)
    }

    fn write_read(&self, bus: u8, addr: u8, input: &[u8], output: &mut [u8]) -> crate::Result<()> {
        self.events
            .lock()
            .unwrap()
            .push(Event::Page(addr, input.to_vec(), output.len()));
        if bus != 0 || input != [0] || output.len() != 256 || !self.pages.contains_key(&addr) {
            return Err(HalError::I2cEndpointRefused {
                bus,
                addr,
                detail: "fixture requires protected full factory page".into(),
            });
        }
        self.wait_if_blocked(Block::Page(addr), bus, addr)?;
        if self.fail_page == Some(addr) {
            return Err(HalError::I2cEndpointNotReady {
                bus,
                addr,
                detail: "injected selected page failure".into(),
            });
        }
        output.copy_from_slice(&self.pages[&addr]);
        Ok(())
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let value: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald-api-types/src/bb_factory_profile_vectors.json"
    )))
    .unwrap();
    let text = value["fixtures"][name]["raw"].as_str().unwrap();
    assert_eq!(text.len(), 512);
    (0..256)
        .map(|index| u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).unwrap())
        .collect()
}

fn owner(backend: Arc<Backend>, bus: u8, protected: bool) -> I2cServiceOwner {
    spawn_owned_sim_i2c_service(
        bus,
        backend,
        if protected {
            (0x50..=0x57).collect()
        } else {
            Vec::new()
        },
    )
    .unwrap()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(5)
}

async fn close(mut inventory: BbSelectedInventory) -> BbSelectedInventory {
    tokio::task::spawn_blocking(move || {
        inventory.close_service_until(deadline()).unwrap();
        assert!(inventory.close_receipt().is_some());
        inventory
    })
    .await
    .unwrap()
}

fn query_events(address: u8) -> Vec<Event> {
    let mut events = vec![Event::Write(address, bb_pic_application::REQUEST.to_vec())];
    events.extend((0..5).map(|_| Event::Read(address, 1)));
    events
}

#[tokio::test]
async fn selected_factory_then_every_exact_pic_query_join_before_inventory_and_actual_close() {
    for sku in ["held_42601", "held_42641"] {
        for selected in [vec![0x52], vec![0x52, 0x50, 0x51]] {
            let backend = Backend::new(sku);
            let owner = owner(backend.clone(), 0, true);
            let handle = owner.request_handle();
            let mut inventory = BbSelectedInventory::new(owner);
            inventory.start(&selected, deadline()).unwrap();
            assert!(inventory.snapshot().inventory.is_none());
            assert!(inventory.join_until(deadline()).await);
            let saved = inventory.snapshot();
            assert!(saved.failure.is_none(), "{saved:?}");
            assert!(saved
                .factory
                .as_ref()
                .unwrap()
                .blocking_task_joined_at
                .is_some());
            assert!(saved.query_task_joined_at.is_some());
            let accepted = saved.inventory.unwrap();
            assert_eq!(
                accepted
                    .factory
                    .pages()
                    .iter()
                    .map(|page| page.address())
                    .collect::<Vec<_>>(),
                selected
            );
            assert_eq!(accepted.pics.len(), selected.len());
            for (attempt, address) in accepted.pics.iter().zip(&selected) {
                assert_eq!(
                    (
                        attempt.factory_address,
                        attempt.native_slot,
                        attempt.pic_address
                    ),
                    (*address, usize::from(address - 0x50), address - 0x30)
                );
                assert_eq!(attempt.accepted_reply, Some(VALID_REPLY));
                assert_eq!(
                    attempt.returned_reads,
                    Some(VALID_REPLY.map(|byte| vec![byte]).to_vec())
                );
            }
            let mut expected: Vec<_> = selected
                .iter()
                .map(|address| Event::Page(*address, vec![0], 256))
                .collect();
            for address in &selected {
                expected.extend(query_events(address - 0x30));
            }
            assert_eq!(backend.events(), expected);
            assert!(inventory.close_receipt().is_none());
            assert!(inventory.start(&selected, deadline()).is_err());
            let inventory = close(inventory).await;
            assert_eq!(inventory.close_receipt().unwrap().bus(), 0);
            assert!(inventory.snapshot().inventory.is_none());
            assert!(handle.read_bb_pic_application_at(0, deadline()).is_err());
            assert_eq!(backend.events(), expected);
        }
    }
}

#[tokio::test]
async fn invalid_selection_bus_policy_expiry_and_terminal_retain_owner_without_pic_queries() {
    for selected in [
        vec![],
        vec![0x50; 4],
        vec![0x50, 0x50],
        vec![0x4f],
        vec![0x53],
        vec![0x54],
    ] {
        let backend = Backend::new("held_42601");
        let mut inventory = BbSelectedInventory::new(owner(backend.clone(), 0, true));
        assert!(inventory.start(&selected, deadline()).is_err());
        assert!(inventory.start(&[0x50], deadline()).is_err());
        assert!(inventory.join_until(deadline()).await);
        assert!(inventory.snapshot().inventory.is_none());
        close(inventory).await;
        assert!(backend.events().is_empty());
    }
    for defect in 0..4 {
        let backend = Backend::new("held_42601");
        let owner = owner(
            backend.clone(),
            if defect == 0 { 1 } else { 0 },
            defect != 1,
        );
        if defect == 3 {
            owner.request_handle().latch_terminal_safe_off();
        }
        let mut inventory = BbSelectedInventory::new(owner);
        let result = inventory.start(
            &[0x50],
            if defect == 2 {
                Instant::now()
            } else {
                deadline()
            },
        );
        if defect == 1 {
            result.unwrap();
        } else {
            assert!(result.is_err());
        }
        assert!(inventory.join_until(deadline()).await);
        assert!(inventory.snapshot().failure.is_some());
        assert!(inventory.snapshot().inventory.is_none());
        close(inventory).await;
        assert!(backend.events().is_empty());
    }
}

#[tokio::test]
async fn every_factory_failure_position_and_invalid_checked_page_keep_prior_data_without_pic() {
    for failed in [0x50, 0x51, 0x52] {
        let mut backend = Backend::new("held_42601");
        Arc::get_mut(&mut backend).unwrap().fail_page = Some(failed);
        let mut inventory = BbSelectedInventory::new(owner(backend.clone(), 0, true));
        inventory.start(&[0x50, 0x51, 0x52], deadline()).unwrap();
        assert!(inventory.join_until(deadline()).await);
        let saved = inventory.snapshot();
        let factory = saved.factory.unwrap();
        assert_eq!(factory.attempts.len(), usize::from(failed - 0x50) + 1);
        assert!(factory.attempts.last().unwrap().error.is_some());
        assert!(factory.attempts[..factory.attempts.len() - 1]
            .iter()
            .all(|attempt| attempt.returned_page.as_ref() == Some(&fixture("held_42601"))));
        assert!(saved.pics.is_empty() && saved.inventory.is_none());
        assert!(backend
            .events()
            .iter()
            .all(|event| matches!(event, Event::Page(..))));
        close(inventory).await;
    }
    for bad in ["identity_crc_mismatch", "unsupported_42621"] {
        let mut backend = Backend::new("held_42601");
        let raw = fixture(bad);
        Arc::get_mut(&mut backend)
            .unwrap()
            .pages
            .insert(0x51, raw.clone());
        let mut inventory = BbSelectedInventory::new(owner(backend.clone(), 0, true));
        inventory.start(&[0x50, 0x51], deadline()).unwrap();
        assert!(inventory.join_until(deadline()).await);
        let saved = inventory.snapshot();
        assert_eq!(
            saved.factory.unwrap().attempts[1].returned_page.as_ref(),
            Some(&raw)
        );
        assert!(saved.pics.is_empty() && saved.inventory.is_none() && saved.failure.is_some());
        close(inventory).await;
        assert_eq!(backend.events().len(), 2);
    }
}

#[tokio::test]
async fn strict_pic_refusal_at_each_position_retains_returned_bytes_and_never_skips_to_later_slot()
{
    for address in [0x20, 0x21, 0x22] {
        for defect in 0..3 {
            let mut backend = Backend::new("held_42601");
            let mutable = Arc::get_mut(&mut backend).unwrap();
            if defect == 0 {
                mutable.replies.insert(address, [0x05, 0x17, 0x86, 0, 0xa2]);
            } else if defect == 1 {
                mutable.replies.insert(address, [0x05, 0x17, 0x89, 0, 0xa4]);
            } else {
                mutable.short_read = Some(address);
            }
            let mut inventory = BbSelectedInventory::new(owner(backend.clone(), 0, true));
            inventory.start(&[0x50, 0x51, 0x52], deadline()).unwrap();
            assert!(inventory.join_until(deadline()).await);
            let saved = inventory.snapshot();
            assert_eq!(saved.pics.len(), usize::from(address - 0x20) + 1);
            assert!(saved.pics[..saved.pics.len() - 1]
                .iter()
                .all(|attempt| attempt.accepted_reply == Some(VALID_REPLY)));
            let rejected = saved.pics.last().unwrap();
            assert!(rejected.error.is_some() && rejected.accepted_reply.is_none());
            if defect < 2 {
                assert!(rejected.returned_reads.is_some());
            }
            assert!(saved.inventory.is_none() && saved.failure.is_some());
            let writes: Vec<_> = backend
                .events()
                .into_iter()
                .filter_map(|event| match event {
                    Event::Write(addr, _) => Some(addr),
                    _ => None,
                })
                .collect();
            assert_eq!(writes, (0x20..=address).collect::<Vec<_>>());
            close(inventory).await;
        }
    }
}

#[tokio::test]
async fn dropping_actual_pending_factory_or_query_join_permanently_cancels_and_retains_cleanup() {
    for block in [Block::Page(0x50), Block::PicRead(0x20)] {
        let mut backend = Backend::new("held_42601");
        Arc::get_mut(&mut backend).unwrap().blocked = Some(block);
        let mut inventory = BbSelectedInventory::new(owner(backend.clone(), 0, true));
        inventory.start(&[0x50, 0x51], deadline()).unwrap();
        let mut pending = Box::pin(inventory.join_until(deadline()));
        tokio::select! {
            _ = backend.wait_entered() => (),
            result = &mut pending => panic!("blocked caller unexpectedly joined: {result}"),
        }
        // Ensure the actual borrowed future was polled before dropping it.
        std::future::poll_fn(|cx| {
            assert!(matches!(pending.as_mut().poll(cx), Poll::Pending));
            Poll::Ready(())
        })
        .await;
        drop(pending);
        let stopped = inventory.snapshot().stopped_at.unwrap();
        assert!(inventory
            .snapshot()
            .failure
            .unwrap()
            .contains("pending join future cancelled"));
        assert!(inventory.close_service_until(deadline()).is_err());
        backend.release();
        assert!(inventory.join_until(deadline()).await);
        let saved = inventory.snapshot();
        assert_eq!(saved.stopped_at, Some(stopped));
        assert!(saved.inventory.is_none() && saved.all_caller_tasks_joined_at.is_some());
        if matches!(block, Block::Page(_)) {
            assert_eq!(saved.factory.unwrap().attempts.len(), 1);
            assert!(saved.pics.is_empty());
        } else {
            assert_eq!(saved.pics.len(), 1);
            assert!(saved.pics[0].returned_reads.is_some());
        }
        let inventory = close(inventory).await;
        assert!(inventory.close_receipt().is_some());
    }
}

#[tokio::test]
async fn timed_out_query_caller_join_cannot_claim_blocked_service_drain_or_unavailable_bytes() {
    let mut backend = Backend::new("held_42601");
    Arc::get_mut(&mut backend).unwrap().blocked = Some(Block::PicRead(0x20));
    let mut inventory = BbSelectedInventory::new(owner(backend.clone(), 0, true));
    inventory
        .start(&[0x50, 0x51], Instant::now() + Duration::from_millis(650))
        .unwrap();
    let mut pending = Box::pin(inventory.join_until(deadline()));
    tokio::select! {
        _ = backend.wait_entered() => (),
        result = &mut pending => panic!("query was not actually blocked: {result}"),
    }
    assert!(pending.await);
    let saved = inventory.snapshot();
    assert!(saved.query_task_joined_at.is_some() && saved.all_caller_tasks_joined_at.is_some());
    assert!(saved.inventory.is_none() && saved.failure.is_some());
    assert_eq!(saved.pics.len(), 1);
    assert!(saved.pics[0].returned_reads.is_none());
    let (mut inventory, result) = tokio::task::spawn_blocking(move || {
        let result = inventory.close_service_until(Instant::now() + Duration::from_millis(30));
        (inventory, result)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(inventory.close_receipt().is_none());
    assert!(!*backend.released.lock().unwrap());
    backend.release();
    inventory = close(inventory).await;
    assert!(inventory.close_receipt().is_some());
    assert!(inventory.snapshot().pics[0].returned_reads.is_none());
    assert_eq!(
        backend
            .events()
            .iter()
            .filter(|event| matches!(event, Event::Write(..)))
            .count(),
        1
    );
}

#[tokio::test]
async fn terminal_latch_during_first_selected_reply_prevents_every_later_query_and_promotion() {
    let mut backend = Backend::new("held_42601");
    Arc::get_mut(&mut backend).unwrap().blocked = Some(Block::PicRead(0x20));
    let retained = owner(backend.clone(), 0, true);
    let handle = retained.request_handle();
    let mut inventory = BbSelectedInventory::new(retained);
    inventory.start(&[0x50, 0x51, 0x52], deadline()).unwrap();
    let mut pending = Box::pin(inventory.join_until(deadline()));
    tokio::select! {
        _ = backend.wait_entered() => (),
        result = &mut pending => panic!("first selected reply was not actually blocked: {result}"),
    }
    handle.latch_terminal_safe_off();
    assert!(handle.terminal_safe_off_is_latched());
    backend.release();
    assert!(pending.await);
    let saved = inventory.snapshot();
    assert!(saved.inventory.is_none() && saved.failure.is_some());
    assert!(saved.query_task_joined_at.is_some() && saved.all_caller_tasks_joined_at.is_some());
    assert_eq!(saved.pics.len(), 1);
    assert_eq!(saved.pics[0].factory_address, 0x50);
    let writes: Vec<_> = backend
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Write(addr, _) => Some(addr),
            _ => None,
        })
        .collect();
    assert_eq!(writes, vec![0x20]);
    close(inventory).await;
}

#[tokio::test]
async fn selected_query_expires_while_queued_without_bus_execution_and_retains_actual_service() {
    let mut backend = Backend::new("held_42601");
    Arc::get_mut(&mut backend).unwrap().blocked = Some(Block::PicRead(0x22));
    let retained = owner(backend.clone(), 0, true);
    let handle = retained.request_handle();
    let mut inventory = BbSelectedInventory::new(retained);
    let limit = Instant::now() + Duration::from_millis(900);
    inventory.start(&[0x50, 0x51], limit).unwrap();
    assert!(
        inventory
            .factory
            .as_mut()
            .unwrap()
            .join_until(deadline())
            .await
    );
    assert!(inventory
        .factory
        .as_ref()
        .unwrap()
        .snapshot()
        .collection
        .is_some());
    let blocker = tokio::task::spawn_blocking(move || handle.read_bb_pic_application_at(2, limit));
    backend.wait_entered().await;
    assert!(inventory.join_until(deadline()).await);
    assert!(blocker.await.unwrap().is_err());
    let saved = inventory.snapshot();
    assert!(saved.inventory.is_none() && saved.failure.is_some());
    assert!(saved.query_task_joined_at.is_some() && saved.all_caller_tasks_joined_at.is_some());
    assert_eq!(saved.pics.len(), 1);
    assert!(saved.pics[0].returned_reads.is_none() && saved.pics[0].error.is_some());
    assert_eq!(
        backend
            .events()
            .iter()
            .filter(|event| matches!(event, Event::Write(..)))
            .count(),
        1
    );
    let (inventory, result) = tokio::task::spawn_blocking(move || {
        let result = inventory.close_service_until(Instant::now() + Duration::from_millis(30));
        (inventory, result)
    })
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(inventory.close_receipt().is_none());
    backend.release();
    close(inventory).await;
    // The completed close observes passage beyond the expired queued request.
    let writes: Vec<_> = backend
        .events()
        .into_iter()
        .filter_map(|event| match event {
            Event::Write(addr, _) => Some(addr),
            _ => None,
        })
        .collect();
    assert_eq!(writes, vec![0x22]);
}

#[tokio::test]
async fn completed_query_candidate_observed_after_original_deadline_never_becomes_inventory() {
    let backend = Backend::new("held_42601");
    let mut inventory = BbSelectedInventory::new(owner(backend.clone(), 0, true));
    let limit = Instant::now() + Duration::from_millis(1200);
    inventory.start(&[0x50], limit).unwrap();
    assert!(
        inventory
            .factory
            .as_mut()
            .unwrap()
            .join_until(deadline())
            .await
    );
    let shared = Arc::clone(&inventory.state);
    let mut pending = Box::pin(inventory.join_until(deadline()));
    std::future::poll_fn(|cx| {
        assert!(matches!(pending.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    // Retain the actual pending future without polling its completed task.
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if state_lock(&shared).candidate.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    let completed = state_lock(&shared)
        .candidate
        .as_ref()
        .unwrap()
        .observed_complete_at;
    assert!(completed < limit);
    assert!(state_lock(&shared).snapshot.query_task_joined_at.is_none());
    tokio::time::sleep_until((limit + Duration::from_millis(10)).into()).await;
    assert!(pending.await);
    let saved = inventory.snapshot();
    assert!(saved.query_task_joined_at.unwrap() >= limit);
    assert!(saved.inventory.is_none() && saved.failure.is_some());
    assert_eq!(saved.pics.len(), 1);
    assert_eq!(saved.pics[0].accepted_reply, Some(VALID_REPLY));
    assert_eq!(
        saved.pics[0].returned_reads,
        Some(VALID_REPLY.map(|byte| vec![byte]).to_vec())
    );
    let mut expected = vec![Event::Page(0x50, vec![0], 256)];
    expected.extend(query_events(0x20));
    assert_eq!(backend.events(), expected);
    close(inventory).await;
}
