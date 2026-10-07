//! Detached tests for proposed platform::bb_factory_acquisition, gated sim-hal.
//! These execute the existing owned service and fixed AT24 operation.
use super::*;
use crate::i2c::{spawn_owned_sim_i2c_service, I2cSimBackend};
use crate::HalError;
use std::collections::BTreeMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Condvar;
use std::task::Poll;
use std::time::Duration;

type Transfer = (u8, u8, Vec<u8>, usize);

struct Backend {
    identity: usize,
    pages: BTreeMap<u8, Vec<u8>>,
    transfers: Mutex<Vec<Transfer>>,
    fail: Option<u8>,
    blocked: Option<u8>,
    entered: AtomicBool,
    released: Mutex<bool>,
    condition: Condvar,
}

impl Backend {
    fn new(page: Vec<u8>, fail: Option<u8>, blocked: Option<u8>) -> Arc<Self> {
        static NEXT: AtomicUsize = AtomicUsize::new(0xbcfa_0000);
        Arc::new(Self {
            identity: NEXT.fetch_add(1, Ordering::SeqCst),
            pages: (0x50..=0x53).map(|addr| (addr, page.clone())).collect(),
            transfers: Mutex::new(Vec::new()),
            fail,
            blocked,
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
        tokio::time::timeout(Duration::from_secs(2), async {
            while !self.entered.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
    }
}

impl I2cSimBackend for Backend {
    fn service_identity(&self) -> Option<usize> {
        Some(self.identity)
    }
    fn write(&self, bus: u8, addr: u8, _: &[u8]) -> crate::Result<usize> {
        Err(HalError::I2cEndpointRefused {
            bus,
            addr,
            detail: "standalone write is forbidden in factory fixture".into(),
        })
    }
    fn read(&self, bus: u8, addr: u8, _: &mut [u8]) -> crate::Result<usize> {
        Err(HalError::I2cEndpointRefused {
            bus,
            addr,
            detail: "standalone read is forbidden in factory fixture".into(),
        })
    }
    fn write_read(&self, bus: u8, addr: u8, input: &[u8], output: &mut [u8]) -> crate::Result<()> {
        self.transfers
            .lock()
            .unwrap()
            .push((bus, addr, input.to_vec(), output.len()));
        assert_eq!(input, [0]);
        assert_eq!(output.len(), 256);
        if Some(addr) == self.blocked {
            self.entered.store(true, Ordering::SeqCst);
            let limit = Instant::now() + Duration::from_secs(5);
            let mut released = self.released.lock().unwrap();
            while !*released {
                let Some(left) = limit.checked_duration_since(Instant::now()) else {
                    return Err(HalError::I2cEndpointNotReady {
                        bus,
                        addr,
                        detail: "fixture block deadline".into(),
                    });
                };
                released = self.condition.wait_timeout(released, left).unwrap().0;
            }
        }
        if Some(addr) == self.fail {
            return Err(HalError::I2cEndpointNotReady {
                bus,
                addr,
                detail: format!("held fixture error at {addr:#04x}"),
            });
        }
        output.copy_from_slice(&self.pages[&addr]);
        Ok(())
    }
}

fn fixture(name: &str) -> Vec<u8> {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../dcentrald-api-types/src/bb_factory_profile_vectors.json"
    )))
    .unwrap();
    let text = fixtures["fixtures"][name]["raw"].as_str().unwrap();
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
    Instant::now() + Duration::from_secs(3)
}

async fn clean_close(mut owner: I2cServiceOwner) {
    tokio::task::spawn_blocking(move || owner.close_and_join_until(deadline()))
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn actual_selected_full_pages_are_complete_checked_data_in_selected_order() {
    for sku in ["held_42601", "held_42641"] {
        for selected in [vec![0x52], vec![0x53, 0x50, 0x52, 0x51]] {
            let page = fixture(sku);
            let backend = Backend::new(page.clone(), None, None);
            let owner = owner(backend.clone(), 0, true);
            let mut acquisition =
                BbFactoryAcquisition::start(&owner, &selected, deadline()).unwrap();
            assert!(acquisition.join_until(deadline()).await);
            let saved = acquisition.snapshot();
            assert!(saved.failure.is_none());
            assert_eq!(
                saved.collection.as_ref().unwrap().pages().len(),
                selected.len()
            );
            assert_eq!(
                saved
                    .collection
                    .as_ref()
                    .unwrap()
                    .pages()
                    .iter()
                    .map(|page| page.address())
                    .collect::<Vec<_>>(),
                selected
            );
            assert_eq!(
                saved
                    .attempts
                    .iter()
                    .map(|row| row.address)
                    .collect::<Vec<_>>(),
                selected
            );
            assert!(saved
                .attempts
                .iter()
                .all(|row| row.returned_page.as_ref() == Some(&page)));
            assert_eq!(
                *backend.transfers.lock().unwrap(),
                selected
                    .iter()
                    .map(|&addr| (0, addr, vec![0], 256))
                    .collect::<Vec<_>>()
            );
            clean_close(owner).await;
        }
    }
}

#[tokio::test]
async fn invalid_selection_owner_policy_deadline_and_terminal_never_read_endpoint() {
    for selected in [
        vec![],
        vec![0x50; 5],
        vec![0x50, 0x50],
        vec![0x4f],
        vec![0x54],
    ] {
        let backend = Backend::new(fixture("held_42601"), None, None);
        let owner = owner(backend.clone(), 0, true);
        assert!(BbFactoryAcquisition::start(&owner, &selected, deadline()).is_err());
        assert!(backend.transfers.lock().unwrap().is_empty());
        clean_close(owner).await;
    }
    for defect in 0..4 {
        let backend = Backend::new(fixture("held_42601"), None, None);
        let owner = owner(
            backend.clone(),
            if defect == 0 { 1 } else { 0 },
            defect != 1,
        );
        if defect == 3 {
            owner.request_handle().latch_terminal_safe_off();
        }
        let result = BbFactoryAcquisition::start(
            &owner,
            &[0x50],
            if defect == 2 {
                Instant::now()
            } else {
                deadline()
            },
        );
        if defect == 1 {
            let mut acquisition = result.unwrap();
            assert!(acquisition.join_until(deadline()).await);
            assert!(acquisition
                .snapshot()
                .failure
                .unwrap()
                .contains("protected-address policy"));
            assert!(acquisition.snapshot().collection.is_none());
        } else {
            assert!(result.is_err());
        }
        assert!(backend.transfers.lock().unwrap().is_empty());
        clean_close(owner).await;
    }
}

#[tokio::test]
async fn each_failed_position_and_checked_collection_error_preserve_exact_prior_pages() {
    let page = fixture("held_42601");
    for failed in 0x50..=0x53 {
        let backend = Backend::new(page.clone(), Some(failed), None);
        let owner = owner(backend.clone(), 0, true);
        let mut acquisition =
            BbFactoryAcquisition::start(&owner, &[0x50, 0x51, 0x52, 0x53], deadline()).unwrap();
        assert!(acquisition.join_until(deadline()).await);
        let saved = acquisition.snapshot();
        assert_eq!(saved.attempts.len(), usize::from(failed - 0x50 + 1));
        assert_eq!(saved.attempts.last().unwrap().address, failed);
        assert!(saved.attempts.last().unwrap().returned_page.is_none());
        assert!(saved
            .attempts
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .contains("held fixture error"));
        assert!(saved.attempts[..saved.attempts.len() - 1]
            .iter()
            .all(|row| row.returned_page.as_ref() == Some(&page)));
        assert_eq!(
            backend.transfers.lock().unwrap().len(),
            saved.attempts.len()
        );
        assert!(saved.collection.is_none());
        clean_close(owner).await;
    }
    for mixed in [false, true] {
        let mut backend = Backend::new(page.clone(), None, None);
        let other = fixture(if mixed {
            "held_42641"
        } else {
            "identity_crc_mismatch"
        });
        Arc::get_mut(&mut backend)
            .unwrap()
            .pages
            .insert(0x51, other.clone());
        let owner = owner(backend, 0, true);
        let mut acquisition =
            BbFactoryAcquisition::start(&owner, &[0x50, 0x51], deadline()).unwrap();
        assert!(acquisition.join_until(deadline()).await);
        let saved = acquisition.snapshot();
        assert!(saved.collection.is_none() && saved.failure.is_some());
        assert_eq!(saved.attempts[0].returned_page.as_ref(), Some(&page));
        assert_eq!(saved.attempts[1].returned_page.as_ref(), Some(&other));
        clean_close(owner).await;
    }
}

#[tokio::test]
async fn actual_read_released_after_cancel_retains_late_bytes_without_reopening_attempt() {
    let page = fixture("held_42601");
    let backend = Backend::new(page.clone(), None, Some(0x50));
    let owner = owner(backend.clone(), 0, true);
    let mut acquisition = BbFactoryAcquisition::start(&owner, &[0x50, 0x51], deadline()).unwrap();
    backend.wait_entered().await;
    acquisition.cancel();
    let cancelled = acquisition.snapshot().stopped_at.unwrap();
    backend.release();
    assert!(acquisition.join_until(deadline()).await);
    let saved = acquisition.snapshot();
    assert_eq!(saved.stopped_at, Some(cancelled));
    assert_eq!(saved.attempts.len(), 1);
    assert_eq!(saved.attempts[0].returned_page.as_ref(), Some(&page));
    assert!(saved.collection.is_none());
    assert_eq!(backend.transfers.lock().unwrap().len(), 1);
    clean_close(owner).await;
}

#[tokio::test]
async fn timed_out_caller_does_not_claim_actual_service_worker_drain_or_late_bytes() {
    let backend = Backend::new(fixture("held_42601"), None, Some(0x50));
    let owner = owner(backend.clone(), 0, true);
    let mut acquisition = BbFactoryAcquisition::start(
        &owner,
        &[0x50, 0x51],
        Instant::now() + Duration::from_millis(80),
    )
    .unwrap();
    backend.wait_entered().await;
    assert!(acquisition.join_until(deadline()).await);
    let saved = acquisition.snapshot();
    assert!(saved.failure.is_some() && saved.collection.is_none());
    assert!(saved.attempts[0].returned_page.is_none());
    let (owner, closed) = tokio::task::spawn_blocking(move || {
        let mut owner = owner;
        let result = owner.close_and_join_until(Instant::now() + Duration::from_millis(30));
        (owner, result)
    })
    .await
    .unwrap();
    assert!(closed.is_err());
    assert!(!*backend.released.lock().unwrap());
    backend.release();
    clean_close(owner).await;
    assert!(acquisition.snapshot().attempts[0].returned_page.is_none());
}

#[tokio::test]
async fn queued_deadline_cancellation_never_executes_selected_read_behind_blocked_operation() {
    let backend = Backend::new(fixture("held_42601"), None, Some(0x53));
    let owner = owner(backend.clone(), 0, true);
    let handle = owner.request_handle();
    let blocker =
        tokio::task::spawn_blocking(move || handle.read_hashboard_eeprom_page_at(0x53, deadline()));
    backend.wait_entered().await;
    let mut acquisition =
        BbFactoryAcquisition::start(&owner, &[0x50], Instant::now() + Duration::from_millis(60))
            .unwrap();
    assert!(acquisition.join_until(deadline()).await);
    assert!(acquisition.snapshot().collection.is_none());
    backend.release();
    blocker.await.unwrap().unwrap();
    clean_close(owner).await;
    assert_eq!(
        backend
            .transfers
            .lock()
            .unwrap()
            .iter()
            .map(|row| row.1)
            .collect::<Vec<_>>(),
        [0x53]
    );
}

#[tokio::test]
async fn late_join_or_terminal_or_cancel_after_reads_cannot_promote_candidate() {
    for defect in 0..3 {
        let backend = Backend::new(fixture("held_42601"), None, None);
        let owner = owner(backend, 0, true);
        let until = deadline();
        let mut acquisition = BbFactoryAcquisition::start(&owner, &[0x50], until).unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !acquisition.task.as_ref().unwrap().is_finished() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert!(acquisition.snapshot().collection.is_none());
        assert!(
            lock_state(&acquisition.state).candidate.is_some(),
            "actual complete checked candidate must precede the adverse join event"
        );
        match defect {
            0 => tokio::time::sleep_until((until + Duration::from_millis(5)).into()).await,
            1 => {
                owner.request_handle().latch_terminal_safe_off();
            }
            _ => acquisition.cancel(),
        }
        assert!(acquisition.join_until(deadline()).await);
        let saved = acquisition.snapshot();
        assert!(saved.collection.is_none() && saved.failure.is_some());
        assert!(saved.attempts[0].returned_page.is_some());
        clean_close(owner).await;
    }
}

#[tokio::test]
async fn dropped_pending_join_future_permanently_cancels_data_and_retains_actual_task_for_cleanup()
{
    let backend = Backend::new(fixture("held_42601"), None, Some(0x50));
    let owner = owner(backend.clone(), 0, true);
    let mut acquisition = BbFactoryAcquisition::start(&owner, &[0x50, 0x51], deadline()).unwrap();
    backend.wait_entered().await;
    let mut pending = Box::pin(acquisition.join_until(deadline()));
    std::future::poll_fn(|cx| {
        assert!(matches!(pending.as_mut().poll(cx), Poll::Pending));
        Poll::Ready(())
    })
    .await;
    drop(pending); // Drop the actually-polled future, not the acquisition object.
    assert!(acquisition.task.is_some());
    let saved = acquisition.snapshot();
    assert!(saved
        .failure
        .as_ref()
        .unwrap()
        .contains("pending join future was cancelled"));
    backend.release();
    assert!(acquisition.join_until(deadline()).await);
    assert!(acquisition.task.is_none());
    let late = acquisition.snapshot();
    assert!(late.blocking_task_joined_at.is_some());
    assert_eq!(late.stopped_at, saved.stopped_at);
    assert!(late.collection.is_none());
    assert!(late.attempts[0].returned_page.is_some());
    assert_eq!(late.attempts.len(), 1);
    clean_close(owner).await;
}
