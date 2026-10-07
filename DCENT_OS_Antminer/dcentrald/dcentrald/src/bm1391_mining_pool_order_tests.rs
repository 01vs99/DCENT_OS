// Executes the production queue selector, dispatcher, work FIFO, retained
// nonce qualifier and outbox. Full native tests separately bind real V1 wire.
use crate::bm1391_mining::pool::{next_pool_event, PoolEvent};
use dcentrald_stratum::types::{StratumState, StratumStatus};

fn queued_job(generation: WorkGeneration) -> JobTemplate {
    let (work, _) = sample(0);
    // Standard pool-computed merkle material isolates ordering from V1's
    // subscription allocator; the unchanged WorkBuilder still encodes it.
    JobTemplate {
        work_generation: generation,
        v1_work_domain: None,
        job_id: work.job_id,
        prev_block_hash: work.prev_block_hash,
        coinbase1: vec![],
        coinbase2: vec![],
        merkle_branches: vec![],
        version: work.version,
        nbits: work.nbits,
        ntime: work.ntime,
        clean_jobs: true,
        share_target: work.share_target,
        extranonce1: vec![],
        extranonce2_size: 0,
        version_mask: 0,
        merkle_root: work.merkle_root,
        pool_difficulty: 1.0,
    }
}

async fn consume_queued_pool_events(
    dispatcher: &mut WorkDispatcher<Mmio>,
    jobs: &mut tokio::sync::mpsc::Receiver<JobTemplate>,
    statuses: &mut tokio::sync::mpsc::Receiver<StratumStatus>,
    count: usize,
) {
    for _ in 0..count {
        match next_pool_event(jobs, statuses).await.unwrap() {
            PoolEvent::Status(StratumStatus::StateChanged(state)) => {
                dispatcher.observe_pool_state(state)
            }
            PoolEvent::Job(job) => dispatcher.accept_job(job).unwrap(),
            _ => panic!("unexpected pool-order fixture message"),
        }
    }
}

#[tokio::test]
async fn queued_startup_statuses_cannot_erase_the_actual_dispatchers_first_job() {
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio.clone(), vec![0]).unwrap();
    let mut dispatcher = WorkDispatcher::new(owner, "queued.startup".into());
    let (job_tx, mut jobs) = tokio::sync::mpsc::channel(4);
    let (status_tx, mut statuses) = tokio::sync::mpsc::channel(4);
    let generation = WorkGeneration {
        session: 71,
        job: 1,
    };
    for status in [StratumState::Connecting, StratumState::Authorized] {
        status_tx
            .send(StratumStatus::StateChanged(status))
            .await
            .unwrap();
    }
    job_tx.send(queued_job(generation)).await.unwrap();
    status_tx
        .send(StratumStatus::StateChanged(StratumState::Mining))
        .await
        .unwrap();
    consume_queued_pool_events(&mut dispatcher, &mut jobs, &mut statuses, 4).await;
    assert!(dispatcher.dispatch_if_ready(deadline()).unwrap());
    assert_eq!(mmio.0.lock().unwrap().writes.len(), 13);
    mmio.0
        .lock()
        .unwrap()
        .returns
        .push_back((0x8000_0080, 0x1dac_2b7c));
    assert_eq!(dispatcher.drain_fifo(deadline()).unwrap(), (1, 0));
    let (shares, mut accepted) = tokio::sync::mpsc::channel(1);
    assert!(dispatcher.flush_shares(&shares).unwrap());
    let share = accepted.try_recv().unwrap();
    assert_eq!(share.work_generation, generation);
    assert_eq!(share.nonce, "7c2bac1d");
    assert_eq!(share.worker_name, "queued.startup");
}

#[tokio::test]
async fn queued_job_after_newer_disconnect_cannot_dispatch_or_revive_terminal_owner() {
    let mmio = Arc::new(Mmio::default());
    let owner = Transport::new(mmio.clone(), vec![0]).unwrap();
    let mut dispatcher = WorkDispatcher::new(owner.clone(), "queued.disconnect".into());
    let (job_tx, mut jobs) = tokio::sync::mpsc::channel(4);
    let (status_tx, mut statuses) = tokio::sync::mpsc::channel(4);
    let generation = WorkGeneration {
        session: 72,
        job: 1,
    };
    job_tx.send(queued_job(generation)).await.unwrap();
    for state in [StratumState::Mining, StratumState::Disconnected] {
        status_tx
            .send(StratumStatus::StateChanged(state))
            .await
            .unwrap();
    }
    consume_queued_pool_events(&mut dispatcher, &mut jobs, &mut statuses, 3).await;
    assert!(!dispatcher.dispatch_if_ready(deadline()).unwrap());
    assert!(mmio.0.lock().unwrap().writes.is_empty());
    assert!(dispatcher
        .accept_job(queued_job(WorkGeneration {
            session: 71,
            job: 1
        }))
        .is_err());
    owner.latch_terminal();
    dispatcher.observe_pool_state(StratumState::Mining);
    dispatcher
        .accept_job(queued_job(WorkGeneration {
            session: 73,
            job: 1,
        }))
        .unwrap();
    assert!(dispatcher.dispatch_if_ready(deadline()).is_err());
    assert!(mmio.0.lock().unwrap().writes.is_empty());
}
