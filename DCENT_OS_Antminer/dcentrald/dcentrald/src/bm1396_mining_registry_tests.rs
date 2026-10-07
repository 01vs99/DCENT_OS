use super::*;
use crate::bm1396_mining_work::test_support::*;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn actual_publications_and_two_distinct_headers_must_return_on_every_retained_chain() {
    let (memory, owner, mut registry) = fixture().await;
    let first = publish(
        &owner,
        &mut registry,
        PreparedJob::known_probe(0, 0).unwrap(),
    )
    .await;
    assert!(registry
        .retain_issued(PreparedJob::known_probe(1, 0).unwrap())
        .is_err());
    for chain in [0, 2] {
        let raw = emit(&memory, &owner, &first, chain, 0).await;
        assert_eq!(
            registry.qualify_return(&raw).unwrap(),
            ReturnDisposition::Probe
        );
        owner.acknowledge_return(&raw).unwrap();
    }
    assert!(!registry.probes_complete());
    let second = publish(
        &owner,
        &mut registry,
        PreparedJob::known_probe(1, 1).unwrap(),
    )
    .await;
    let raw = emit(&memory, &owner, &second, 0, 0).await;
    registry.qualify_return(&raw).unwrap();
    owner.acknowledge_return(&raw).unwrap();
    assert!(!registry.probes_complete());
    let generation = WorkGeneration { session: 1, job: 1 };
    registry.set_active_generation(Some(generation));
    assert!(registry
        .retain_issued(pool_fixture(2, generation, [255; 32]))
        .is_err());
    let raw = emit(&memory, &owner, &second, 2, 0).await;
    registry.qualify_return(&raw).unwrap();
    owner.acknowledge_return(&raw).unwrap();
    assert!(registry.probes_complete());
    assert_eq!(registry.retained_returns().len(), 4);
    assert!(registry
        .retain_issued(PreparedJob::known_probe(0, 0).unwrap())
        .is_err());
}

#[tokio::test]
async fn identical_foreign_and_incomplete_publications_cannot_join_issued_metadata() {
    let (memory, owner, mut registry) = fixture().await;
    let (foreign_memory, foreign_owner, mut foreign_registry) = fixture().await;
    let issued = registry
        .retain_issued(PreparedJob::known_probe(0, 0).unwrap())
        .unwrap();
    let foreign_job = publish(
        &foreign_owner,
        &mut foreign_registry,
        PreparedJob::known_probe(0, 0).unwrap(),
    )
    .await;
    let foreign = foreign_owner.publications().unwrap().pop().unwrap();
    assert_eq!(foreign.packet(), issued.packet());
    assert_eq!(
        registry.join_publication(&foreign).unwrap_err().to_string(),
        "BM1396 publication is foreign or incomplete"
    );
    let raw = emit(&foreign_memory, &foreign_owner, &foreign_job, 0, 0).await;
    assert_eq!(
        registry.qualify_return(&raw).unwrap_err().to_string(),
        "BM1396 return is terminal or foreign"
    );
    assert!(registry.retained_returns().is_empty());
    memory.corrupt.store(true, Ordering::SeqCst);
    assert!(owner
        .publish_job(issued.packet().to_vec(), false, 400, deadline())
        .await
        .is_err());
    let partial = owner.publications().unwrap().pop().unwrap();
    assert!(partial.same_owner(&owner) && !partial.completed());
    assert_eq!(
        registry.join_publication(&partial).unwrap_err().to_string(),
        "BM1396 publication is foreign or incomplete"
    );
}

#[tokio::test]
async fn actual_stable_table_returns_with_wrong_full_version_en2_or_nonce_stay_unacknowledged() {
    for defect in [1, 2, 3] {
        let (memory, owner, mut registry) = fixture().await;
        let issued = publish(
            &owner,
            &mut registry,
            PreparedJob::known_probe(0, 0).unwrap(),
        )
        .await;
        let raw = emit(&memory, &owner, &issued, 0, defect).await;
        let expected = match defect {
            1 => "BM1396 returned complete version differs from issued header",
            2 => "BM1396 returned EN2 escaped issued fixed domain",
            3 => "BM1396 return failed complete CPU header hash",
            _ => unreachable!(),
        };
        assert_eq!(
            registry.qualify_return(&raw).unwrap_err().to_string(),
            expected,
            "defect{defect}"
        );
        assert!(registry.retained_returns().is_empty());
        assert_eq!(owner.pending_returns().unwrap().len(), 1);
        assert!(!registry.probes_complete());
        owner.begin_terminal();
        owner.drain(deadline()).await.unwrap();
    }
}

#[tokio::test]
async fn actual_cpu_share_survives_backpressure_and_generation_retirement_without_duplicate_credit()
{
    let (memory, owner, mut registry) = fixture().await;
    probes(&memory, &owner, &mut registry).await;
    let generation = WorkGeneration {
        session: 11,
        job: 7,
    };
    registry.set_active_generation(Some(generation));
    let job = publish(
        &owner,
        &mut registry,
        pool_fixture(2, generation, [255; 32]),
    )
    .await;
    let raw = emit(&memory, &owner, &job, 0, 0).await;
    assert_eq!(
        registry.qualify_return(&raw).unwrap(),
        ReturnDisposition::ShareQueued
    );
    owner.acknowledge_return(&raw).unwrap();
    let duplicate = emit(&memory, &owner, &job, 2, 0).await;
    assert_eq!(
        registry.qualify_return(&duplicate).unwrap(),
        ReturnDisposition::Duplicate
    );
    owner.acknowledge_return(&duplicate).unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    let queued = registry.outbox.front().unwrap().1.clone();
    tx.try_send(queued).unwrap();
    assert!(!registry.offer_head(&tx).unwrap());
    assert_eq!(
        registry.retained_returns()[4].share_disposition,
        Some(ShareDisposition::Queued)
    );
    registry.set_active_generation(None);
    assert!(registry.offer_head(&tx).unwrap());
    assert_eq!(
        registry.retained_returns()[4].share_disposition,
        Some(ShareDisposition::RetiredGeneration)
    );
    rx.recv().await.unwrap();
    assert!(rx.try_recv().is_err());
    registry.set_active_generation(Some(WorkGeneration {
        session: 12,
        job: 1,
    }));
    assert!(registry
        .retain_issued(pool_fixture(
            3,
            WorkGeneration {
                session: 12,
                job: 1
            },
            [255; 32]
        ))
        .is_err());
    assert_eq!(registry.lifetime_jobs(), 3);
    assert!(registry.charged_bytes() < CUSTODY_BYTES);
    let next_generation = WorkGeneration {
        session: 12,
        job: 1,
    };
    let next = publish(
        &owner,
        &mut registry,
        pool_fixture_index(3, 1, next_generation, [255; 32]),
    )
    .await;
    let raw = emit(&memory, &owner, &next, 0, 0).await;
    assert_eq!(
        registry.qualify_return(&raw).unwrap(),
        ReturnDisposition::ShareQueued
    );
    owner.acknowledge_return(&raw).unwrap();
    let (closed_tx, closed_rx) = mpsc::channel(1);
    drop(closed_rx);
    assert!(registry.offer_head(&closed_tx).is_err());
    assert_eq!(
        registry.retained_returns()[6].share_disposition,
        Some(ShareDisposition::Queued)
    );
    assert!(registry.offer_head(&tx).unwrap());
    let offered = rx.recv().await.unwrap();
    assert_eq!(offered.work_generation, next_generation);
    assert_eq!(
        offered.nonce,
        format!(
            "{:08x}",
            u32::from_le_bytes(next.header()[76..80].try_into().unwrap())
        )
    );
    assert_eq!(
        registry.retained_returns()[6].share_disposition,
        Some(ShareDisposition::OfferedToStratum)
    );
}

#[tokio::test]
async fn share_metadata_is_bounded_before_publication_and_backpressure_never_clones_payload() {
    let (memory, owner, mut registry) = fixture().await;
    probes(&memory, &owner, &mut registry).await;
    let generation = WorkGeneration {
        session: 19,
        job: 1,
    };
    registry.set_active_generation(Some(generation));
    let charged_before = registry.charged_bytes();
    for (job_id, extranonce2) in [
        ("j".repeat(POOL_JOB_ID_BYTES + 1), "00".to_owned()),
        ("j".to_owned(), "0".repeat(EXTRANONCE2_HEX_BYTES + 2)),
        ("j".to_owned(), "0".to_owned()),
        ("j".to_owned(), "gg".to_owned()),
    ] {
        let mut job = pool_fixture(2, generation, [255; 32]);
        let work = job.pool.as_mut().unwrap();
        work.job_id = job_id;
        work.extranonce2 = extranonce2;
        assert!(registry
            .retain_issued(job)
            .unwrap_err()
            .to_string()
            .contains("share metadata"));
        assert_eq!(registry.lifetime_jobs(), 2);
        assert_eq!(registry.charged_bytes(), charged_before);
        assert_eq!(owner.publications().unwrap().len(), 2);
        assert!(registry.outbox.is_empty());
    }
    let mut job = pool_fixture(2, generation, [255; 32]);
    job.pool.as_mut().unwrap().job_id = "j".repeat(POOL_JOB_ID_BYTES);
    job.pool.as_mut().unwrap().extranonce2 = "01".repeat(EXTRANONCE2_HEX_BYTES / 2);
    let job = publish(&owner, &mut registry, job).await;
    let raw = emit(&memory, &owner, &job, 0, 0).await;
    assert_eq!(
        registry.qualify_return(&raw).unwrap(),
        ReturnDisposition::ShareQueued
    );
    owner.acknowledge_return(&raw).unwrap();
    let (_, share) = registry.outbox.front().unwrap();
    let job_allocation = share.job_id.as_ptr();
    let nonce_allocation = share.extranonce2.as_ptr();
    let occupied = share.clone(); // Explicit fixture occupies the real channel.
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(occupied).unwrap();
    for _ in 0..8 {
        assert!(!registry.offer_head(&tx).unwrap());
        assert_eq!(registry.outbox.len(), 1);
        assert_eq!(
            registry.outbox.front().unwrap().1.job_id.as_ptr(),
            job_allocation
        );
    }
    rx.recv().await.unwrap();
    assert!(registry.offer_head(&tx).unwrap());
    assert!(registry.outbox.is_empty());
    let offered = rx.recv().await.unwrap();
    assert_eq!(offered.job_id.as_ptr(), job_allocation);
    assert_eq!(offered.extranonce2.as_ptr(), nonce_allocation);
    assert_eq!(offered.job_id.len(), POOL_JOB_ID_BYTES);
    assert_eq!(offered.extranonce2.len(), EXTRANONCE2_HEX_BYTES);
    assert_eq!(
        registry
            .retained_returns()
            .last()
            .unwrap()
            .share_disposition,
        Some(ShareDisposition::OfferedToStratum)
    );
}
