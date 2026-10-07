//! Ordered consumption of the real pool owner's independent job/status queues.
use super::*;

pub(crate) enum PoolEvent {
    Status(StratumStatus),
    Job(JobTemplate),
}

pub(crate) async fn next_pool_event(
    jobs: &mut mpsc::Receiver<JobTemplate>,
    statuses: &mut mpsc::Receiver<StratumStatus>,
) -> Result<PoolEvent> {
    // V1 sends Authorized before its first job and Mining after that job.
    // Consume pending state first so old startup telemetry cannot erase a
    // newly accepted job. The dispatcher independently requires current
    // mining status: a job queued before a later disconnect grants no work.
    tokio::select! {
        biased;
        status = statuses.recv() => Ok(PoolEvent::Status(status.context("BM1391 pool status actor exited")?)),
        job = jobs.recv() => Ok(PoolEvent::Job(job.context("BM1391 pool job actor exited")?)),
    }
}
