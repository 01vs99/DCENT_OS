import type { FirmwareUploadResponse, UpdateJobStatus } from '../api/types';

const KEY = 'dcentos-update-job';
export const UPDATE_JOB_CHANGED = 'dcentos-update-job-changed';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SHA256 = /^[0-9a-f]{64}$/;

export interface TrackedUpdateJob {
  job_id: string;
  package_sha256: string;
  source_boot_id: string;
  filename?: string;
}

function validIdentity(value: unknown): value is TrackedUpdateJob {
  if (value == null || typeof value !== 'object') return false;
  const job = value as Partial<TrackedUpdateJob>;
  return typeof job.job_id === 'string' && UUID.test(job.job_id)
    && typeof job.package_sha256 === 'string' && SHA256.test(job.package_sha256)
    && typeof job.source_boot_id === 'string' && UUID.test(job.source_boot_id);
}

export function loadUpdateJob(): TrackedUpdateJob | null {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(KEY) ?? 'null');
    return validIdentity(value) ? value : null;
  } catch {
    return null;
  }
}

// Save the receipt centrally so both settings and maintenance uploads survive
// navigation and a miner reboot. A storage failure must not fail an applied update.
export function rememberUpdateJob(response: FirmwareUploadResponse): void {
  const job = response.job;
  if (!response.update_started || !validIdentity(job)
    || job.schema !== 1 || job.state !== 'scheduled') return;
  const record: TrackedUpdateJob = {
    job_id: job.job_id,
    package_sha256: job.package_sha256,
    source_boot_id: job.source_boot_id,
    filename: response.filename,
  };
  try {
    localStorage.setItem(KEY, JSON.stringify(record));
  } catch {
    // The mounted panel can still track this receipt for the current page.
  }
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(UPDATE_JOB_CHANGED, { detail: record }));
  }
}

export function matchingUpdateJob(
  tracked: TrackedUpdateJob,
  jobs: UpdateJobStatus[] | undefined,
): UpdateJobStatus | null {
  if (!Array.isArray(jobs)) return null;
  const matches = jobs.filter(job => job?.schema === 1
    && job.job_id === tracked.job_id
    && job.package_sha256 === tracked.package_sha256
    && job.source_boot_id === tracked.source_boot_id);
  return matches.length === 1 ? matches[0] : null;
}

export function updateJobCopy(job: UpdateJobStatus | null) {
  const state = job?.state;
  if (state === 'boot_committed' && job?.boot_verified === true) {
    return { label: 'Update complete', detail: 'The miner booted into this update and confirmed its boot settings.', terminal: true, failed: false };
  }
  if (['failed_before_start', 'command_failed', 'worker_failed'].includes(state ?? '')) {
    return { label: 'Update failed', detail: job?.error || 'The update stopped. Review its result before starting another update.', terminal: true, failed: true };
  }
  switch (state) {
    case 'preparing':
    case 'scheduled':
      return { label: 'Update scheduled', detail: 'The miner has reserved this package and is preparing to install it.', terminal: false, failed: false };
    case 'running':
      return { label: 'Installing update', detail: 'Keep the miner powered while the update runs. This page reconnects automatically.', terminal: false, failed: false };
    case 'command_completed':
    case 'reboot_pending':
      return { label: 'Waiting for boot confirmation', detail: 'Installation has finished its current step. Waiting for the miner to confirm this update after reboot.', terminal: false, failed: false };
    case 'previous_boot_result_unconfirmed':
      return { label: 'Miner reconnected', detail: 'The miner has rebooted. Waiting for confirmation that this update booted successfully.', terminal: false, failed: false };
    default:
      return { label: 'Checking update result', detail: 'Waiting for the saved result of this specific update. Keep this page open or return later.', terminal: false, failed: false };
  }
}
