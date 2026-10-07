// @vitest-environment jsdom
import React from 'react';
import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from '../../api/client';
import type { FirmwareUploadResponse, SystemUpgradeStatusResponse, UpdateJobStatus } from '../../api/types';
import { loadUpdateJob, matchingUpdateJob, rememberUpdateJob } from '../../utils/updateJob';
import { UpgradeStatusPanel } from './UpgradeStatusPanel';

vi.mock('../../api/client', () => ({ api: { getSystemUpgradeStatus: vi.fn() } }));

const job: UpdateJobStatus = {
  schema: 1,
  job_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  source_boot_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  package_sha256: 'c'.repeat(64),
  state: 'scheduled',
  boot_verified: false,
};
const receipt: FirmwareUploadResponse = {
  status: 'ok', message: 'Scheduled', update_started: true, job,
  filename: 'dcentos-beta.tar',
};
function status(jobs: UpdateJobStatus[]): SystemUpgradeStatusResponse {
  return {
    status: 'ok', read_only: true, state: 'idle', stage_root: '/tmp/dcentos-upgrade',
    stage_root_present: true, staged_package_count: 0, staged_packages: [],
    upgrade_stage: null, bootcount: null, bootlimit: null, boot_slot: null, jobs,
  };
}
const query = vi.mocked(api.getSystemUpgradeStatus);

beforeEach(() => {
  vi.useFakeTimers();
  localStorage.clear();
  query.mockReset();
});
afterEach(() => {
  cleanup();
  vi.useRealTimers();
  vi.restoreAllMocks();
});
async function mount() {
  await act(async () => { render(<UpgradeStatusPanel />); });
}
async function poll() {
  await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
}

describe('persistent update progress', () => {
  it('restores the exact receipt after navigation and reconnects without replaying the update', async () => {
    rememberUpdateJob(receipt);
    query.mockResolvedValueOnce(status([{ ...job, state: 'running' }]))
      .mockRejectedValueOnce(new Error('offline'))
      .mockResolvedValueOnce(status([{ ...job, state: 'previous_boot_result_unconfirmed' }]))
      .mockResolvedValue(status([{ ...job, state: 'boot_committed', boot_verified: true }]));
    await mount();
    expect(screen.getByText('Installing update')).toBeTruthy();
    expect(screen.getByText(receipt.filename!)).toBeTruthy();
    await poll();
    expect(screen.getByText(/Connection lost/)).toBeTruthy();
    expect(screen.getByText('Installing update')).toBeTruthy();
    await poll();
    expect(screen.getByText('Miner reconnected')).toBeTruthy();
    expect(screen.queryByText('Update complete')).toBeNull();
    await poll();
    expect(screen.getByText('Update complete')).toBeTruthy();
    const completedQueries = query.mock.calls.length;
    await poll();
    expect(query).toHaveBeenCalledTimes(completedQueries);
    expect(loadUpdateJob()?.job_id).toBe(job.job_id);
  });

  it('never treats an installer exit or an unrelated boot record as update completion', async () => {
    rememberUpdateJob(receipt);
    query.mockResolvedValueOnce(status([{ ...job, state: 'command_completed', exit_code: 0 }]))
      .mockResolvedValueOnce(status([{ ...job, package_sha256: 'd'.repeat(64), state: 'boot_committed', boot_verified: true }]))
      .mockResolvedValueOnce(status([{ ...job, source_boot_id: job.job_id, state: 'boot_committed', boot_verified: true }]))
      .mockResolvedValue(status([{ ...job, state: 'boot_committed', boot_verified: false }]));
    await mount();
    expect(screen.getByText('Waiting for boot confirmation')).toBeTruthy();
    for (let i = 0; i < 3; i++) {
      await poll();
      expect(screen.queryByText('Update complete')).toBeNull();
      expect(screen.getByText('Checking update result')).toBeTruthy();
    }
    expect(matchingUpdateJob(job, [job, job])).toBeNull();
  });

  it('starts tracking a new apply receipt on an already mounted page when storage is unavailable', async () => {
    query.mockResolvedValue(status([]));
    await mount();
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('storage full'); });
    query.mockResolvedValue(status([job]));
    await act(async () => { rememberUpdateJob(receipt); });
    expect(screen.getByText('Update scheduled')).toBeTruthy();
    expect(screen.getByText(receipt.filename!)).toBeTruthy();
    expect(loadUpdateJob()).toBeNull();
  });

  it('shows a terminal worker failure and stops polling', async () => {
    rememberUpdateJob(receipt);
    query.mockResolvedValue(status([{ ...job, state: 'command_failed', exit_code: 7 }]));
    await mount();
    expect(screen.getByText('Update failed')).toBeTruthy();
    expect(screen.getByText('Installer exit code: 7')).toBeTruthy();
    const calls = query.mock.calls.length;
    await poll();
    expect(query).toHaveBeenCalledTimes(calls);
  });

  it('does not overlap status requests when the miner responds slowly', async () => {
    rememberUpdateJob(receipt);
    let finish!: (value: SystemUpgradeStatusResponse) => void;
    query.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
    await mount();
    await poll();
    await poll();
    expect(query).toHaveBeenCalledTimes(1);
    await act(async () => { finish(status([job])); });
    await poll();
    expect(query).toHaveBeenCalledTimes(2);
    await act(async () => { finish(status([job])); });
  });

  it('ignores staging-only responses, malformed identities and corrupt saved records', () => {
    rememberUpdateJob({ ...receipt, update_started: false });
    expect(loadUpdateJob()).toBeNull();
    rememberUpdateJob({ ...receipt, job: { ...job, package_sha256: 'invalid' } });
    expect(loadUpdateJob()).toBeNull();
    localStorage.setItem('dcentos-update-job', '{broken');
    expect(loadUpdateJob()).toBeNull();
    rememberUpdateJob(receipt);
    expect(loadUpdateJob()).toMatchObject(jobIdentity());
  });
});

function jobIdentity() {
  return { job_id: job.job_id, source_boot_id: job.source_boot_id, package_sha256: job.package_sha256 };
}
