// @vitest-environment jsdom
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { api } from './client';
import { loadUpdateJob } from '../utils/updateJob';

const job = {
  schema: 1, job_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  source_boot_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  package_sha256: 'c'.repeat(64), state: 'scheduled', boot_verified: false,
};
const requests: { method: string; url: string; body: FormData }[] = [];
let apply = true;

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  requests.length = 0;
  apply = true;
  vi.stubGlobal('XMLHttpRequest', class {
    upload = {};
    status = 200;
    responseText = '';
    onload?: () => void;
    method = '';
    url = '';
    open(method: string, url: string) { this.method = method; this.url = url; }
    setRequestHeader() { /* fixture has no credentials */ }
    send(body: FormData) {
      requests.push({ method: this.method, url: this.url, body });
      this.responseText = JSON.stringify({ status: 'ok', message: 'Accepted', filename: 'beta.tar', update_started: apply, job: apply ? job : undefined });
      queueMicrotask(() => this.onload?.());
    }
  });
});
afterEach(() => vi.unstubAllGlobals());

it.each(['file', 'staged'] as const)('saves the exact apply receipt through the actual %s upload API', async source => {
  const options = source === 'file'
    ? { file: new File(['fixture'], 'beta.tar') }
    : { stagedPath: '/tmp/dcentos-upgrade/upload/beta.tar' };
  const result = await api.uploadFirmware({ ...options, apply: true });
  expect(result.job).toEqual(job);
  expect(loadUpdateJob()).toEqual({ job_id: job.job_id, source_boot_id: job.source_boot_id, package_sha256: job.package_sha256, filename: 'beta.tar' });
  expect(requests).toHaveLength(1);
  expect(requests[0]).toMatchObject({ method: 'POST', url: '/api/system/upgrade' });
  expect(requests[0].body.get('apply')).toBe('true');
});

it('keeps validation-only uploads out of persistent running-job tracking', async () => {
  apply = false;
  await api.uploadFirmware({ stagedPath: '/tmp/dcentos-upgrade/upload/beta.tar' });
  expect(requests).toHaveLength(1);
  expect(requests[0].body.get('apply')).toBe('false');
  expect(loadUpdateJob()).toBeNull();
});
