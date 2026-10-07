// @vitest-environment jsdom
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { ChannelUpdatePanel } from './ChannelUpdatePanel';
import { api } from '../../api/client';

vi.mock('../../api/client', () => ({ api: {
  checkChannelUpdate: vi.fn(), fetchChannelUpdate: vi.fn(),
  getChannelUpdateStatus: vi.fn(), applyChannelUpdate: vi.fn(),
  getChannelDownloads: vi.fn(), discardChannelDownload: vi.fn(),
} }));

const candidate = { board_target: 'am1-s9', version: '1.2.3', minimum_version: '0.9.0',
  release_channel: 'beta', sha256: 'b'.repeat(64), size: 1024 };
const checked = { status: 'available', board_target: 'am1-s9', current_version: '1.2.2',
  release_channel: 'beta', feed_sha256: 'a'.repeat(64), candidate, update_started: false };
const staged = { status: 'staged', download_id: 'retained-id', feed_sha256: checked.feed_sha256,
  artifact_sha256: candidate.sha256, candidate, update_started: false };

describe('Channel update operator flow', () => {
  beforeEach(() => { vi.resetAllMocks(); });
  afterEach(cleanup);

  it('has no automatic network check, download or install', () => {
    render(<ChannelUpdatePanel />);
    expect(api.checkChannelUpdate).not.toHaveBeenCalled();
    expect(api.fetchChannelUpdate).not.toHaveBeenCalled();
    expect(api.applyChannelUpdate).not.toHaveBeenCalled();
    expect(screen.queryByRole('textbox')).toBeNull();
  });

  it('pins check/download/apply separately and never installs after fetch', async () => {
    vi.mocked(api.checkChannelUpdate).mockResolvedValue(checked as never);
    vi.mocked(api.fetchChannelUpdate).mockResolvedValue({ operation_id: 'fetch-id', phase: 'checking' });
    vi.mocked(api.getChannelUpdateStatus).mockResolvedValue({ operation_id: 'fetch-id', phase: 'staged', result: staged as never });
    vi.mocked(api.applyChannelUpdate).mockResolvedValue({ operation_id: 'apply-id', phase: 'applying' });
    render(<ChannelUpdatePanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Check for updates' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Download and verify' }));
    await screen.findByText('Verified download staged. Nothing has been installed.');
    expect(api.fetchChannelUpdate).toHaveBeenCalledWith(checked.feed_sha256, candidate.sha256);
    expect(api.applyChannelUpdate).not.toHaveBeenCalled();
    const install = screen.getByRole('button', { name: 'Install verified update' });
    expect((install as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'install verified update' } });
    expect((install as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'INSTALL VERIFIED UPDATE' } });
    vi.mocked(api.getChannelUpdateStatus).mockResolvedValue({ operation_id: 'apply-id', phase: 'scheduled' });
    fireEvent.click(install);
    await screen.findByText(/Update scheduled\./);
    expect(api.applyChannelUpdate).toHaveBeenCalledWith(staged.download_id, staged.feed_sha256,
      staged.artifact_sha256, 'INSTALL VERIFIED UPDATE');
    expect(screen.queryByText(/successfully installed/i)).toBeNull();
  });

  it('shows policy/signature refusal and exposes no fetch action', async () => {
    vi.mocked(api.checkChannelUpdate).mockRejectedValue(new Error('This release requires external media.'));
    render(<ChannelUpdatePanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Check for updates' }));
    expect((await screen.findByRole('alert')).textContent).toContain('requires external media');
    expect(screen.queryByRole('button', { name: 'Download and verify' })).toBeNull();
    expect(api.fetchChannelUpdate).not.toHaveBeenCalled();
  });

  it('does not offer install when asynchronous verification fails', async () => {
    vi.mocked(api.checkChannelUpdate).mockResolvedValue(checked as never);
    vi.mocked(api.fetchChannelUpdate).mockResolvedValue({ operation_id: 'fetch-id', phase: 'checking' });
    vi.mocked(api.getChannelUpdateStatus).mockResolvedValue({ operation_id: 'fetch-id', phase: 'failed', detail: 'SHA-256 mismatch' });
    render(<ChannelUpdatePanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Check for updates' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Download and verify' }));
    expect((await screen.findByRole('alert')).textContent).toContain('SHA-256 mismatch');
    expect(screen.queryByRole('button', { name: 'Install verified update' })).toBeNull();
    expect(api.applyChannelUpdate).not.toHaveBeenCalled();
  });

  it('reports a lost operation without claiming completion', async () => {
    vi.mocked(api.checkChannelUpdate).mockResolvedValue(checked as never);
    vi.mocked(api.fetchChannelUpdate).mockResolvedValue({ operation_id: 'fetch-id', phase: 'checking' });
    vi.mocked(api.getChannelUpdateStatus).mockRejectedValue(new Error('Daemon restarted; operation unknown.'));
    render(<ChannelUpdatePanel />);
    fireEvent.click(screen.getByRole('button', { name: 'Check for updates' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Download and verify' }));
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('operation unknown'));
    expect(api.applyChannelUpdate).not.toHaveBeenCalled();
    expect(screen.queryByText(/Update scheduled\./)).toBeNull();
  });

  it('explicitly discards a stored or interrupted download without starting an update', async () => {
    vi.mocked(api.getChannelDownloads).mockResolvedValue({ download_ids: ['old-stage'] });
    vi.mocked(api.discardChannelDownload).mockResolvedValue({ discarded: true });
    render(<ChannelUpdatePanel />);
    expect(api.getChannelDownloads).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: 'Show stored downloads' }));
    fireEvent.click(await screen.findByRole('button', { name: 'Discard download old-stage' }));
    await screen.findByText('No stored downloads.');
    expect(api.discardChannelDownload).toHaveBeenCalledWith('old-stage');
    expect(api.applyChannelUpdate).not.toHaveBeenCalled();
  });
});
