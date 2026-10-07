// @vitest-environment jsdom
import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import type { SshKeyEnrollmentResult, SshKeyStatus } from '../../../api/types';

const mocks = vi.hoisted(() => ({ get: vi.fn(), enroll: vi.fn() }));
vi.mock('../../../api/client', () => ({ api: { getSshKeyStatus: mocks.get, enrollSshKeys: mocks.enroll } }));
vi.mock('../../../store/miner', () => ({
  useMinerStore: (selector: (state: { settings: { apiToken: string } }) => unknown) => selector({ settings: { apiToken: 'fixture-admin-session' } }),
}));
import { SshKeysPanel } from './SshKeysPanel';

const status: SshKeyStatus = { available: true, scope: 'classic_aml_nvdata', reason: null,
  fingerprints: [], operator_disabled: false, root_password_changed: false };
// Public-only wire-shape fixture. The backend independently checks the point.
const publicKey = `ssh-ed25519 ${'A'.repeat(68)} public-fixture`;
const result: SshKeyEnrollmentResult = { status: { ...status, fingerprints: ['SHA256:public-fixture'] },
  persisted: true, durable: true, activation: 'requested', activation_error: null };

beforeEach(() => {
  mocks.get.mockReset().mockResolvedValue(status);
  mocks.enroll.mockReset().mockResolvedValue(result);
});
afterEach(cleanup);

async function enterKey() {
  const input = await screen.findByLabelText('Ed25519 public key');
  fireEvent.change(input, { target: { value: publicKey } });
  fireEvent.click(screen.getByRole('button', { name: 'Add public key and start SSH' }));
}

describe('SSH public-key enrollment', () => {
  it('submits a public key and reports startup as requested, with no password-login claim', async () => {
    render(<SshKeysPanel />);
    await enterKey();
    expect(await screen.findByText(/Public key saved\. SSH startup requested/)).toBeTruthy();
    expect(mocks.enroll).toHaveBeenCalledWith(publicKey, true);
    expect(screen.getByText('SHA256:public-fixture')).toBeTruthy();
    expect((screen.getByLabelText('Ed25519 public key') as HTMLTextAreaElement).value).toBe('');
    expect(screen.getByText(/dashboard password does not set a Linux login password/)).toBeTruthy();
  });

  it('does not submit private-key text', async () => {
    render(<SshKeysPanel />);
    fireEvent.change(await screen.findByLabelText('Ed25519 public key'), { target: { value: '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add public key and start SSH' }));
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(mocks.enroll).not.toHaveBeenCalled();
  });

  it('keeps unavailable storage out of the enrollment flow', async () => {
    mocks.get.mockResolvedValue({ ...status, available: false, reason: 'unqualified family' });
    render(<SshKeysPanel />);
    expect(await screen.findByText('SSH key enrollment is unavailable on this image.')).toBeTruthy();
    expect(screen.queryByLabelText('Ed25519 public key')).toBeNull();
    expect(mocks.enroll).not.toHaveBeenCalled();
  });

  it('rejects a key comment beyond the server line limit before submission', async () => {
    render(<SshKeysPanel />);
    fireEvent.change(await screen.findByLabelText('Ed25519 public key'), { target: { value: `${publicKey} ${'x'.repeat(4200)}` } });
    fireEvent.click(screen.getByRole('button', { name: 'Add public key and start SSH' }));
    expect(await screen.findByText(/Each public-key line must be at most 4096 characters/)).toBeTruthy();
    expect(mocks.enroll).not.toHaveBeenCalled();
  });

  it('reports preserved enrollment when service activation fails', async () => {
    mocks.enroll.mockResolvedValue({ ...result, activation: 'failed', activation_error: 'fixture failure' });
    render(<SshKeysPanel />);
    await enterKey();
    expect(await screen.findByText(/Public key saved, but SSH startup failed/)).toBeTruthy();
    expect(screen.getByText('SHA256:public-fixture')).toBeTruthy();
  });

  it('does not turn an uncertain durability result into successful activation', async () => {
    mocks.enroll.mockResolvedValue({ ...result, durable: false, activation: 'not_requested' });
    render(<SshKeysPanel />);
    await enterKey();
    expect(await screen.findByText(/storage durability was not confirmed/)).toBeTruthy();
    expect((screen.getByLabelText('Ed25519 public key') as HTMLTextAreaElement).value).toBe(publicKey);
  });

  it('preserves the operator disable preference', async () => {
    mocks.get.mockResolvedValue({ ...status, operator_disabled: true });
    mocks.enroll.mockResolvedValue({ ...result, status: { ...result.status, operator_disabled: true }, activation: 'disabled_by_operator' });
    render(<SshKeysPanel />);
    await enterKey();
    expect(await screen.findByText(/Your saved SSH opt-out remains in effect/)).toBeTruthy();
  });

  it('requires an admin session and allows a status retry', async () => {
    mocks.get.mockRejectedValueOnce(new Error('Unauthorized'));
    render(<SshKeysPanel />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryByLabelText('Ed25519 public key')).toBeNull();
    fireEvent.click(screen.getByRole('button', { name: 'Refresh SSH status' }));
    await waitFor(() => expect(screen.getByLabelText('Ed25519 public key')).toBeTruthy());
    expect(mocks.get).toHaveBeenCalledTimes(2);
  });
});
