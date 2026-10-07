// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
const mocks = vi.hoisted(() => ({ get: vi.fn(), update: vi.fn() }));
vi.mock('../../../api/client', () => ({ api: {
  getConfig: mocks.get, updateConfig: mocks.update,
  getNetworkInfo: async () => ({ hostname: 'fixture-miner' }),
} }));
vi.mock('../NotificationSettings', () => ({ NotificationSettings: () => null }));
vi.mock('../../../store/miner', () => ({ useMinerStore: (selector: (state: unknown) => unknown) => selector({
  systemInfo: null, settings: { soundAlerts: false, browserNotifications: false },
  updateSettings: () => {}, addAlert: () => {},
}) }));
import { FleetApiSettings } from './FleetApiSettings';
import { NetworkTab } from './NetworkTab';
const current = { cgminer_port: 4028, cgminer_bind_lan: true, cgminer_lan_writes: false };
beforeEach(() => {
  mocks.get.mockReset().mockResolvedValue({ api: current });
  mocks.update.mockReset().mockResolvedValue({ status: 'ok' });
});
afterEach(cleanup);

describe('Fleet API network controls', () => {
  it('is reachable from the actual Network settings tab', async () => {
    render(<NetworkTab />);
    expect(await screen.findByLabelText('Allow LAN monitoring')).toBeTruthy();
    expect(screen.getByLabelText('Allow LAN control commands')).toBeTruthy();
  });
  it('shows the reported read-only default and an explicit unauthenticated control warning', async () => {
    render(<FleetApiSettings />);
    expect((await screen.findByLabelText('Allow LAN monitoring') as HTMLInputElement).checked).toBe(true);
    expect((screen.getByLabelText('Allow LAN control commands') as HTMLInputElement).checked).toBe(false);
    expect(screen.getByText(/LAN control has no password authentication/)).toBeTruthy();
    expect(screen.getByText(/redirect your hashrate/)).toBeTruthy();
    expect(mocks.update).not.toHaveBeenCalled();
  });
  it('persists explicit write opt-in without pretending the running listener has changed', async () => {
    render(<FleetApiSettings />);
    fireEvent.click(await screen.findByLabelText('Allow LAN control commands'));
    fireEvent.click(screen.getByRole('button', { name: 'Save fleet API settings' }));
    await screen.findByText(/Settings saved. Restart required/);
    expect(mocks.update).toHaveBeenCalledWith({ api: { cgminer_bind_lan: true, cgminer_lan_writes: true } });
    expect(screen.getByText(/Currently running: LAN monitoring, remote writes blocked/)).toBeTruthy();
  });
  it('disabling LAN visibility also clears latent remote-write permission', async () => {
    mocks.get.mockResolvedValue({ api: { ...current, cgminer_lan_writes: true } });
    render(<FleetApiSettings />);
    fireEvent.click(await screen.findByLabelText('Allow LAN monitoring'));
    const writes = screen.getByLabelText('Allow LAN control commands') as HTMLInputElement;
    expect(writes.checked).toBe(false);
    expect(writes.disabled).toBe(true);
    fireEvent.click(screen.getByRole('button', { name: 'Save fleet API settings' }));
    await waitFor(() => expect(mocks.update).toHaveBeenCalledWith({ api: { cgminer_bind_lan: false, cgminer_lan_writes: false } }));
  });
  it('reloads saved pending changes and still reports the actual running state', async () => {
    mocks.get.mockResolvedValue({ api: { ...current, cgminer_saved: { cgminer_bind_lan: false, cgminer_lan_writes: false } } });
    render(<FleetApiSettings />);
    expect((await screen.findByLabelText('Allow LAN monitoring') as HTMLInputElement).checked).toBe(false);
    expect(screen.getByText(/Settings saved. Restart required/)).toBeTruthy();
    expect(screen.getByText(/Currently running: LAN monitoring/)).toBeTruthy();
  });
  it('keeps a failed save visible and retryable without reporting success', async () => {
    mocks.update.mockRejectedValue(new Error('Persistent storage is read-only'));
    render(<FleetApiSettings />);
    fireEvent.click(await screen.findByLabelText('Allow LAN control commands'));
    fireEvent.click(screen.getByRole('button', { name: 'Save fleet API settings' }));
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', 'Persistent storage is read-only');
    expect(screen.queryByText(/Settings saved. Restart required/)).toBeNull();
    expect((screen.getByRole('button', { name: 'Save fleet API settings' }) as HTMLButtonElement).disabled).toBe(false);
  });
  it('does not guess access flags when older firmware omits them', async () => {
    mocks.get.mockResolvedValue({ api: { cgminer_port: 4028 } });
    render(<FleetApiSettings />);
    expect(await screen.findByRole('alert')).toBeTruthy();
    expect(screen.queryByLabelText('Allow LAN monitoring')).toBeNull();
    expect(mocks.update).not.toHaveBeenCalled();
  });
});
