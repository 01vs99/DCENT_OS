// @vitest-environment jsdom
import React from 'react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BuildPanel } from './BuildPanel';
import { ReportProblem } from './ReportProblem';
import { ToastContainer } from './Toast';
import { DangerZonePage } from '../restore-to-stock/DangerZonePage';

const mockApi = vi.hoisted(() => ({ getDiagnostics: vi.fn(), fetchLogBackup: vi.fn(), resetSettings: vi.fn() }));
const toastState = vi.hoisted(() => ({ toasts: [] as Array<{ id: string; message: string; type: string; createdAt: number }>, removeToast: vi.fn() }));
vi.mock('../../store/miner', () => ({ useMinerStore: (select: (value: typeof toastState) => unknown) => select(toastState) }));
vi.mock('../../api/client', () => ({ api: mockApi }));
vi.mock('../restore-to-stock/RestoreToStockModal', () => ({ RestoreToStockModal: () => null }));
vi.mock('../restore-to-stock/HarvestModeBanner', () => ({ HarvestModeBanner: () => null }));
vi.mock('./Tooltip', () => ({ InfoDot: () => null }));

beforeEach(() => { vi.clearAllMocks(); });
afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it('renders exact image metadata and observed signature state', async () => {
  mockApi.getDiagnostics.mockResolvedValue({ board_target: 'am3-s21', image_version: '1.2.3',
    daemon_version: '1.2.3', git_sha: 'a'.repeat(40), channel: 'beta', drop: 'beta-7',
    active_slot: 'slot-b', signature_state: 'verified', signature_detail: null, warnings: [], last_panic: null });
  render(<BuildPanel />);
  await screen.findByText('am3-s21');
  for (const value of ['a'.repeat(40), 'beta', 'beta-7', 'slot-b', 'verified']) {
    expect(screen.getByText(value)).toBeTruthy();
  }
});

it('shows unavailable metadata without inventing a verified build', async () => {
  mockApi.getDiagnostics.mockRejectedValue(new Error('offline'));
  render(<BuildPanel />);
  await screen.findByText(/diagnostics are unavailable/);
  expect(screen.queryByText('verified')).toBeNull();
  expect(screen.getAllByText('Unavailable')).toHaveLength(8);
});

it('downloads the server-redacted bundle before offering a separate support link', async () => {
  const create = vi.fn(() => 'blob:local-support');
  Object.defineProperty(URL, 'createObjectURL', { configurable: true, value: create });
  Object.defineProperty(URL, 'revokeObjectURL', { configurable: true, value: vi.fn() });
  const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
  mockApi.fetchLogBackup.mockResolvedValue({ text: 'Build am3-s21\npassword=<redacted>', filename: 'support.txt' });
  render(<ReportProblem />);
  expect(screen.queryByRole('link')).toBeNull();
  fireEvent.click(screen.getByRole('button', { name: /Report a problem/ }));
  await screen.findByRole('link', { name: 'support request' });
  expect(mockApi.fetchLogBackup).toHaveBeenCalledOnce();
  expect(create).toHaveBeenCalledWith(expect.any(Blob));
  expect(click).toHaveBeenCalledOnce();
  expect(screen.getByText(/Nothing is uploaded/)).toBeTruthy();
});

it('keeps a failed support request visible without producing another toast', async () => {
  mockApi.fetchLogBackup.mockRejectedValue(new Error('Miner disconnected'));
  render(<ReportProblem />);
  fireEvent.click(screen.getByRole('button'));
  await screen.findByRole('alert');
  expect(screen.getByText('Miner disconnected')).toBeTruthy();
  expect(screen.queryByRole('link')).toBeNull();
});

it('requires exact reset confirmation and reports scheduling rather than completion', async () => {
  mockApi.resetSettings.mockResolvedValue({ status: 'scheduled', detail: 'Waiting for checked shutdown.' });
  render(<DangerZonePage />);
  const button = screen.getByRole('button', { name: 'Reset DCENT_OS settings' }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText('Type RESET DCENT_OS SETTINGS'), { target: { value: 'RESET DCENT_OS SETTINGS' } });
  fireEvent.click(button);
  await waitFor(() => expect(mockApi.resetSettings).toHaveBeenCalledWith('RESET DCENT_OS SETTINGS'));
  await screen.findByText('Waiting for checked shutdown.');
  expect(button.disabled).toBe(true);
});

it('offers a report download inside every error toast without nested buttons', () => {
  toastState.toasts = [{ id: '1', message: 'First failure', type: 'error', createdAt: 0 },
    { id: '2', message: 'Second failure', type: 'error', createdAt: 0 }];
  const { container } = render(<ToastContainer />);
  expect(screen.getAllByRole('button', { name: /Report a problem/ })).toHaveLength(2);
  expect(container.querySelector('button button')).toBeNull();
  fireEvent.click(screen.getAllByRole('button', { name: /notification/ })[0]);
  expect(toastState.removeToast).toHaveBeenCalledWith('1');
});
