// @vitest-environment jsdom
import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { useMinerStore } from '../store/miner';
import { PowerPresets } from '../components/basic/PowerPresets';
import { api } from '../api/client';

const originalAddToast = useMinerStore.getState().addToast;
afterEach(() => { cleanup(); vi.restoreAllMocks(); useMinerStore.setState({ addToast: originalAddToast }); });
it('does not substitute S9 controls when this model has no presets', () => {
  useMinerStore.setState({ heaterPresets: [], heaterPresetScope: { kind: 'unavailable', family: 'unknown', chip_type: 'unknown', label: 'Unknown', universal: false } });
  render(<PowerPresets />);
  expect(screen.queryAllByRole('button')).toHaveLength(0);
  expect(screen.getByText(/No heater presets are available/)).toBeTruthy();
});

it('shows an S19j request without calculating fictional heat or wall-power estimates', () => {
  useMinerStore.setState({ heaterPresets: [{ name: 's19j_low', watts: 600, btu_h: 0, noise_db: null, description: 'Power target', estimates_available: false }], heaterPresetScope: { kind: 'model', family: 's19j_pro', chip_type: 'BM1362', label: 'S19j Pro / Xilinx', universal: false } });
  const { container } = render(<PowerPresets />);
  expect(screen.getByRole('button', { name: /600 watts/ })).toBeTruthy();
  expect(container.textContent).not.toContain('BTU/h');
  expect(container.textContent).not.toContain('Preset estimates');
  expect(screen.getByText('Power target; check live wall power')).toBeTruthy();
});

it.each([
  { applied_runtime: true, status: 'ok', message: 'Owner adopted target', tone: 'success' },
  { applied_runtime: false, status: 'ok', message: 'Saved only', tone: 'warning' },
  { applied_runtime: false, status: 'error', message: 'Write failed', tone: 'error' },
] as const)('reports $tone only from the actual preset response', async ({ tone, ...response }) => {
  const addToast = vi.fn();
  useMinerStore.setState({ addToast, heaterPresets: [{ name: 's19j_low', watts: 600, btu_h: 0, noise_db: null, description: 'Requested target', estimates_available: false }],
    heaterPresetScope: { kind: 'model', family: 's19j_pro', chip_type: 'BM1362', label: 'S19j Pro / Xilinx', universal: false,
      live_control_available: false, control_note: 'This runtime saves requests only.' } });
  const send = vi.spyOn(api, 'setHeaterTarget').mockResolvedValue(response);
  render(<PowerPresets />);
  expect(screen.getByRole('status').textContent).toBe('This runtime saves requests only.');
  fireEvent.click(screen.getByRole('button', { name: /600 watts/ }));
  await waitFor(() => expect(addToast).toHaveBeenCalledWith(expect.any(String), tone));
  expect(send).toHaveBeenCalledWith({ preset: 's19j_low' });
});
