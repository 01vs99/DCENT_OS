// @vitest-environment jsdom
import React from 'react';
import { afterEach, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { api } from '../../api/client';
import { useMinerStore } from '../../store/miner';
import { TuningPriorityConfigurator } from './TuningPriorityConfigurator';

const original = useMinerStore.getState();
afterEach(() => { cleanup(); vi.restoreAllMocks(); useMinerStore.setState(original); });

it.each([true, false])('changes fan policy only after a positive power acknowledgement: %s', async applied => {
  const addAlert = vi.fn();
  useMinerStore.setState({ addAlert,
    status: { hashrate_ghs: 10000, chains: [], fans: { pwm: 20 } } as never,
    heaterStatus: { wall_watts: 1000, source: 'pmbus', live_power_available: true } as never,
    stats: null,
  });
  vi.spyOn(api, 'setHeaterTarget').mockResolvedValue({ status: 'ok', message: 'Power request saved', applied_runtime: applied });
  const fan = vi.spyOn(api, 'setFan').mockResolvedValue({ status: 'ok' } as never);
  render(<TuningPriorityConfigurator />);
  fireEvent.click(screen.getByRole('button', { name: /Apply/i }));
  fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
  await waitFor(() => expect(addAlert).toHaveBeenCalled());
  expect(fan).toHaveBeenCalledTimes(applied ? 1 : 0);
  expect(addAlert.mock.calls[0][0]).toBe(applied ? 'info' : 'warning');
});
