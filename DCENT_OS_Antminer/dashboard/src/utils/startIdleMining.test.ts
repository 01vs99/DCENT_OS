import { describe, expect, it, vi } from 'vitest';
import { startIdleMining } from './startIdleMining';

function client() {
  return {
    getConfig: vi.fn().mockResolvedValue({ initial_idle_activation_available: true }),
    getPools: vi.fn().mockResolvedValue({ pools: [{ id: 0, url: 'stratum+tcp://pool.example:3333', worker: 'tester' }] }),
    updateConfig: vi.fn().mockResolvedValue({ status: 'ok' }),
  };
}

describe('initial idle mining start', () => {
  it('saves enabled only after the daemon and primary pool are ready', async () => {
    const transport = client();
    await startIdleMining(transport);
    expect(transport.updateConfig).toHaveBeenCalledTimes(1);
    expect(transport.updateConfig).toHaveBeenCalledWith({ mining: { enabled: true } });
  });

  it('does not mutate an active, unsupported, or older daemon', async () => {
    const transport = client();
    transport.getConfig.mockResolvedValue({});
    await expect(startIdleMining(transport)).rejects.toThrow('unavailable');
    expect(transport.getPools).not.toHaveBeenCalled();
    expect(transport.updateConfig).not.toHaveBeenCalled();
  });

  it('requires the primary pool even if a secondary pool exists', async () => {
    const transport = client();
    transport.getPools.mockResolvedValue({ pools: [{ id: 1, url: 'stratum+tcp://pool.example:3333', worker: 'tester' }] });
    await expect(startIdleMining(transport)).rejects.toThrow('primary pool');
    expect(transport.updateConfig).not.toHaveBeenCalled();
  });

  it('reports a failed configuration save to the caller', async () => {
    const transport = client();
    transport.updateConfig.mockRejectedValue(new Error('write failed'));
    await expect(startIdleMining(transport)).rejects.toThrow('write failed');
  });
});
