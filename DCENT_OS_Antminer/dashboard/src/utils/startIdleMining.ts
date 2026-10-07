import type { api } from '../api/client';

/** Start only through the daemon's initial idle configuration owner. */
export async function startIdleMining(client: Pick<typeof api, 'getConfig' | 'getPools' | 'updateConfig'>): Promise<void> {
  const config = await client.getConfig();
  if (!config.initial_idle_activation_available) {
    throw new Error('Starting mining is unavailable in the current state. Check the status page.');
  }
  const { pools } = await client.getPools();
  const primary = pools.find(pool => pool.id === 0);
  if (!primary?.url.trim() || !primary.worker.trim()) {
    throw new Error('Save a primary pool URL and worker before starting mining.');
  }
  // The initial idle owner validates this saved configuration and activates
  // itself. No service restart or machine reboot is needed from the browser.
  await client.updateConfig({ mining: { enabled: true } });
}
