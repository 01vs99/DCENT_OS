import { useEffect, useState } from 'react';
import { api } from '../../../api/client';
import type { ConfigResponse } from '../../../api/types';

type Access = { cgminer_bind_lan: boolean; cgminer_lan_writes: boolean };

export function FleetApiSettings() {
  const [running, setRunning] = useState<Access | null>(null);
  const [saved, setSaved] = useState<Access | null>(null);
  const [draft, setDraft] = useState<Access | null>(null);
  const [port, setPort] = useState(4028);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let active = true;
    api.getConfig().then((config: ConfigResponse) => {
      if (!active) return;
      const { cgminer_bind_lan, cgminer_lan_writes, cgminer_saved, cgminer_port } = config.api;
      if (typeof cgminer_bind_lan !== 'boolean' || typeof cgminer_lan_writes !== 'boolean') {
        setError('This firmware does not report fleet API access settings.');
        return;
      }
      const current = { cgminer_bind_lan, cgminer_lan_writes };
      setRunning(current);
      setSaved(cgminer_saved ?? current);
      setDraft(cgminer_saved ?? current);
      setPort(cgminer_port);
    }).catch((failure: unknown) => {
      if (active) setError(failure instanceof Error ? failure.message : 'Unable to load fleet API settings.');
    }).finally(() => { if (active) setLoaded(true); });
    return () => { active = false; };
  }, []);

  const different = (a: Access | null, b: Access | null) => !!a && !!b && (
    a.cgminer_bind_lan !== b.cgminer_bind_lan || a.cgminer_lan_writes !== b.cgminer_lan_writes
  );
  const save = async () => {
    if (!draft || saving) return;
    setSaving(true);
    setError('');
    try {
      await api.updateConfig({ api: draft });
      setSaved(draft);
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'Unable to save fleet API settings.');
    } finally {
      setSaving(false);
    }
  };

  return <>
    <div className="section-title">Fleet monitoring API</div>
    <div style={{ background: 'var(--card-bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', padding: 16 }}>
      <p>CGMiner-compatible TCP port {port} lets tools such as pyasic and hass-miner read status on your LAN.</p>
      {!loaded && <p role="status">Loading fleet API settings…</p>}
      {error && <p role="alert">{error}</p>}
      {draft && <>
        <label style={{ display: 'block', marginBottom: 12 }}>
          <input type="checkbox" checked={draft.cgminer_bind_lan} disabled={saving}
            onChange={event => setDraft({ ...draft, cgminer_bind_lan: event.target.checked,
              cgminer_lan_writes: event.target.checked ? draft.cgminer_lan_writes : false })} />
          {' '}Allow LAN monitoring
        </label>
        <label style={{ display: 'block', marginBottom: 12 }}>
          <input type="checkbox" checked={draft.cgminer_lan_writes} disabled={saving || !draft.cgminer_bind_lan}
            aria-describedby="fleet-api-write-warning"
            onChange={event => setDraft({ ...draft, cgminer_lan_writes: event.target.checked })} />
          {' '}Allow LAN control commands
        </label>
        <p id="fleet-api-write-warning" style={{ color: 'var(--orange)' }}>
          Warning: LAN control has no password authentication. Anyone who can reach this port could change pools,
          redirect your hashrate, change supported mining settings, or interrupt mining. Enable only on a trusted network.
        </p>
        <p>Read-only monitoring is the default. Changes are saved for the next daemon restart; saving does not restart mining.</p>
        {running && <p>Currently running: {running.cgminer_bind_lan
          ? running.cgminer_lan_writes ? 'LAN monitoring and control' : 'LAN monitoring, remote writes blocked'
          : 'local access only'}.</p>}
        {different(saved, running) && <p role="status">Settings saved. Restart required to apply fleet API access changes.</p>}
        <button type="button" className="btn btn-secondary" disabled={saving || !different(draft, saved)} onClick={() => void save()}>
          {saving ? 'Saving…' : 'Save fleet API settings'}
        </button>
      </>}
    </div>
  </>;
}
