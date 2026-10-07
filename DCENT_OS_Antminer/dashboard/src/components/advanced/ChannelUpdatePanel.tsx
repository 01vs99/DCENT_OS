import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import type { ChannelStagedUpdate, ChannelUpdateCheck, ChannelUpdateOperation } from '../../api/types';

const CONFIRMATION = 'INSTALL VERIFIED UPDATE';

export function ChannelUpdatePanel() {
  const [checked, setChecked] = useState<ChannelUpdateCheck | null>(null);
  const [staged, setStaged] = useState<ChannelStagedUpdate | null>(null);
  const [operation, setOperation] = useState<ChannelUpdateOperation | null>(null);
  const [checking, setChecking] = useState(false);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [downloads, setDownloads] = useState<string[] | null>(null);
  const active = operation && !['staged', 'scheduled', 'failed'].includes(operation.phase);
  const busy = checking || sending || !!active;

  useEffect(() => {
    if (!active || !operation) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const value = await api.getChannelUpdateStatus(operation.operation_id);
        if (cancelled) return;
        setOperation(value);
        if (value.phase === 'staged' && value.result && 'download_id' in value.result) setStaged(value.result);
        if (value.phase === 'failed') setError(value.detail || 'The operation failed. Installation completion is not confirmed.');
        if (!['staged', 'scheduled', 'failed'].includes(value.phase)) timer = setTimeout(() => void poll(), 1500);
      } catch (cause) {
        if (!cancelled) {
          setError(cause instanceof Error ? cause.message : 'Update operation could not be observed.');
          setOperation(null);
        }
      }
    };
    void poll();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [operation?.operation_id, !!active]);

  async function check() {
    setChecking(true); setError(''); setChecked(null); setStaged(null); setOperation(null); setConfirmation('');
    try { setChecked(await api.checkChannelUpdate()); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Channel check failed.'); }
    finally { setChecking(false); }
  }

  async function fetchUpdate() {
    if (!checked) return;
    setSending(true); setError(''); setStaged(null);
    try { setOperation(await api.fetchChannelUpdate(checked.feed_sha256, checked.candidate.sha256)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Download could not start.'); }
    finally { setSending(false); }
  }

  async function apply() {
    if (!staged || confirmation !== CONFIRMATION) return;
    setSending(true); setError('');
    try { setOperation(await api.applyChannelUpdate(staged.download_id, staged.feed_sha256, staged.artifact_sha256, confirmation)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Update scheduling could not be confirmed.'); }
    finally { setSending(false); }
  }

  async function storedDownloads() {
    setSending(true); setError('');
    try { setDownloads((await api.getChannelDownloads()).download_ids); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Stored downloads could not be inspected.'); }
    finally { setSending(false); }
  }

  async function discard(downloadId: string) {
    setSending(true); setError('');
    try {
      await api.discardChannelDownload(downloadId);
      setDownloads(current => current?.filter(id => id !== downloadId) ?? null);
      if (staged?.download_id === downloadId) { setStaged(null); setOperation(null); setConfirmation(''); }
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'The download could not be discarded.'); }
    finally { setSending(false); }
  }

  return <section className="mm-url-section" aria-label="Release channel update">
    <h3>Release channel update</h3>
    <p>Check the image's trusted release channel. Downloading verifies and stages the package; installation requires a separate confirmation.</p>
    <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void check()}>
      {checking ? 'Checking channel…' : 'Check for updates'}
    </button>
    {checked && <div>
      <p>{checked.candidate.board_target}: {checked.current_version} → {checked.candidate.version} ({checked.release_channel}).
        Minimum installed version: {checked.candidate.minimum_version}.</p>
      {!staged && <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void fetchUpdate()}>
        Download and verify
      </button>}
    </div>}
    {operation && <p role="status">
      {operation.phase === 'checking' && 'Rechecking the selected release…'}
      {operation.phase === 'downloading' && `Downloading ${operation.downloaded_bytes ?? 0} of ${operation.total_bytes ?? 0} bytes…`}
      {operation.phase === 'verifying' && 'Verifying package signature and target preflight…'}
      {operation.phase === 'staged' && 'Verified download staged. Nothing has been installed.'}
      {operation.phase === 'applying' && 'Rechecking the staged package and scheduling the update…'}
      {operation.phase === 'scheduled' && 'Update scheduled. Use update status below to follow the worker and subsequent boot result.'}
    </p>}
    {staged && operation?.phase !== 'scheduled' && <div>
      <p>The miner may reboot after checked shutdown and inactive-slot flashing.</p>
      <label>Type {CONFIRMATION}
        <input value={confirmation} onChange={event => setConfirmation(event.target.value)} disabled={busy} />
      </label>
      <button type="button" className="btn btn-danger" disabled={busy || confirmation !== CONFIRMATION} onClick={() => void apply()}>
        Install verified update
      </button>
    </div>}
    <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void storedDownloads()}>
      Show stored downloads
    </button>
    {downloads && <div>
      <p>At most two downloads are stored. Discarding frees space and does not change an installed image or a scheduled worker.</p>
      {downloads.length === 0 && <p>No stored downloads.</p>}
      {downloads.map(id => <p key={id}>Download {id} <button type="button" disabled={busy} onClick={() => void discard(id)}>
        Discard download {id}
      </button></p>)}
    </div>}
    {error && <p role="alert">{error}</p>}
  </section>;
}
