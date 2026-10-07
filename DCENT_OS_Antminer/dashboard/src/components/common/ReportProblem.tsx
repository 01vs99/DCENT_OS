import React, { useState } from 'react';
import { api } from '../../api/client';

/** The miner serves a redacted download; support is a separate browser action. */
export function ReportProblem() {
  const [busy, setBusy] = useState(false);
  const [downloaded, setDownloaded] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function download() {
    setBusy(true);
    setError(null);
    try {
      const bundle = await api.fetchLogBackup();
      if (!bundle) throw new Error('Support download is unavailable. Retry when the miner reconnects.');
      const url = URL.createObjectURL(new Blob([bundle.text], { type: 'text/plain;charset=utf-8' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = bundle.filename.replace(/[^a-zA-Z0-9._-]/g, '_');
      document.body.appendChild(link);
      link.click();
      link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setDownloaded(true);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Support download failed.');
    } finally { setBusy(false); }
  }
  return <div className="support-download" style={{ marginTop: 12 }}>
    <button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void download()}>
      {busy ? 'Preparing support bundle…' : 'Report a problem / download logs'}
    </button>
    <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: '8px 0' }}>
      Downloads redacted logs, build identity and the last crash record. Nothing is uploaded.
    </p>
    {downloaded && <p role="status">Bundle downloaded. Review it, then attach it to your{' '}
      <a href="https://d-central.tech/contact/" target="_blank" rel="noopener noreferrer">support request</a>.
    </p>}
    {error && <p role="alert">{error}</p>}
  </div>;
}
