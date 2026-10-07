import React, { useEffect, useState } from 'react';
import { api } from '../../../api/client';
import type { SshKeyEnrollmentResult, SshKeyStatus } from '../../../api/types';
import { useMinerStore } from '../../../store/miner';

function resultMessage(result: SshKeyEnrollmentResult): string {
  if (!result.persisted) return 'The public key was not saved.';
  if (!result.durable) {
    return 'The key file was saved, but storage durability was not confirmed. SSH startup was not requested. Refresh the status and retry.';
  }
  switch (result.activation) {
    case 'requested': return 'Public key saved. SSH startup requested. Use the matching private key to connect as root.';
    case 'disabled_by_operator': return 'Public key saved. Your saved SSH opt-out remains in effect.';
    case 'failed': return 'Public key saved, but SSH startup failed. Refresh the status and retry.';
    default: return 'Public key saved. SSH startup was not requested.';
  }
}

export function SshKeysPanel() {
  const token = useMinerStore(state => state.settings.apiToken);
  const [status, setStatus] = useState<SshKeyStatus | null>(null);
  const [publicKeys, setPublicKeys] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    let current = true;
    setLoading(true);
    setError('');
    void api.getSshKeyStatus().then(value => {
      if (current) setStatus(value);
    }).catch(() => {
      if (current) {
        setStatus(null);
        setError('Sign in with an admin dashboard session to view SSH enrollment. Finish setup before adding a key.');
      }
    }).finally(() => { if (current) setLoading(false); });
    return () => { current = false; };
  }, [token, refresh]);

  const enroll = async () => {
    // Prevent accidental private-key submission in the browser. The API also
    // validates every key's complete Ed25519 wire format independently.
    const rawLines = publicKeys.split(/\r?\n/);
    if (rawLines.some(line => line.length > 4096)) {
      setError('Each public-key line must be at most 4096 characters. Shorten the key comment and retry.');
      return;
    }
    const lines = rawLines.map(line => line.trim()).filter(Boolean);
    if (publicKeys.length > 8192 || lines.length === 0 || lines.length > 16
      || lines.some(line => !/^ssh-ed25519\s+[A-Za-z0-9+/]{68}(?:\s+[^\r\n]*)?$/.test(line))) {
      setError('Paste an Ed25519 public key starting with ssh-ed25519. Private keys and authorized_keys options are not accepted.');
      return;
    }
    setSaving(true);
    setMessage('');
    setError('');
    try {
      const result = await api.enrollSshKeys(publicKeys, true);
      setStatus(result.status);
      setMessage(resultMessage(result));
      if (result.persisted && result.durable) setPublicKeys('');
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : 'SSH key enrollment failed. Refresh the status before retrying.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <section aria-labelledby="ssh-key-title" style={{
      background: 'var(--card-bg)', borderRadius: 'var(--radius)', padding: 16,
      border: '1px solid var(--border)', maxWidth: 560, marginTop: 16,
    }}>
      <h3 id="ssh-key-title" style={{ fontSize: '0.9rem', marginTop: 0 }}>SSH public keys</h3>
      <p style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
        SSH uses an Ed25519 public key. Keep the matching private key on your computer.
        Your dashboard password does not set a Linux login password.
      </p>
      {loading && <p role="status">Checking SSH storage…</p>}
      {!loading && status && !status.available && (
        <p>SSH key enrollment is unavailable on this image.</p>
      )}
      {status?.available && (
        <>
          <p>{status.fingerprints.length} public {status.fingerprints.length === 1 ? 'key' : 'keys'} enrolled.</p>
          {status.fingerprints.length > 0 && (
            <ul aria-label="Enrolled SSH fingerprints" style={{ paddingLeft: 20 }}>
              {status.fingerprints.map(fingerprint => (
                <li key={fingerprint} style={{ overflowWrap: 'anywhere', fontFamily: 'monospace', fontSize: '0.75rem' }}>
                  {fingerprint}
                </li>
              ))}
            </ul>
          )}
          {status.operator_disabled && <p>SSH is disabled by your saved preference. Adding a key preserves that preference.</p>}
          <label htmlFor="ssh-public-keys">Ed25519 public key</label>
          <textarea id="ssh-public-keys" value={publicKeys} onChange={event => setPublicKeys(event.target.value)}
            placeholder="ssh-ed25519 AAAA… your-label" rows={4} maxLength={8192} spellCheck={false}
            autoComplete="off" style={{ width: '100%', marginTop: 8, boxSizing: 'border-box' }} />
          <p style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>Existing keys are kept. Up to 16 distinct keys may be enrolled.</p>
          <button className="btn btn-primary" onClick={() => { void enroll(); }}
            disabled={saving || !publicKeys.trim()}>
            {saving ? 'Saving public key…' : 'Add public key and start SSH'}
          </button>
        </>
      )}
      <button className="btn" style={{ marginTop: 10, marginLeft: status?.available ? 8 : 0 }}
        onClick={() => setRefresh(value => value + 1)} disabled={loading || saving}>Refresh SSH status</button>
      {message && <p role="status">{message}</p>}
      {error && <p role="alert">{error}</p>}
    </section>
  );
}
