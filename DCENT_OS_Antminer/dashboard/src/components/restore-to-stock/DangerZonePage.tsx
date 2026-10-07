// DangerZonePage — destructive operations live here, segregated
// from the main dashboard to avoid accidental clicks.
//
// Mounted at hash route #/system/danger-zone. The
// Restore-to-Stock button is the marquee feature; future
// destructive ops (factory reset, key revocation, NAND wipe)
// belong here too.

import React, { useState } from 'react';
import { RestoreToStockModal } from './RestoreToStockModal';
import { HarvestModeBanner } from './HarvestModeBanner';
import { InfoDot } from '../common/Tooltip';
import { api } from '../../api/client';

export function DangerZonePage() {
  const [restoreOpen, setRestoreOpen] = useState(false);
  const [confirmation, setConfirmation] = useState('');
  const [resetBusy, setResetBusy] = useState(false);
  const [resetMessage, setResetMessage] = useState<string | null>(null);
  const [resetError, setResetError] = useState<string | null>(null);
  async function resetSettings() {
    setResetBusy(true);
    setResetError(null);
    try {
      const result = await api.resetSettings(confirmation);
      setResetMessage(result.detail);
    } catch (error) {
      setResetError(error instanceof Error ? error.message : 'Settings reset could not be scheduled.');
    } finally { setResetBusy(false); }
  }

  return (
    <div className="page-content p4-danger-page">
      <div className="p4-danger-head">
        <h2 className="p4-danger-title">Danger zone</h2>
        <span className="ds-chip ds-danger" aria-label="Destructive operations">
          <span className="ds-dot" aria-hidden />
          Destructive
        </span>
        <InfoDot term="brick_anxiety" placement="bottom" label="Why these operations are gated" />
      </div>
      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary, #8b8b9e)', maxWidth: 720, marginBottom: 16 }}>
        Read the scope of each operation before confirming. Settings reset clears your DCENT_OS
        preferences and credentials. Flashing stock firmware has a separate preflight and confirmation.
      </div>

      <HarvestModeBanner />

      <section className="section" aria-label="Reset DCENT_OS settings">
        <h3>Reset DCENT_OS settings</h3>
        <p>Stops mining through the checked shutdown owner, clears DCENT_OS configuration,
          dashboard credentials, uploaded SSH keys and saved profiles, then reboots with mining disabled.
          Vendor partitions and hardware safety records are preserved. A failed shutdown prevents reset.</p>
        <label htmlFor="reset-settings-confirmation">Type RESET DCENT_OS SETTINGS</label>
        <input id="reset-settings-confirmation" value={confirmation} autoComplete="off"
          disabled={resetBusy || Boolean(resetMessage)} onChange={event => setConfirmation(event.target.value)} />
        <button type="button" className="btn-danger" onClick={() => void resetSettings()}
          disabled={resetBusy || Boolean(resetMessage) || confirmation !== 'RESET DCENT_OS SETTINGS'}>
          {resetBusy ? 'Scheduling reset…' : 'Reset DCENT_OS settings'}
        </button>
        {resetMessage && <p role="status">{resetMessage}</p>}
        {resetError && <p role="alert">{resetError}</p>}
        <details style={{ marginTop: 12 }}>
          <summary>Recover without a UART console</summary>
          <p>No reset-button timing is qualified. On supported external SD media, power down and
            use a Linux computer to place a root-owned <code>dcent/reset-settings</code> file
            on the DCENT data partition, containing <code>RESET DCENT_OS SETTINGS</code> followed
            by a newline. Use mode 0600 for the file and 0700 for its directory, unmount cleanly
            and reinstall the card. The next boot validates the signed defaults and checked
            shutdown before consuming the marker. This does not reset a separate NAND partition.</p>
          <p>An interrupted reset remains fenced. Resolve the reported cause before repeating
            the marker procedure. Never remove a hardware-session or crash journal to force startup.</p>
        </details>
      </section>

      <div className="section p4-restore-card">
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 280 }}>
            <h3 style={{ margin: 0, fontSize: '1rem', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              Flash stock Bitmain firmware
              <InfoDot term="slot_removed_warning" size={12} label="What this keeps and what it clears" />
            </h3>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary, #8b8b9e)', marginTop: 6, lineHeight: 1.5 }}>
              <strong>This removes DCENT_OS</strong> and writes stock Bitmain firmware to the
              inactive NAND slot so you can capture vendor telemetry for RE / harvest workflows.
              Any tuning, autotuner profiles, or operator config baked into DCENT_OS will not
              follow you to stock. Safety preflight refuses tainted firmware (SECURE_BOOT_SET,
              daemons:22322 listener, Hashcore root hash). NAND backup is mandatory.{' '}
              <strong>Manual recovery REQUIRED</strong> — full procedure is shown inside the
              modal and in <code>STOCK_BOOT_HARVEST_PROCEDURE.md §10</code>.
            </div>
            <ul style={{ marginTop: 8, fontSize: '0.78rem', color: 'var(--text)', paddingLeft: 18 }}>
              <li>Default <code>confirm:false</code> dry-run.</li>
              <li>Type miner serial + phrase <code>RESTORE TO STOCK</code> + slider.</li>
              <li>Critical IOC findings cannot be overridden from this UI.</li>
              <li>NAND backup written to <code>/data/restore-backup-&lt;timestamp&gt;/</code>.</li>
            </ul>
          </div>
          <button
            type="button"
            onClick={() => setRestoreOpen(true)}
            className="btn-danger"
            style={{
              padding: '12px 20px',
              borderRadius: 8,
              border: '1px solid var(--red, #EF4444)',
              background: 'rgba(239,68,68,0.08)',
              color: 'var(--red, #EF4444)',
              fontWeight: 800,
              fontSize: '0.85rem',
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              cursor: 'pointer',
              alignSelf: 'flex-start',
            }}
            data-testid="restore-to-stock-trigger"
          >
            Flash to stock firmware...
          </button>
        </div>
      </div>

      <RestoreToStockModal open={restoreOpen} onClose={() => setRestoreOpen(false)} />
    </div>
  );
}
