import React, { useEffect, useState } from 'react';
import { api } from '../../api/client';
import type { DiagnosticsResponse } from '../../api/types';

export function BuildPanel() {
  const [data, setData] = useState<DiagnosticsResponse | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    api.getDiagnostics().then(value => { if (active) setData(value); })
      .catch(() => { if (active) setFailed(true); });
    return () => { active = false; };
  }, []);
  const rows = [
    ['Board target', data?.board_target], ['Image version', data?.image_version],
    ['Daemon version', data?.daemon_version], ['Git revision', data?.git_sha],
    ['Release channel', data?.channel], ['Drop', data?.drop],
    ['Active slot', data?.active_slot], ['Runtime signature', data?.signature_state],
  ];
  return <section className="section" aria-label="Build">
    <h3 className="section-title">Build</h3>
    <dl style={{ display: 'grid', gridTemplateColumns: 'minmax(100px, 1fr) minmax(0, 2fr)', gap: 8 }}>
      {rows.map(([label, value]) => <React.Fragment key={label}>
        <dt>{label}</dt><dd style={{ margin: 0, overflowWrap: 'anywhere' }}>{value || 'Unavailable'}</dd>
      </React.Fragment>)}
    </dl>
    {failed && <p role="status">Build diagnostics are unavailable while the miner is disconnected.</p>}
    {data?.signature_detail && <p>{data.signature_detail}</p>}
    {data?.warnings.map(warning => <p key={warning}>{warning}</p>)}
    {data?.reset_status && <p>Settings reset: {data.reset_status.phase.replace(/_/g, ' ')}.
      {data.reset_status.error && <> {data.reset_status.error}</>}</p>}
    {data?.last_panic && <p>Last crash: {data.last_panic.location || 'location unavailable'}. Include a support bundle when reporting it.</p>}
  </section>;
}
