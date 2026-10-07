import { DCENT_FUND_CANONICAL_URL as FUND_URL } from '../../utils/links';
// DonationFeeCard - transparent donation visibility and controls.
//
// C6 (operator decision 2026-09-01): DCENT_OS ships with ZERO mandatory
// fee. This card is a NUDGE, not a toll booth: the default state is
// disabled at 0%, one-tap 1/2/3% presets let an operator opt in, and the
// mechanism stays fully visible and one-tap-off. The compact variant is
// a DISMISSIBLE donate nudge (About page); the full variant (Settings)
// is the always-available control surface.
//
// Copy truth-contract (load-bearing — enforced by donationNudge.honesty.test.ts):
//   • never claim the donation "pays for itself" or that the autotuner
//     offsets it (CLAIM_UNSAFE per COMPETITIVE_FEATURE_MATRIX);
//   • no countdown / scarcity pressure patterns;
//   • always state "no mandatory fee, ever";
//   • the fund link https://d-central.tech/fund/ is always present.

import React, { useEffect, useMemo, useState } from 'react';
import { api } from '../../api/client';
import type { DonationConfig, DonationInfoResponse } from '../../api/types';
import { useMinerStore } from '../../store/miner';

const DEFAULT_POOL_URL = 'stratum+tcp://pool.d-central.tech:3333';
const DEFAULT_WORKER = 'DungeonMaster';
const DEFAULT_PASSWORD = 'x';
const DEFAULT_FALLBACK_POOL_URL = 'stratum+tcp://stratum.braiins.com:3333';
const DEFAULT_FALLBACK_WORKER = 'DungeonMaster';
const DEFAULT_CYCLE_S = 3600;
const DEFAULT_PERCENT = 0;
const NUDGE_DISMISS_STORAGE_KEY = 'dcentos-donate-nudge-dismissed';

type DonationState = DonationConfig;

const DEFAULT_STATE: DonationState = {
  enabled: false,
  percent: DEFAULT_PERCENT,
  pool_url: DEFAULT_POOL_URL,
  worker: DEFAULT_WORKER,
  password: DEFAULT_PASSWORD,
  fallback_enabled: true,
  fallback_pool_url: DEFAULT_FALLBACK_POOL_URL,
  fallback_worker: DEFAULT_FALLBACK_WORKER,
  fallback_password: DEFAULT_PASSWORD,
  cycle_duration_s: DEFAULT_CYCLE_S,
};

function clampPercent(value: unknown): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? value : DEFAULT_PERCENT;
  return Math.max(0, Math.min(5, n));
}

function clampCycle(value: unknown): number {
  const n = typeof value === 'number' && Number.isFinite(value) ? Math.round(value) : DEFAULT_CYCLE_S;
  return Math.max(60, Math.min(86400, n));
}

function normalizeDonationConfig(value: Partial<DonationConfig> | undefined): DonationState {
  return {
    enabled: value?.enabled ?? DEFAULT_STATE.enabled,
    percent: clampPercent(value?.percent),
    pool_url: value?.pool_url || DEFAULT_STATE.pool_url,
    worker: value?.worker || DEFAULT_STATE.worker,
    password: value?.password || DEFAULT_STATE.password,
    fallback_enabled: value?.fallback_enabled ?? DEFAULT_STATE.fallback_enabled,
    fallback_pool_url: value?.fallback_pool_url || DEFAULT_STATE.fallback_pool_url,
    fallback_worker: value?.fallback_worker || DEFAULT_STATE.fallback_worker,
    fallback_password: value?.fallback_password || DEFAULT_STATE.fallback_password,
    cycle_duration_s: clampCycle(value?.cycle_duration_s),
  };
}

function formatPercent(value: number): string {
  return value.toFixed(value % 1 === 0 ? 0 : 1);
}

function formatCycleSplit(percent: number, cycleS: number): { donateS: number; userS: number } {
  const p = Math.max(0, Math.min(5, percent));
  const donateS = Math.round((p / 100) * cycleS);
  return { donateS, userS: cycleS - donateS };
}

function saveErrorMessage(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err || '');
  const status = err && typeof err === 'object' && 'status' in err
    ? Number((err as { status?: number }).status)
    : null;
  if (status === 404 || message.includes('/api/config/donation')) {
    return 'This firmware API build does not expose donation settings yet. The dashboard controls are ready, but the daemon must provide /api/config/donation before this can be saved from the UI.';
  }
  if (message.includes('Disallowed config keys') && message.includes('donation')) {
    return 'This firmware API build does not allow saving donation settings through the old config path. Update the daemon API to use /api/config/donation.';
  }
  return message || 'Failed to save donation settings';
}

function readNudgeDismissed(): boolean {
  try {
    if (typeof localStorage === 'undefined') return false;
    return localStorage.getItem(NUDGE_DISMISS_STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

function persistNudgeDismissed(): void {
  try {
    if (typeof localStorage === 'undefined') return;
    localStorage.setItem(NUDGE_DISMISS_STORAGE_KEY, '1');
  } catch {
    /* ignore quota / private-mode */
  }
}

export interface DonationFeeCardProps {
  variant?: 'full' | 'compact';
  onNavigateToSettings?: () => void;
}

export function DonationFeeCard({ variant = 'full', onNavigateToSettings }: DonationFeeCardProps) {
  const addAlert = useMinerStore(s => s.addAlert);
  const poolDonating = useMinerStore(s => s.status?.pool?.donating) === true;

  const [loaded, setLoaded] = useState(false);
  const [saving, setSaving] = useState(false);
  const [apiReportsDonation, setApiReportsDonation] = useState(false);
  const [serverState, setServerState] = useState<DonationState>(DEFAULT_STATE);
  const [state, setState] = useState<DonationState>(DEFAULT_STATE);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [nudgeDismissed, setNudgeDismissed] = useState(false);
  // W9.5: trust-but-verify. Public donation pool disclosure (URL,
  // payout address, block-explorer link). Fetched read-only and
  // independently of the donation-config above so the Verify link
  // stays available even when /api/config/donation is missing on
  // older daemons.
  const [donationInfo, setDonationInfo] = useState<DonationInfoResponse | null>(null);

  useEffect(() => {
    setNudgeDismissed(readNudgeDismissed());
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const donation = await api.getDonationConfig();
        const merged = normalizeDonationConfig(donation);
        if (!cancelled) {
          setApiReportsDonation(true);
          setServerState(merged);
          setState(merged);
          setLoaded(true);
        }
      } catch {
        try {
          const cfg = await api.getConfig();
          const hasDonation = !!cfg.donation && typeof cfg.donation === 'object';
          const merged = normalizeDonationConfig(cfg.donation);
          if (!cancelled) {
            setApiReportsDonation(hasDonation);
            setServerState(merged);
            setState(merged);
            setLoaded(true);
          }
        } catch {
          if (!cancelled) {
            setLoaded(true);
          }
        }
      }
    })();
    return () => { cancelled = true; };
  }, []);

  // W9.5: fetch the public donation pool disclosure once on mount.
  // Never blocks save/load of the donation config above. Falls
  // through to null on older daemons (route returns 404), and we
  // simply hide the Verify section in that case.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const info = await api.getDonationInfo();
        if (!cancelled) setDonationInfo(info);
      } catch {
        if (!cancelled) setDonationInfo(null);
      }
    })();
    return () => { cancelled = true; };
  }, []);

  const dirty = useMemo(() => {
    return !apiReportsDonation
      || state.enabled !== serverState.enabled
      || state.percent !== serverState.percent
      || state.cycle_duration_s !== serverState.cycle_duration_s
      || state.pool_url !== serverState.pool_url
      || state.worker !== serverState.worker
      || state.password !== serverState.password
      || state.fallback_enabled !== serverState.fallback_enabled
      || state.fallback_pool_url !== serverState.fallback_pool_url
      || state.fallback_worker !== serverState.fallback_worker
      || state.fallback_password !== serverState.fallback_password;
  }, [apiReportsDonation, state, serverState]);

  const { donateS, userS } = formatCycleSplit(state.percent, state.cycle_duration_s);
  const enabledLabel = state.enabled
    ? `${formatPercent(state.percent)}% donation enabled`
    : 'Donation off — 0% fee';

  async function persist(patch: Partial<DonationState>) {
    const nextDonation = normalizeDonationConfig({ ...state, ...patch });
    setSaving(true);
    try {
      const response = await api.updateDonationConfig(nextDonation);
      const saved = normalizeDonationConfig(response.config ?? nextDonation);
      setApiReportsDonation(true);
      setServerState(saved);
      setState(saved);
      addAlert('info', saved.enabled
        ? `Donation saved at ${formatPercent(saved.percent)}%. Thank you for supporting DCENT_OS.`
        : 'Donation disabled. No mandatory fee, ever.');
    } catch (err) {
      addAlert('warning', saveErrorMessage(err));
    } finally {
      setSaving(false);
    }
  }

  const handleSave = () => { void persist({}); };
  const handleDisable = () => { void persist({ enabled: false }); };
  const handlePreset = (percent: number) => { void persist({ enabled: true, percent }); };
  const handleToggleEnabled = () => {
    setState(current => ({
      ...current,
      enabled: !current.enabled,
      // Enabling at 0% would be a no-op; the smallest honest opt-in is 1%.
      percent: !current.enabled && current.percent <= 0 ? 1 : current.percent,
    }));
  };

  const dismissNudge = () => {
    persistNudgeDismissed();
    setNudgeDismissed(true);
  };

  if (variant === 'compact') {
    if (nudgeDismissed) {
      return (
        <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', lineHeight: 1.6 }}>
          DCENT_OS stays 0% fee — donation stays off. Change it anytime under{' '}
          {onNavigateToSettings ? (
            <button
              type="button"
              className="ds-btn ghost"
              onClick={onNavigateToSettings}
              style={{ padding: '2px 6px' }}
            >
              Settings
            </button>
          ) : 'Settings'}
          {' '}or{' '}
          <a
            href={FUND_URL}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--accent, #FAA500)' }}
          >
            fund development directly
          </a>.
        </div>
      );
    }

    return (
      <div style={{ fontSize: '0.85rem', color: 'var(--text, #E8E8E8)', lineHeight: 1.7, position: 'relative' }}>
        <button
          type="button"
          onClick={dismissNudge}
          aria-label="Dismiss donation nudge"
          title="Dismiss — the donation stays fully available in Settings"
          style={{
            position: 'absolute',
            top: -4,
            right: -4,
            background: 'none',
            border: 'none',
            color: 'var(--text-dim, #6B7280)',
            fontSize: '1rem',
            cursor: 'pointer',
            padding: '2px 6px',
            lineHeight: 1,
          }}
        >
          ×
        </button>
        <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
          <strong style={{ fontFamily: "var(--font-heading)", fontSize: '1.05rem', color: 'var(--accent, #FAA500)' }}>
            {loaded && apiReportsDonation ? enabledLabel : '0% fee — open source'}
          </strong>
          {poolDonating && (
            <span className="ds-chip ds-accent ds-live" aria-label="Currently mining on the donation pool">
              <span className="ds-dot" /> LIVE
            </span>
          )}
        </div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)', lineHeight: 1.6, marginBottom: 10 }}>
          DCENT_OS is 0% fee and open source — <strong>no mandatory fee, ever</strong>.
          If it helps your miner, you can fund development with an optional,
          always-visible time-sliced donation.
        </div>
        <div
          role="group"
          aria-label="One-tap donation presets"
          style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}
        >
          {[1, 2, 3].map(p => (
            <button
              key={p}
              type="button"
              className="ds-btn ghost"
              onClick={() => handlePreset(p)}
              disabled={saving || !loaded}
              style={{
                padding: '4px 12px',
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.78rem',
                cursor: saving ? 'wait' : 'pointer',
              }}
              aria-label={`Opt in to a ${p} percent donation`}
            >
              Donate {p}%
            </button>
          ))}
        </div>
        <div style={{ fontSize: '0.75rem', color: 'var(--text-dim)', marginBottom: 12, lineHeight: 1.6 }}>
          One tap on, one tap off, anytime. Or support the project directly:{' '}
          <a
            href={FUND_URL}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--accent, #FAA500)', textDecoration: 'underline' }}
          >
            d-central.tech/fund
          </a>
        </div>
        <DonationVerifyLink info={donationInfo} compact />
        {onNavigateToSettings && (
          <button
            type="button"
            className="ds-btn ghost"
            onClick={onNavigateToSettings}
            style={{ padding: '6px 0' }}
          >
            Manage in Settings -&gt;
          </button>
        )}
      </div>
    );
  }

  const ticks = [0, 1, 2, 3, 5];

  return (
    <div
      style={{
        background: 'var(--surface-glass-card, var(--card-bg, #242432))',
        borderRadius: 'var(--radius, 12px)',
        padding: 20,
        border: '1px solid var(--accent-border, rgba(250, 165, 0, 0.18))',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div style={{
        position: 'absolute',
        top: 0,
        left: 0,
        right: 0,
        height: 2,
        background: 'linear-gradient(90deg, transparent, var(--accent, #FAA500), var(--accent-deep, #FA6700), transparent)',
        opacity: 0.7,
        pointerEvents: 'none',
      }} />

      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 12,
        marginBottom: 14,
        flexWrap: 'wrap',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
          <div style={{
            fontFamily: "var(--font-heading)",
            fontWeight: 700,
            fontSize: '1.3rem',
            color: 'var(--text, #E8E8E8)',
          }}>
            Donation
          </div>
          {poolDonating && (
            <span className="ds-chip ds-accent ds-live" aria-label="Currently mining on the donation pool">
              <span className="ds-dot" /> LIVE
            </span>
          )}
        </div>
        <div className="ds-chip ds-info" style={{ fontSize: '0.62rem' }}>
          0% fee · opt in
        </div>
      </div>

      <div style={{
        fontSize: '0.82rem',
        color: 'var(--fg-secondary, var(--text-dim, #9CA3AF))',
        lineHeight: 1.6,
        marginBottom: 18,
      }}>
        DCENT_OS is 0% fee and open source — <strong>no mandatory fee, ever</strong>.
        The donation below is optional, visible pool switching that funds firmware
        development: 1% helps, you can go up to 5%, and one tap turns it off.
      </div>

      {!apiReportsDonation && loaded && (
        <div style={{
          marginBottom: 14,
          padding: '10px 12px',
          background: 'rgba(245, 158, 11, 0.08)',
          border: '1px solid rgba(245, 158, 11, 0.25)',
          borderRadius: 8,
          fontSize: '0.76rem',
          color: 'var(--amber, #F59E0B)',
          lineHeight: 1.5,
        }}>
          This API response has not reported saved donation settings yet. The
          firmware default is 0% (off); save once to record your choice on
          firmware builds that expose the donation config key.
        </div>
      )}

      <div
        role="group"
        aria-label="One-tap donation presets"
        style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}
      >
        {[1, 2, 3].map(p => (
          <button
            key={p}
            type="button"
            className={`ds-btn${state.enabled && Math.abs(state.percent - p) < 0.05 ? ' primary' : ' ghost'}`}
            onClick={() => handlePreset(p)}
            disabled={saving || !loaded}
            style={{ padding: '6px 16px', fontFamily: "'JetBrains Mono', monospace" }}
            aria-label={`Opt in to a ${p} percent donation`}
          >
            {p}%
          </button>
        ))}
        {state.enabled && (
          <button
            type="button"
            className="ds-btn ghost"
            onClick={handleDisable}
            disabled={saving || !loaded}
            style={{ padding: '6px 16px' }}
          >
            Turn off
          </button>
        )}
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'minmax(0, 1fr) auto',
        gap: 20,
        alignItems: 'center',
        marginBottom: 6,
      }}>
        <div>
          <label
            htmlFor="donation-percent-slider"
            style={{
              display: 'block',
              fontSize: '0.7rem',
              color: 'var(--text-dim, #9CA3AF)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              fontWeight: 600,
              marginBottom: 8,
            }}
          >
            Donation percent
          </label>
          <input
            id="donation-percent-slider"
            type="range"
            min={0}
            max={5}
            step={0.5}
            value={state.percent}
            onChange={e => setState(s => ({ ...s, percent: clampPercent(Number(e.target.value)) }))}
            disabled={!state.enabled}
            aria-valuemin={0}
            aria-valuemax={5}
            aria-valuenow={state.percent}
            aria-valuetext={`${formatPercent(state.percent)} percent`}
            style={{
              width: '100%',
              accentColor: 'var(--accent, #FAA500)',
              opacity: state.enabled ? 1 : 0.55,
              cursor: state.enabled ? 'pointer' : 'not-allowed',
            }}
          />
          <div
            role="group"
            aria-label="Donation percentage quick presets"
            style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6, padding: '0 4px' }}
          >
            {ticks.map(t => (
              <button
                key={t}
                type="button"
                onClick={() => state.enabled && setState(s => ({ ...s, percent: t }))}
                disabled={!state.enabled}
                style={{
                  background: 'none',
                  border: 'none',
                  padding: '2px 4px',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.7rem',
                  color: state.enabled && t === state.percent ? 'var(--accent, #FAA500)' : 'var(--text-dim, #6B7280)',
                  fontWeight: state.enabled && t === state.percent ? 700 : 500,
                  cursor: state.enabled ? 'pointer' : 'default',
                }}
                aria-label={`Set donation to ${t} percent`}
              >
                {t}%
              </button>
            ))}
          </div>
        </div>

        <div style={{ textAlign: 'right', minWidth: 92 }}>
          <div style={{
            fontFamily: "var(--font-heading)",
            fontWeight: 700,
            fontSize: '3.2rem',
            lineHeight: 1,
            color: state.enabled ? 'var(--accent, #FAA500)' : 'var(--text-dim, #6B7280)',
            filter: state.enabled ? 'drop-shadow(0 0 12px rgba(250,165,0,0.35))' : 'none',
            transition: 'color 0.2s, filter 0.2s',
          }}>
            {formatPercent(state.percent)}
            <span style={{ fontSize: '1.4rem', marginLeft: 2, opacity: 0.85 }}>%</span>
          </div>
        </div>
      </div>

      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: 14,
        padding: '14px 0',
        borderTop: '1px solid var(--border, rgba(255,255,255,0.06))',
        borderBottom: '1px solid var(--border, rgba(255,255,255,0.06))',
        marginTop: 10,
      }}>
        <div>
          <div style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text, #E8E8E8)' }}>
            {state.enabled ? 'Donation enabled' : 'Donation disabled'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-dim, #9CA3AF)', marginTop: 2 }}>
            {state.enabled
              ? 'Briefly mines on the donation pool each cycle, then returns to your pool.'
              : 'Your miner stays on your pool for the full cycle. No mandatory fee, ever.'}
          </div>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={state.enabled}
          aria-label={state.enabled ? 'Disable donation' : 'Enable donation'}
          onClick={handleToggleEnabled}
          className={`ds-toggle${state.enabled ? ' on' : ''}`}
        >
          <span className="ds-toggle-knob" />
        </button>
      </div>

      <div style={{
        marginTop: 14,
        padding: '12px 14px',
        background: 'rgba(10,10,15,0.5)',
        border: '1px solid var(--border, rgba(255,255,255,0.06))',
        borderRadius: 10,
        fontSize: '0.82rem',
        color: 'var(--fg-secondary, var(--text-dim, #9CA3AF))',
        lineHeight: 1.6,
      }}>
        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: '0.78rem',
          color: 'var(--text, #E8E8E8)',
          marginBottom: 4,
        }}>
          <span style={{ color: 'var(--accent, #FAA500)' }}>{donateS}s</span> donation
          <span style={{ color: 'var(--text-dim)' }}> / </span>
          <span style={{ color: 'var(--text, #E8E8E8)' }}>{userS}s</span> your pool
          <span style={{ color: 'var(--text-dim)' }}> / cycle {state.cycle_duration_s}s</span>
        </div>
        At {formatPercent(state.percent)}%, the miner spends {donateS} seconds
        every {Math.round(state.cycle_duration_s / 60)}-minute cycle on the
        donation pool. The remaining {userS} seconds mine to your pool.
        Prefer to support the project without touching hashrate?{' '}
        <a
          href={FUND_URL}
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: 'var(--accent, #FAA500)', textDecoration: 'underline' }}
        >
          d-central.tech/fund
        </a>
      </div>

      {/* W9.5: trust-but-verify. Public payout address + block-explorer link. */}
      <DonationVerifyLink info={donationInfo} />

      <div style={{ marginTop: 18, display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <button
          type="button"
          className="ds-btn primary"
          onClick={handleSave}
          disabled={saving || !dirty || !loaded}
        >
          {saving ? 'Saving...' : dirty ? 'Save donation settings' : 'Saved'}
        </button>
        {state.enabled && (
          <button
            type="button"
            className="ds-btn ghost"
            onClick={handleDisable}
            disabled={saving || !loaded}
          >
            Turn off
          </button>
        )}
        {!loaded && (
          <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>
            Loading current config...
          </span>
        )}
      </div>

      <div style={{
        marginTop: 14,
        paddingTop: 12,
        borderTop: '1px solid var(--border, rgba(255,255,255,0.06))',
        fontSize: '0.72rem',
        color: 'var(--text-dim, #6B7280)',
        fontFamily: "'JetBrains Mono', monospace",
        display: 'flex',
        flexWrap: 'wrap',
        gap: 6,
        alignItems: 'center',
      }}>
        <span>Pool: {state.pool_url.replace(/^stratum\+tcp:\/\//, '')}</span>
        <span>/</span>
        {state.fallback_enabled && (
          <>
            <span>Backup: {state.fallback_pool_url.replace(/^stratum\+tcp:\/\//, '')}</span>
            <span>/</span>
          </>
        )}
        <span>Worker: {state.worker}</span>
        <span>/</span>
        <button
          type="button"
          onClick={() => setShowAdvanced(v => !v)}
          style={{
            background: 'none',
            border: 'none',
            padding: 0,
            color: 'var(--accent, #FAA500)',
            fontFamily: 'inherit',
            fontSize: 'inherit',
            cursor: 'pointer',
            textDecoration: 'underline',
          }}
          aria-expanded={showAdvanced}
        >
          Advanced: {showAdvanced ? 'hide cycle' : 'change cycle'}
        </button>
      </div>

      {showAdvanced && (
        <div style={{
          marginTop: 12,
          padding: '12px 14px',
          background: 'rgba(10,10,15,0.5)',
          border: '1px solid var(--border, rgba(255,255,255,0.08))',
          borderRadius: 8,
        }}>
          <label
            htmlFor="donation-cycle-input"
            style={{
              display: 'block',
              fontSize: '0.7rem',
              color: 'var(--text-dim, #9CA3AF)',
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              fontWeight: 600,
              marginBottom: 6,
            }}
          >
            Cycle duration (seconds, 60-86400)
          </label>
          <input
            id="donation-cycle-input"
            type="number"
            min={60}
            max={86400}
            step={60}
            value={state.cycle_duration_s}
            onChange={e => setState(s => ({ ...s, cycle_duration_s: clampCycle(Number(e.target.value)) }))}
            className="ds-input"
            style={{ maxWidth: 180 }}
          />
          <div style={{ marginTop: 6, fontSize: '0.72rem', color: 'var(--text-dim, #6B7280)' }}>
            Default is 3600 seconds. Longer cycles mean fewer pool switches.
          </div>
        </div>
      )}
    </div>
  );
}

/**
 * W9.5 — DonationVerifyLink
 *
 * Renders a "Verify on-chain" disclosure block below the donation
 * slider/toggle. Shows the donation pool's payout Bitcoin address and
 * a block-explorer link to its on-chain payout history. The whole
 * point: trust-but-verify. The operator can paste the address into
 * any block explorer and audit that the donation slice actually lands
 * where the firmware claims.
 *
 * Hidden when `info` is null (older daemons without /api/donation/info,
 * or transient fetch failure). The donation slider above keeps working
 * either way; this component is purely additive disclosure.
 */
function DonationVerifyLink({
  info,
  compact = false,
}: {
  info: DonationInfoResponse | null;
  compact?: boolean;
}) {
  if (!info || !info.payout_address || !info.explorer_url) return null;

  // Truncate the address for display: first 7 + last 6 chars with an
  // ellipsis. The full address is in the link target so the operator
  // can always copy the canonical value from the URL.
  const addr = info.payout_address;
  const displayAddr =
    addr.length > 16 ? `${addr.slice(0, 7)}...${addr.slice(-6)}` : addr;

  if (compact) {
    return (
      <div
        style={{
          marginBottom: 10,
          padding: '8px 10px',
          background: 'rgba(10,10,15,0.5)',
          border: '1px solid var(--border, rgba(255,255,255,0.06))',
          borderRadius: 8,
          fontSize: '0.72rem',
          color: 'var(--text-dim, #9CA3AF)',
          lineHeight: 1.55,
          fontFamily: "'JetBrains Mono', monospace",
        }}
      >
        <div style={{ marginBottom: 4 }}>
          Donations go to{' '}
          <a
            href={info.explorer_url}
            target="_blank"
            rel="noopener noreferrer"
            style={{ color: 'var(--accent, #FAA500)' }}
            aria-label={`Donation payout address ${addr} on ${info.explorer_name}`}
          >
            {displayAddr}
          </a>
        </div>
        <a
          href={info.explorer_url}
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: 'var(--accent, #FAA500)', textDecoration: 'underline' }}
        >
          {info.verify_label || 'View on-chain payout history'} -&gt;
        </a>
      </div>
    );
  }

  return (
    <div
      style={{
        marginTop: 14,
        padding: '12px 14px',
        background: 'rgba(10,10,15,0.5)',
        border: '1px solid var(--border, rgba(255,255,255,0.08))',
        borderRadius: 10,
        fontSize: '0.8rem',
        color: 'var(--text, #E8E8E8)',
        lineHeight: 1.6,
      }}
    >
      <div
        style={{
          fontSize: '0.7rem',
          color: 'var(--text-dim, #9CA3AF)',
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
          fontWeight: 600,
          marginBottom: 6,
        }}
      >
        Verify on-chain (trust-but-verify)
      </div>
      <div style={{ marginBottom: 6 }}>
        Donations go to{' '}
        <a
          href={info.explorer_url}
          target="_blank"
          rel="noopener noreferrer"
          style={{
            color: 'var(--accent, #FAA500)',
            fontFamily: "'JetBrains Mono', monospace",
          }}
          aria-label={`Donation payout address ${addr} on ${info.explorer_name}`}
        >
          {displayAddr}
        </a>{' '}
        <span style={{ color: 'var(--text-dim, #9CA3AF)', fontSize: '0.75rem' }}>
          (on {info.explorer_name})
        </span>
      </div>
      <a
        href={info.explorer_url}
        target="_blank"
        rel="noopener noreferrer"
        style={{
          color: 'var(--accent, #FAA500)',
          textDecoration: 'underline',
          fontSize: '0.78rem',
        }}
      >
        {info.verify_label || 'View on-chain payout history'} -&gt;
      </a>
      <div
        style={{
          marginTop: 6,
          fontSize: '0.72rem',
          color: 'var(--text-dim, #6B7280)',
          lineHeight: 1.5,
        }}
      >
        {info.disclosure ||
          'Donation slice flows to the address above. Verify on the block explorer.'}
      </div>
    </div>
  );
}

export default DonationFeeCard;
