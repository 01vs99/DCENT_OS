import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from '../../api/client';
import { useMinerStore } from '../../store/miner';
import { useTranslation } from '../../i18n/i18n';
import type {
  AutotunerChipHealthResponse,
  AutotunerChipHealthStatus,
  ChipHealthSnapshotResponse,
  ChipMapCell,
  DiagnosticReportMetadata,
} from '../../api/types';
import {
  CHIP_HEALTH_COLORS,
  chipHealthToneFromAutotuner,
  chipHealthToneFromDiagnostics,
  formatHealthPercent,
  normalizeHealthScore,
  type ChipHealthTone,
} from '../common/ChipHealthLegend';
import { ChipHeatMap } from './ChipHeatMap';

/**
 * Weak-chip repair advisory (a5 Design 1 — the superiority view no competitor
 * ships). READ-ONLY: every number comes from existing snapshots
 * (`GET /api/chips`, `GET /api/autotuner/chip-health`, persisted
 * `/api/diagnostics/chip-health` report metadata). No new daemon endpoints.
 *
 * HONESTY CONTRACT (extends ChipHeatMap's):
 *  - No fabricated per-chip temperatures. The temp ranking mode exists ONLY
 *    while some `die_temp_c` is actually on the wire; otherwise the mode is
 *    disabled with an explanatory note and ranking falls back to
 *    nonce/CRC/grade evidence (crate-level "honest degrade" rule).
 *  - The advisory is advisory: rows say "inspect / replace candidate" or
 *    "derate" — a chip is never declared dead without an offline
 *    chip-health test corroborating it.
 *  - The only write path is the EXISTING `/api/debug/chip/frequency`
 *    override exposed by PerChipOverridePanel on the Tuning page — this
 *    panel links there (navigate + alert); it performs no writes itself.
 *  - The nonce/temperature math is a faithful TypeScript port of
 *    `dcentrald-chip-analysis` (compute_mean_std / compute_hot_zscore /
 *    compute_slot_avg_nonce / compute_nonce_deficit) so the dashboard ranks
 *    chips with the same numbers the daemon-side analysis produces.
 */

export type WeakChipEvidenceMode = 'grade' | 'temp' | 'nonce-deficit';
export type WeakChipAction = 'inspect' | 'derate' | 'watch';
export type WeakChipSource = 'diagnostics' | 'autotuner';

/** Rows shown in the ranked table (top-N by the selected evidence mode). */
export const WEAK_CHIP_TABLE_LIMIT = 8;
/** Advisory list length (repair order — the top actionable suspects). */
export const WEAK_CHIP_ADVISORY_LIMIT = 3;
/** Session trend ring length per chip (one sample per refresh). */
const TREND_RING_MAX = 12;
/** Refresh cadence — matches ChipHeatMap's lightweight 10s poll. */
const REFRESH_MS = 10_000;

// ── dcentrald-chip-analysis port (byte-faithful over its input domain) ─────

const ZSCORE_UNIFORM_STD_THRESHOLD = 0.5;
const ZSCORE_UNIFORM_CAP = 3.0;

/** Population mean/std (divide by n). Mirrors compute_mean_std. */
export function computeMeanStd(values: number[]): { mean: number; std: number } {
  if (values.length === 0) return { mean: 0, std: 0 };
  const n = values.length;
  const mean = values.reduce((s, v) => s + v, 0) / n;
  if (n === 1) return { mean, std: 0 };
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / n;
  return { mean, std: Math.sqrt(variance) };
}

/** Hot-spot-only z-score. Mirrors compute_hot_zscore (uniform-std cap 3.0). */
export function computeHotZscore(temp: number, mean: number, std: number): number {
  if (!Number.isFinite(mean) || !Number.isFinite(std) || std < 0) {
    return ZSCORE_UNIFORM_CAP;
  }
  const deviation = temp - mean;
  if (deviation <= 0) return 0;
  if (std < ZSCORE_UNIFORM_STD_THRESHOLD) return Math.min(deviation, ZSCORE_UNIFORM_CAP);
  return deviation / std;
}

/** Average valid-nonce count across the chips of one chain. Mirrors compute_slot_avg_nonce. */
export function slotAverageNonce(nonces: number[]): number {
  if (nonces.length === 0) return 0;
  return nonces.reduce((s, n) => s + Math.max(0, n), 0) / nonces.length;
}

/** Nonce deficit % below the chain average (0..100). Mirrors compute_nonce_deficit. */
export function computeNonceDeficit(chipNonce: number, slotAvg: number): number {
  if (!Number.isFinite(slotAvg)) return 100;
  if (slotAvg <= 0) return 0;
  const chip = Math.max(0, chipNonce);
  if (chip >= slotAvg) return 0;
  const deficit = ((slotAvg - chip) / slotAvg) * 100;
  return Math.min(100, Math.max(0, deficit));
}

// ── Row projection ──────────────────────────────────────────────────────────

export interface WeakChipRow {
  chainId: number;
  chipIndex: number;
  grade: string;
  present: boolean;
  healthTone: ChipHealthTone;
  healthScoreNormalized: number | null;
  freqMhz: number;
  nonceCount: number;
  /** % below the same-chain average nonce (0 = at-or-above average). */
  nonceDeficitPct: number;
  crcErrors: number;
  tempC: number | null;
  /** Cross-chain hot z-score; null when per-chip temps are not on the wire. */
  tempZ: number | null;
  /** Evidence actually used for this row (never fabricated). */
  sources: WeakChipSource[];
  /** Combined-evidence weakness (deterministic; higher = weaker). */
  weakScore: number;
  action: WeakChipAction;
}

function gradeWeight(grade: string): number {
  const g = String(grade ?? '').toUpperCase();
  if (g === 'D' || g === 'F') return 3;
  if (g === 'C') return 1.5;
  return 0;
}

// Deterministic suggested action. "inspect" (not responding) outranks
// "derate" (weak but alive); healthy chips are only "watch". A chip is
// never marked dead here — "inspect / replace candidate" phrasing only.
function suggestAction(row: Omit<WeakChipRow, 'action' | 'weakScore'>): WeakChipAction {
  if (!row.present) return 'inspect';
  const weakGrade = ['C', 'D', 'F'].includes(String(row.grade ?? '').toUpperCase());
  if (weakGrade || row.nonceDeficitPct >= 40 || row.crcErrors >= 5 || row.healthTone === 'failing') {
    return 'derate';
  }
  return 'watch';
}

/**
 * Project a real `/api/chips` snapshot (+ optional autotuner health) into
 * ranked weak-chip rows. Every field traces to a wire value; tempZ stays
 * null unless at least one chain publishes die temps for the chip position.
 */
export function buildWeakChipRows(
  snapshot: ChipHealthSnapshotResponse,
  autotuner: AutotunerChipHealthResponse | null,
): WeakChipRow[] {
  const autotunerByChip = new Map<string, AutotunerChipHealthStatus>();
  for (const chip of autotuner?.chips ?? []) {
    autotunerByChip.set(`${chip.chain_id}:${chip.chip_index}`, chip);
  }

  // Cross-chain ("cross-slot") temperature population per chip position —
  // only from chains that actually publish die temps.
  const crossSlotTemps = new Map<number, number[]>();
  for (const chain of snapshot.chains ?? []) {
    for (const cell of chain.chipmap?.cells ?? []) {
      if (cell.die_temp_c != null && Number.isFinite(cell.die_temp_c)) {
        const list = crossSlotTemps.get(cell.index) ?? [];
        list.push(cell.die_temp_c);
        crossSlotTemps.set(cell.index, list);
      }
    }
  }

  const rows: WeakChipRow[] = [];
  for (const chain of snapshot.chains ?? []) {
    const cells: ChipMapCell[] = chain.chipmap?.cells ?? [];
    const slotAvg = slotAverageNonce(cells.map(c => c.nonce_count));
    for (const cell of cells) {
      const present = cell.health_score > 0;
      const autotunerChip = autotunerByChip.get(`${chain.chain_id}:${cell.index}`) ?? null;
      const autotunerTone = autotunerChip
        ? chipHealthToneFromAutotuner({
          status: autotunerChip.status,
          healthScore: autotunerChip.health_score,
        })
        : null;
      const diagnosticsTone = chipHealthToneFromDiagnostics({
        present,
        color: cell.color,
        grade: cell.grade,
        healthScore: cell.health_score,
      });
      const useAutotuner = autotunerChip !== null && autotunerTone !== null && autotunerTone !== 'no-data';
      const healthTone: ChipHealthTone = useAutotuner ? autotunerTone : diagnosticsTone;
      const healthScoreNormalized = normalizeHealthScore(
        useAutotuner ? autotunerChip?.health_score : cell.health_score,
      );

      const nonceDeficitPct = computeNonceDeficit(cell.nonce_count, slotAvg);
      const tempSamples = crossSlotTemps.get(cell.index) ?? [];
      const tempStats = tempSamples.length > 0 ? computeMeanStd(tempSamples) : null;
      const tempZ = cell.die_temp_c != null && tempStats
        ? computeHotZscore(cell.die_temp_c, tempStats.mean, tempStats.std)
        : null;

      // Combined evidence: grade (0..3) + nonce deficit (0..2) + CRC (0..1)
      // + hot z (0..1) + inverted health (0..1.5). All axes are real wire
      // values; absent axes contribute 0 (never an invented penalty).
      const weakScore =
        gradeWeight(cell.grade) +
        (nonceDeficitPct / 100) * 2 +
        Math.min(cell.crc_errors, 20) / 20 +
        Math.min(tempZ ?? 0, 3) / 3 +
        (healthScoreNormalized != null ? (1 - healthScoreNormalized) * 1.5 : 0);

      const partial = {
        chainId: chain.chain_id,
        chipIndex: cell.index,
        grade: String(cell.grade ?? ''),
        present,
        healthTone,
        healthScoreNormalized,
        freqMhz: cell.frequency_mhz,
        nonceCount: cell.nonce_count,
        nonceDeficitPct,
        crcErrors: cell.crc_errors,
        tempC: cell.die_temp_c ?? null,
        tempZ,
        sources: (useAutotuner ? ['diagnostics', 'autotuner'] : ['diagnostics']) as WeakChipSource[],
      };
      rows.push({ ...partial, weakScore, action: suggestAction(partial) });
    }
  }
  return rows;
}

/** Sort rows by the selected evidence mode (stable, deterministic ties). */
export function sortWeakChipRows(rows: WeakChipRow[], mode: WeakChipEvidenceMode): WeakChipRow[] {
  const tieBreak = (a: WeakChipRow, b: WeakChipRow) =>
    a.chainId - b.chainId || a.chipIndex - b.chipIndex;
  const copy = rows.slice();
  if (mode === 'temp') {
    copy.sort((a, b) => ((b.tempZ ?? -Infinity) - (a.tempZ ?? -Infinity)) || tieBreak(a, b));
  } else if (mode === 'nonce-deficit') {
    copy.sort((a, b) => (b.nonceDeficitPct - a.nonceDeficitPct) || (b.weakScore - a.weakScore) || tieBreak(a, b));
  } else {
    copy.sort((a, b) => (b.weakScore - a.weakScore) || tieBreak(a, b));
  }
  return copy;
}

// ── Trend sparkline (session ring — honest, never fabricated history) ──────

function TrendSparkline({ samples }: { samples: number[] }) {
  const w = 64;
  const h = 16;
  const pad = 2;
  const min = Math.min(...samples);
  const max = Math.max(...samples);
  const span = max - min || 1;
  const points = samples
    .map((v, i) => {
      const x = pad + (i / (samples.length - 1)) * (w - pad * 2);
      const y = h - pad - ((v - min) / span) * (h - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');
  const latest = samples[samples.length - 1];
  const worsening = latest > samples[0];
  return (
    <svg
      data-testid="weak-chip-trend"
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      role="img"
      aria-label={`Nonce deficit trend over ${samples.length} session samples, latest ${Math.round(latest)} percent`}
    >
      <polyline
        points={points}
        fill="none"
        stroke={worsening ? 'var(--red)' : 'var(--green)'}
        strokeWidth={1.5}
        strokeLinecap="round"
      />
    </svg>
  );
}

// ── Panel ───────────────────────────────────────────────────────────────────

// Small provenance pill (inline-styled like ChipHeatMap's cells — no new CSS).
function SourcePill({ label, title }: { label: string; title?: string }) {
  return (
    <span
      title={title}
      style={{
        fontSize: '0.62rem', padding: '2px 6px', borderRadius: 4,
        background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)',
        color: 'var(--text-dim)', whiteSpace: 'nowrap',
      }}
    >
      {label}
    </span>
  );
}


type PanelState = 'loading' | 'ready' | 'unavailable';

export function WeakChipAdvisoryPanel() {
  const { t } = useTranslation();
  const addAlert = useMinerStore(s => s.addAlert);
  const setCurrentPage = useMinerStore(s => s.setCurrentPage);
  const storeChains = useMinerStore(s => s.status?.chains ?? []);

  const [panelState, setPanelState] = useState<PanelState>('loading');
  const [snapshot, setSnapshot] = useState<ChipHealthSnapshotResponse | null>(null);
  const [autotuner, setAutotuner] = useState<AutotunerChipHealthResponse | null>(null);
  const [offlineReport, setOfflineReport] = useState<DiagnosticReportMetadata | null>(null);
  const [mode, setMode] = useState<WeakChipEvidenceMode>('grade');
  const [refreshing, setRefreshing] = useState(false);

  // Session trend ring: chain:chip -> recent nonce-deficit samples gathered
  // by this panel's own refreshes. NOT persisted history — the first sample
  // appears after the first refresh, and <2 samples render "collecting".
  const trendRef = useRef<Map<string, number[]>>(new Map());
  const mountedRef = useRef(true);

  const load = useCallback(async () => {
    setRefreshing(true);
    try {
      const [chips, chipHealth, recentReports] = await Promise.all([
        api.getChips(),
        api.getAutotunerChipHealth().catch(() => null),
        api.getRecentDiagnosticReports(8).catch(() => null),
      ]);
      if (!mountedRef.current) return;
      const chains = chips?.chains ?? [];
      const anyCells = chains.some(c => (c.chipmap?.cells ?? []).length > 0);
      if (!chips || !anyCells) {
        setSnapshot(null);
        setPanelState('unavailable');
        return;
      }
      // Append one honest trend sample per chip per refresh.
      const nextTrend = trendRef.current;
      for (const row of buildWeakChipRows(chips, chipHealth)) {
        const key = `${row.chainId}:${row.chipIndex}`;
        const list = nextTrend.get(key) ?? [];
        list.push(row.nonceDeficitPct);
        if (list.length > TREND_RING_MAX) list.shift();
        nextTrend.set(key, list);
      }
      setSnapshot(chips);
      setAutotuner(chipHealth);
      const offline = (recentReports?.reports ?? []).find(r => r.test_type === 'chip_health_snapshot') ?? null;
      setOfflineReport(offline);
      setPanelState('ready');
    } catch {
      if (!mountedRef.current) return;
      setSnapshot(null);
      setPanelState('unavailable');
    } finally {
      if (mountedRef.current) setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    void load();
    const timer = window.setInterval(() => void load(), REFRESH_MS);
    return () => {
      mountedRef.current = false;
      window.clearInterval(timer);
    };
  }, [load]);

  const rows = useMemo(
    () => (snapshot ? buildWeakChipRows(snapshot, autotuner) : []),
    [snapshot, autotuner],
  );

  const anyPerChipTemps = useMemo(
    () => rows.some(r => r.tempC != null),
    [rows],
  );

  // Honest degrade: if temps disappear (or never arrive), the temp mode
  // cannot rank anything — fall back to grade mode and disable the button.
  useEffect(() => {
    if (mode === 'temp' && panelState === 'ready' && !anyPerChipTemps) {
      setMode('grade');
    }
  }, [mode, panelState, anyPerChipTemps]);

  const ranked = useMemo(
    () => sortWeakChipRows(rows, mode).slice(0, WEAK_CHIP_TABLE_LIMIT),
    [rows, mode],
  );
  const advisory = useMemo(
    () => ranked.filter(r => r.action !== 'watch').slice(0, WEAK_CHIP_ADVISORY_LIMIT),
    [ranked],
  );

  // Per-chain grid reuses the production ChipHeatMap verbatim (it fetches
  // its own /api/chips data). Match snapshot chains onto live store chains
  // by id — ChipHeatMap is indexed by store position.
  const gridChains = useMemo(() => {
    const ids = new Set((snapshot?.chains ?? []).map(c => c.chain_id));
    return storeChains
      .map((chain, index) => ({ index, id: chain.id }))
      .filter(({ id }) => ids.has(id));
  }, [snapshot, storeChains]);

  const derateCta = useCallback((row: WeakChipRow) => {
    addAlert(
      'info',
      `Weak-chip advisory: chain ${row.chainId} chip ${row.chipIndex} (grade ${row.grade || 'n/a'}). ` +
      'Opening the Tuning page — use "Per-chip override" to derate it via the daemon\'s real per-chip frequency endpoint.',
    );
    setCurrentPage('tuning');
  }, [addAlert, setCurrentPage]);

  const sourceLabel = (src: WeakChipSource) =>
    src === 'autotuner' ? t('weakchip.source.autotuner', 'autotuner estimate') : t('weakchip.source.diagnostics', 'diagnostics snapshot');

  const actionLabel = (action: WeakChipAction) =>
    action === 'inspect'
      ? t('weakchip.action.inspect', 'Inspect / replace candidate')
      : action === 'derate'
        ? t('weakchip.action.derate', 'Derate (per-chip override)')
        : t('weakchip.action.watch', 'Watch');

  // ── Honest states ────────────────────────────────────────────────────────
  if (panelState === 'loading') {
    return (
      <section className="section weak-chip-advisory" aria-busy="true">
        <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text)', margin: 0 }}>{t('weakchip.title', 'Weak-Chip Advisory')}</h3>
        <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontStyle: 'italic' }}>
          Loading per-chip evidence…
        </div>
      </section>
    );
  }

  if (panelState === 'unavailable') {
    return (
      <section className="section weak-chip-advisory" data-testid="weak-chip-unavailable">
        <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text)', margin: 0 }}>{t('weakchip.title', 'Weak-Chip Advisory')}</h3>
        <div
          role="status"
          style={{
            fontSize: '0.72rem', lineHeight: 1.45, color: 'var(--text-dim)',
            padding: '10px 12px', background: 'var(--card-bg)',
            borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)',
          }}
        >
          <div style={{ fontWeight: 700, color: 'var(--text)', marginBottom: 4 }}>
            {t('weakchip.telemetryUnavailableTitle', 'Per-chip telemetry unavailable')}
          </div>
          {t('weakchip.telemetryUnavailable', '/api/chips did not return per-chip data. DCENT_OS only ranks real per-chip evidence — no weak-chip list is estimated.')}
          <div style={{ marginTop: 8 }}>
            <button type="button" className="btn btn-secondary" onClick={() => void load()}>
              {t('weakchip.retry', 'Retry')}
            </button>
          </div>
        </div>
      </section>
    );
  }

  // ── Ready ────────────────────────────────────────────────────────────────
  const modeMeta: { id: WeakChipEvidenceMode; label: string; aria: string; disabled: boolean }[] = [
    { id: 'grade', label: t('weakchip.mode.grade', 'Health grade'), aria: 'Rank weakest chips by combined health-grade evidence', disabled: false },
    { id: 'temp', label: t('weakchip.mode.temp', 'Temperature'), aria: 'Rank weakest chips by per-chip temperature z-score', disabled: !anyPerChipTemps },
    { id: 'nonce-deficit', label: t('weakchip.mode.nonce', 'Nonce deficit'), aria: 'Rank weakest chips by nonce deficit versus chain average', disabled: false },
  ];

  return (
    <section className="section weak-chip-advisory" data-testid="weak-chip-advisory">
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text)', margin: 0 }}>{t('weakchip.title', 'Weak-Chip Advisory')}</h3>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
          {autotuner && (
            <SourcePill label={`autotuner: ${autotuner.source}${autotuner.stale ? ` (stale ${Math.round(autotuner.age_s)}s)` : ''}`} title="/api/autotuner/chip-health" />
          )}
          {offlineReport && (
            <SourcePill
              label={`${t('weakchip.source.offline', 'offline test')}: ${offlineReport.report_id}`}
              title="/api/diagnostics/chip-health — persisted offline test"
            />
          )}
          <SourcePill label={snapshot?.report_id ?? 'chip snapshot'} title="/api/chips — ChipHealthSnapshot" />
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => void load()}
            disabled={refreshing}
          >
            {refreshing ? '…' : t('weakchip.refresh', 'Refresh')}
          </button>
        </div>
      </div>
      <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', margin: '4px 0 12px', maxWidth: 720 }}>
        {t('weakchip.subtitle', 'Ranked repair view built from real per-chip evidence. Advisory only — nothing here marks a chip dead without an offline test.')}
      </div>

      {/* Honest degrade: no fabricated temps */}
      {!anyPerChipTemps && (
        <div
          data-testid="weak-chip-temp-note"
          style={{
            fontSize: '0.65rem', fontStyle: 'italic', color: '#D97706', lineHeight: 1.4,
            padding: '5px 8px', marginBottom: 8,
            background: 'rgba(217, 119, 6, 0.06)', borderRadius: 'var(--radius-sm)',
          }}
        >
          <span style={{ marginRight: 4 }}>&#9432;</span>
          {t('weakchip.tempUnavailable', 'Per-chip die temperature is not reported by this firmware — temperature ranking stays unavailable and ranking uses nonce/CRC/grade evidence only.')}
        </div>
      )}

      {/* Evidence mode selector */}
      <div
        role="group"
        aria-label="Weak-chip ranking evidence mode"
        style={{ display: 'flex', gap: 6, marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}
      >
        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>{t('weakchip.rankBy', 'Rank by')}</span>
        {modeMeta.map(m => (
          <button
            key={m.id}
            type="button"
            data-testid={`weak-chip-mode-${m.id}`}
            className={`chipmap-mode-btn time-tab ${mode === m.id ? 'active' : ''}`}
            onClick={() => setMode(m.id)}
            disabled={m.disabled}
            aria-pressed={mode === m.id}
            aria-label={m.aria}
            title={m.disabled
              ? 'Per-chip die temperatures are not on the wire — this mode stays unavailable instead of estimating.'
              : undefined}
          >
            {m.label}
          </button>
        ))}
      </div>

      {/* Weakest chips ranked table */}
      <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>
        {t('weakchip.table.title', 'Weakest chips')} ({ranked.length})
      </div>
      <div className="table-wrap">
        <table className="dp-table" data-testid="weak-chip-table">
          <thead>
            <tr>
              <th scope="col" className="is-l">{t('weakchip.col.rank', 'Rank')}</th>
              <th scope="col">{t('weakchip.col.chain', 'Chain')}</th>
              <th scope="col">{t('weakchip.col.chip', 'Chip')}</th>
              <th scope="col" title="Grade from the /api/chips ChipHealthSnapshot">{t('weakchip.col.grade', 'Grade')}</th>
              <th scope="col" title="Health score merged from /api/chips + /api/autotuner/chip-health">{t('weakchip.col.health', 'Health')}</th>
              <th scope="col" className="is-r" title="Percent below the same-chain average nonce (/api/chips nonce_count)">{t('weakchip.col.nonceDeficit', 'Nonce deficit')}</th>
              <th scope="col" className="is-r" title="CRC errors (/api/chips crc_errors)">{t('weakchip.col.crc', 'CRC errors')}</th>
              <th scope="col" className="is-r" title="Per-chip die temp — n/a until the firmware publishes it">{t('weakchip.col.temp', 'Die temp')}</th>
              <th scope="col" className="is-r" title="Cross-chain hot z-score (dcentrald-chip-analysis math) — n/a without per-chip temps">{t('weakchip.col.tempZ', 'Temp z')}</th>
              <th scope="col" title="Nonce-deficit samples gathered by this panel during this session">{t('weakchip.col.trend', 'Trend')}</th>
              <th scope="col">{t('weakchip.col.source', 'Source')}</th>
              <th scope="col">{t('weakchip.col.action', 'Action')}</th>
            </tr>
          </thead>
          <tbody>
            {ranked.map((row, i) => {
              const trend = trendRef.current.get(`${row.chainId}:${row.chipIndex}`) ?? [];
              return (
                <tr key={`${row.chainId}:${row.chipIndex}`} data-testid={`weak-chip-row-${row.chainId}-${row.chipIndex}`}>
                  <td className="is-l tnum">{i + 1}</td>
                  <td className="tnum">{row.chainId}</td>
                  <td className="tnum">{row.chipIndex}</td>
                  <td style={{ color: row.healthTone === 'failing' ? 'var(--red)' : row.healthTone === 'degraded' ? 'var(--yellow)' : 'var(--text)' }}>
                    {row.present ? row.grade : `${row.grade || '—'} (${t('weakchip.notResponding', 'not responding')})`}
                  </td>
                  <td style={{ color: CHIP_HEALTH_COLORS[row.healthTone] }}>
                    {formatHealthPercent(row.healthScoreNormalized)}
                  </td>
                  <td className="is-r tnum" style={{ color: row.nonceDeficitPct >= 40 ? 'var(--red)' : row.nonceDeficitPct > 0 ? 'var(--yellow)' : 'var(--green)' }}>
                    {row.nonceDeficitPct.toFixed(0)}%
                  </td>
                  <td className="is-r tnum" style={{ color: row.crcErrors > 0 ? 'var(--red)' : 'var(--green)' }}>
                    {row.crcErrors}
                  </td>
                  <td className="is-r tnum">{row.tempC == null ? 'n/a' : `${row.tempC.toFixed(1)}°C`}</td>
                  <td className="is-r tnum">{row.tempZ == null ? 'n/a' : row.tempZ.toFixed(2)}</td>
                  <td>
                    {trend.length >= 2
                      ? <TrendSparkline samples={trend} />
                      : <span style={{ color: 'var(--text-dim)', fontStyle: 'italic' }}>{t('weakchip.trendCollecting', 'collecting…')}</span>}
                  </td>
                  <td>
                    <span style={{ display: 'inline-flex', gap: 4, flexWrap: 'wrap' }}>
                      {row.sources.map(src => (
                        <SourcePill key={src} label={sourceLabel(src)} />
                      ))}
                    </span>
                  </td>
                  <td>
                    {row.action === 'derate' ? (
                      <button
                        type="button"
                        className="btn btn-secondary"
                        onClick={() => derateCta(row)}
                        aria-label={`Derate chain ${row.chainId} chip ${row.chipIndex} — opens the existing per-chip override on the Tuning page`}
                      >
                        {actionLabel(row.action)}
                      </button>
                    ) : (
                      <span style={{ color: row.action === 'inspect' ? 'var(--red)' : 'var(--text-dim)' }}>
                        {actionLabel(row.action)}
                      </span>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      {/* Repair-order advisory */}
      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>
          {t('weakchip.advisory.title', 'Repair order')}
        </div>
        {advisory.length === 0 ? (
          <div style={{ fontSize: '0.72rem', color: 'var(--green)' }}>
            No weak-chip suspects in the current evidence — nothing to repair-order.
          </div>
        ) : (
          <ol data-testid="weak-chip-advisory-list" style={{ margin: 0, paddingLeft: 20, fontSize: '0.75rem', lineHeight: 1.7 }}>
            {advisory.map(row => (
              <li key={`${row.chainId}:${row.chipIndex}`} data-testid={`weak-chip-advisory-${row.chainId}-${row.chipIndex}`}>
                <strong>Chain {row.chainId} · Chip {row.chipIndex}</strong>
                {' '}— grade {row.grade || 'n/a'}, {row.nonceDeficitPct.toFixed(0)}% nonce deficit
                {row.crcErrors > 0 ? `, ${row.crcErrors} CRC errors` : ''}
                {row.tempZ != null ? `, temp z ${row.tempZ.toFixed(2)}` : ''}
                {' '}→ {actionLabel(row.action)}
                {row.action === 'inspect' && ' (confirm with an offline chip-health test before replacing)'}
              </li>
            ))}
          </ol>
        )}
        <div style={{ fontSize: '0.65rem', color: 'var(--text-dim)', fontStyle: 'italic', marginTop: 6 }}>
          {t('weakchip.advisory.note', 'Inspect/replace candidates first, then derate. A chip is never declared dead without an offline chip-health test.')}
        </div>
      </div>

      {/* Per-chain grid — production ChipHeatMap reuse */}
      <div style={{ marginTop: 16 }}>
        <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text)', marginBottom: 6 }}>
          {t('weakchip.grid.title', 'Per-chain chip map')}
        </div>
        {gridChains.length === 0 ? (
          <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontStyle: 'italic' }}>
            Chain grid needs live chain telemetry from the miner status — per-chain maps appear
            once status chains load. The ranked table above is unaffected.
          </div>
        ) : (
          gridChains.map(({ index, id }) => (
            <ChipHeatMap key={id} chainIndex={index} chainId={id} />
          ))
        )}
      </div>
    </section>
  );
}
