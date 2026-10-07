/** @vitest-environment jsdom */
//
// Weak-chip advisory panel tests (a5 Design 1 — superiority view).
// Covers: fixture render, ranked ordering correctness (pure + rendered),
// honest degrade (no per-chip temps => temp mode unavailable, never
// fabricated), the offline/unavailable path, the derate CTA routing to the
// EXISTING per-chip override flow (no new write path), ChipHeatMap grid
// reuse, the session trend sparkline, and i18n key presence in all five
// locale tables.

import React from 'react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';

import { WeakChipAdvisoryPanel, buildWeakChipRows, sortWeakChipRows, computeNonceDeficit, slotAverageNonce, computeHotZscore } from './WeakChipAdvisoryPanel';
import { LOCALE_KEYS } from '../../i18n/locales/table';
import en from '../../i18n/locales/en';
import es from '../../i18n/locales/es';
import fr from '../../i18n/locales/fr';
import zh from '../../i18n/locales/zh';
import ru from '../../i18n/locales/ru';
import type {
  AutotunerChipHealthResponse,
  ChipHealthSnapshotResponse,
} from '../../api/types';

// ── Mocks (existing patterns: FleetView.test / RecoverySupport.test) ────────

const mockApi = vi.hoisted(() => ({
  getChips: vi.fn(),
  getAutotunerChipHealth: vi.fn(),
  getRecentDiagnosticReports: vi.fn(),
  setChipFrequency: vi.fn(),
}));

const mockStore = vi.hoisted(() => ({
  status: { chains: [{ id: 6 }, { id: 7 }] },
  setCurrentPage: vi.fn(),
  addAlert: vi.fn(),
}));

vi.mock('../../api/client', () => ({ api: mockApi }));
vi.mock('../../store/miner', () => ({
  useMinerStore: (select: (value: typeof mockStore) => unknown) => select(mockStore),
}));
vi.mock('../../i18n/i18n', () => ({
  useTranslation: () => ({ t: (_key: string, fallback?: string) => fallback ?? _key, locale: 'en', setLocale: () => undefined }),
}));

// ── Fixtures (shapes mirror the REAL /api/chips + /api/autotuner/chip-health) ─

function makeSnapshot(withTemps: boolean): ChipHealthSnapshotResponse {
  const temp = (v: number | null) => (withTemps ? { die_temp_c: v } : {});
  return {
    report_id: 'chip-health-test',
    generated_at: '2026-10-05T00:00:00Z',
    report_type: 'chip_health',
    source: 'diagnostics',
    total_boards: 2,
    total_chips: 6,
    warnings: [],
    recommendations: [],
    chains: [
      {
        chain_id: 6,
        source: 'diagnostics',
        chip_count: 4,
        responding_chips: 3,
        board_temp_c: 60,
        board_hashrate_ghs: 4000,
        board_health_score: 0.6,
        frequency_mhz: 650,
        voltage_mv: 9100,
        errors: 14,
        status: 'ok',
        chipmap: {
          chain_id: 6,
          chip_count: 4,
          columns: 4,
          rows: 1,
          cells: [
            { index: 0, address: 0, health_score: 0.96, grade: 'A', color: 'Green', frequency_mhz: 650, nonce_count: 1200, crc_errors: 0, ...temp(55) },
            { index: 1, address: 1, health_score: 0.62, grade: 'C', color: 'Yellow', frequency_mhz: 625, nonce_count: 400, crc_errors: 2, ...temp(60) },
            { index: 2, address: 2, health_score: 0.24, grade: 'F', color: 'Red', frequency_mhz: 580, nonce_count: 40, crc_errors: 12, ...temp(80) },
            { index: 3, address: 3, health_score: 0, grade: 'X', color: 'Gray', frequency_mhz: 0, nonce_count: 0, crc_errors: 0, ...temp(null) },
          ],
        },
      },
      {
        chain_id: 7,
        source: 'diagnostics',
        chip_count: 2,
        responding_chips: 2,
        board_temp_c: 58,
        board_hashrate_ghs: 3600,
        board_health_score: 0.7,
        frequency_mhz: 640,
        voltage_mv: 9100,
        errors: 3,
        status: 'ok',
        chipmap: {
          chain_id: 7,
          chip_count: 2,
          columns: 2,
          rows: 1,
          cells: [
            { index: 0, address: 0, health_score: 0.9, grade: 'A', color: 'Green', frequency_mhz: 640, nonce_count: 1000, crc_errors: 0 },
            { index: 1, address: 1, health_score: 0.5, grade: 'C', color: 'Yellow', frequency_mhz: 600, nonce_count: 200, crc_errors: 3 },
          ],
        },
      },
    ],
  };
}

const autotunerHealth: AutotunerChipHealthResponse = {
  source: 'runtime',
  live_runtime: true,
  stale: false,
  age_s: 2,
  last_update_s: 1_779_999_600,
  message: 'ok',
  total_chips: 2,
  chips: [
    {
      chain_id: 6,
      chip_index: 1,
      health_score: 58,
      trend: 0,
      estimated_days_to_warning: null,
      error_rate_pct: 1.4,
      freq_mhz: 625,
      backoff_count: 0,
      hashrate_ratio: 0.9,
      status: 'healthy',
    },
  ],
};

function mockReady(withTemps: boolean) {
  mockApi.getChips.mockResolvedValue(makeSnapshot(withTemps));
  mockApi.getAutotunerChipHealth.mockResolvedValue(autotunerHealth);
  mockApi.getRecentDiagnosticReports.mockResolvedValue({
    status: 'ok',
    reports: [{
      report_id: 'chip-health-offline-1',
      test_type: 'chip_health_snapshot',
      generated_at: '2026-10-04T00:00:00Z',
      firmware_version: '1.0.0',
      html_size_bytes: 2048,
      json_size_bytes: 4096,
      grade: 'B',
    }],
  });
}

beforeEach(() => {
  vi.clearAllMocks();
  mockStore.setCurrentPage.mockReset();
  mockStore.addAlert.mockReset();
});

afterEach(() => {
  cleanup();
});

// ── Pure analysis (dcentrald-chip-analysis port) ────────────────────────────

describe('weak-chip analysis math (crate port)', () => {
  it('computes nonce deficit vs chain average with the crate semantics', () => {
    // Chain 6 nonces: [1200, 400, 40, 0] -> avg 410.
    const avg = slotAverageNonce([1200, 400, 40, 0]);
    expect(avg).toBeCloseTo(410);
    expect(computeNonceDeficit(1200, avg)).toBe(0);       // at-or-above average
    expect(computeNonceDeficit(40, avg)).toBeCloseTo(90.24, 1);
    expect(computeNonceDeficit(0, avg)).toBeCloseTo(100, 1);
    expect(computeNonceDeficit(50, 0)).toBe(0);           // no nonces on chain: undefined
    expect(slotAverageNonce([])).toBe(0);
  });

  it('keeps the hot z-score hot-spot-only and capped for uniform populations', () => {
    expect(computeHotZscore(60, 55, 5)).toBeCloseTo(1);
    expect(computeHotZscore(50, 55, 5)).toBe(0);          // cooler than mean: not flagged
    expect(computeHotZscore(70, 55, 0)).toBe(3);          // uniform std: capped, no infinity
    expect(computeHotZscore(70, 55, Number.NaN)).toBe(3); // invalid stats: conservative cap
  });
});

// ── Ranked ordering correctness ─────────────────────────────────────────────

describe('weak-chip ranked ordering', () => {
  it('ranks by combined evidence with deterministic ties (grade mode)', () => {
    const rows = buildWeakChipRows(makeSnapshot(true), autotunerHealth);
    // Sanity: all 6 snapshot cells projected, none fabricated.
    expect(rows).toHaveLength(6);

    const ranked = sortWeakChipRows(rows, 'grade');
    expect(ranked.slice(0, 3).map(r => `${r.chainId}:${r.chipIndex}`)).toEqual([
      '6:2', // grade F + 90% deficit + 12 CRC + failing health
      '7:1', // grade C + 67% deficit
      '6:3', // not responding (health 0, 100% deficit) — but grade X carries no grade weight
    ]);
    // Weakest first, healthy A-chips last.
    expect(ranked[ranked.length - 1].grade).toBe('A');
  });

  it('ranks by nonce deficit when that evidence mode is selected', () => {
    const ranked = sortWeakChipRows(buildWeakChipRows(makeSnapshot(true), autotunerHealth), 'nonce-deficit');
    expect(ranked.slice(0, 3).map(r => `${r.chainId}:${r.chipIndex}`)).toEqual(['6:3', '6:2', '7:1']);
  });

  it('marks not-responding chips inspect and weak C/F chips derate — never dead', () => {
    const rows = buildWeakChipRows(makeSnapshot(true), autotunerHealth);
    const byKey = new Map(rows.map(r => [`${r.chainId}:${r.chipIndex}`, r]));
    expect(byKey.get('6:3')?.action).toBe('inspect');
    expect(byKey.get('6:2')?.action).toBe('derate');
    expect(byKey.get('6:0')?.action).toBe('watch');
    for (const row of rows) {
      expect(row.action).not.toMatch(/dead|replace-only/i);
    }
  });

  it('merges autotuner evidence into the row sources', () => {
    const rows = buildWeakChipRows(makeSnapshot(true), autotunerHealth);
    const merged = rows.find(r => r.chainId === 6 && r.chipIndex === 1);
    expect(merged?.sources).toEqual(['diagnostics', 'autotuner']);
    const plain = rows.find(r => r.chainId === 7 && r.chipIndex === 0);
    expect(plain?.sources).toEqual(['diagnostics']);
  });
});

// ── Rendered panel ───────────────────────────────────────────────────────────

describe('WeakChipAdvisoryPanel render', () => {
  it('renders the ranked table from a real snapshot fixture with source labels', async () => {
    mockReady(true);
    render(<WeakChipAdvisoryPanel />);

    const table = await screen.findByTestId('weak-chip-table');
    const rowOrder = within(table)
      .getAllByRole('row')
      .slice(1) // header
      .map(tr => tr.getAttribute('data-testid'));
    expect(rowOrder).toEqual([
      'weak-chip-row-6-2',
      'weak-chip-row-7-1',
      'weak-chip-row-6-3',
      'weak-chip-row-6-1',
      'weak-chip-row-7-0',
      'weak-chip-row-6-0',
    ]);

    // Source labels: snapshot + autotuner + offline test are all labeled.
    expect(within(table).getAllByText('diagnostics snapshot').length).toBeGreaterThan(0);
    expect(within(table).getAllByText('autotuner estimate').length).toBeGreaterThan(0);
    expect(screen.getByText(/offline test: chip-health-offline-1/)).toBeTruthy();

    // Advisory present, honest phrasing (suspects are never "dead").
    const advisory = screen.getByTestId('weak-chip-advisory-list');
    expect(within(advisory).getAllByText(/Chain 6 · Chip 2/).length).toBeGreaterThan(0);
    expect(advisory.textContent).not.toMatch(/dead/i);
  });

  it('degrades honestly when per-chip temps are absent from the wire', async () => {
    mockReady(false); // snapshot WITHOUT die_temp_c anywhere
    render(<WeakChipAdvisoryPanel />);

    await screen.findByTestId('weak-chip-table');

    // Temp mode is disabled with an explanatory note — never estimated.
    const tempMode = screen.getByTestId('weak-chip-mode-temp');
    expect((tempMode as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByTestId('weak-chip-temp-note').textContent).toContain('not reported');

    // Temp + z columns show the honest n/a, not a fabricated number.
    const worst = screen.getByTestId('weak-chip-row-6-2');
    const tempCells = within(worst).getAllByText('n/a');
    expect(tempCells.length).toBeGreaterThanOrEqual(2);
    expect(within(worst).queryByText(/°C/)).toBeNull();
  });

  it('shows the honest unavailable state when /api/chips returns nothing', async () => {
    mockApi.getChips.mockResolvedValue(null);
    mockApi.getAutotunerChipHealth.mockResolvedValue(autotunerHealth);
    mockApi.getRecentDiagnosticReports.mockResolvedValue({ status: 'ok', reports: [] });
    render(<WeakChipAdvisoryPanel />);

    const unavailable = await screen.findByTestId('weak-chip-unavailable');
    expect(unavailable.textContent).toContain('no weak-chip list is estimated');
    expect(screen.queryByTestId('weak-chip-table')).toBeNull();
  });

  it('routes the derate CTA to the existing per-chip override flow (no new write path)', async () => {
    mockReady(true);
    render(<WeakChipAdvisoryPanel />);

    const derate = await screen.findByRole('button', {
      name: /Derate chain 6 chip 2 — opens the existing per-chip override on the Tuning page/,
    });
    fireEvent.click(derate);

    expect(mockStore.setCurrentPage).toHaveBeenCalledWith('tuning');
    expect(mockStore.addAlert).toHaveBeenCalledTimes(1);
    // Read-only panel: the only real write endpoint is never touched here.
    expect(mockApi.setChipFrequency).not.toHaveBeenCalled();
  });

  it('reuses the production ChipHeatMap for each live chain', async () => {
    mockReady(true);
    render(<WeakChipAdvisoryPanel />);

    expect(await screen.findByText('Chain 6 Estimated Chip Map')).toBeTruthy();
    expect(screen.getByText('Chain 7 Estimated Chip Map')).toBeTruthy();
  });

  it('collects the trend sparkline from its own session samples only', async () => {
    mockReady(true);
    render(<WeakChipAdvisoryPanel />);

    // First sample: no trend yet — honest "collecting" placeholder.
    const worst = await screen.findByTestId('weak-chip-row-6-2');
    expect(within(worst).getByText('collecting…')).toBeTruthy();

    // Second refresh appends a second real sample -> sparkline renders.
    fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    await waitFor(() => {
      expect(within(screen.getByTestId('weak-chip-row-6-2')).getByTestId('weak-chip-trend')).toBeTruthy();
    });
    const spark = screen.getByTestId('weak-chip-row-6-2').querySelector('[data-testid="weak-chip-trend"]');
    expect(spark?.getAttribute('role')).toBe('img');
    expect(spark?.getAttribute('aria-label')).toContain('2 session samples');
  });
});

// ── i18n parity for the new keys ────────────────────────────────────────────

describe('weak-chip i18n keys (all five locales)', () => {
  const weakChipKeys = LOCALE_KEYS.filter(k => k.startsWith('weakchip.'));
  const tables: Record<string, Record<string, string>> = { en, es, fr, zh, ru };

  it('registers the full weak-chip key set in the shared table', () => {
    expect(weakChipKeys.length).toBeGreaterThanOrEqual(35);
  });

  it('resolves every weak-chip key in en/es/fr/zh/ru (no raw-key fallback)', () => {
    for (const [locale, table] of Object.entries(tables)) {
      for (const key of weakChipKeys) {
        expect(table[key], `${locale} missing ${key}`).toBeTruthy();
      }
    }
  });
});
