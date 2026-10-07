// @vitest-environment jsdom
//
// STD-A-09 honesty regression: the Earnings page falls back to a nominal ~25 W
// "standby" figure when the daemon reports no wall-power telemetry. That assumed
// value must NOT be presented as a real reading — the Power Draw card renders an
// em-dash + "standby (assumed)" and the calculator's "(live)" tag is suppressed
// unless the watts came from measured telemetry.

import { readFileSync } from 'node:fs';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

// EarningsPage polls /api/perf/efficiency and (via useNetworkContext)
// /api/network/block. Both are wrapped in try/catch, so rejecting keeps the
// component on its null-telemetry render path — exactly the state under test.
// Donation fetch is resolved at the firmware 0% opt-in default (C6, 2026-09-01).
vi.mock('../../api/client', () => ({
  api: {
    getPerfEfficiency: vi.fn().mockRejectedValue(new Error('no perf endpoint')),
    getNetworkBlock: vi.fn().mockRejectedValue(new Error('no network block')),
    getDonationConfig: vi.fn().mockResolvedValue({ enabled: false, percent: 0 }),
  },
}));

import { EarningsPage } from './EarningsPage';
import { useMinerStore } from '../../store/miner';
import type { StatusResponse, StatsResponse } from '../../api/types';
import {
  applyTakeRates,
  donationTakePercent,
  DEFAULT_DONATION_PERCENT,
  estimateDailyProfit,
  seasonalHeatCredit,
} from '../../utils/thermal';

const earningsSrc = readFileSync('src/components/standard/EarningsPage.tsx', 'utf8');

function setStore(opts: {
  status: Partial<StatusResponse> | null;
  stats: Partial<StatsResponse> | null;
}) {
  useMinerStore.setState({
    status: (opts.status as unknown as StatusResponse) ?? null,
    stats: (opts.stats as unknown as StatsResponse) ?? null,
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

afterEach(() => {
  cleanup();
  useMinerStore.setState({ status: null, stats: null });
});

describe('EarningsPage — STD-A-09 Power Draw honesty', () => {
  it('renders an em-dash + "standby (assumed)" and no "(live)" tag when power telemetry is absent', () => {
    // status present (so the page renders, not the first-load skeleton) but no
    // stats.power, and standby (hashrate 0) → watts is the assumed ~25 W fallback.
    setStore({ status: { hashrate_ghs: 0, uptime_s: 0 }, stats: null });
    render(<EarningsPage />);

    expect(screen.getByText('standby (assumed)')).toBeTruthy();
    // The assumed value is never advertised as an authoritative "(live)" reading.
    expect(screen.queryByText('(live)')).toBeNull();
  });

  it('shows the measured watts with a "(live)" tag when power telemetry is present', () => {
    setStore({
      status: { hashrate_ghs: 0, uptime_s: 0 },
      stats: {
        power: {
          wall_watts: 1350,
          source: 'pmbus',
          source_detail: 'pmbus_measured',
          live_power_available: true,
        },
      },
    });
    render(<EarningsPage />);

    // Real telemetry → no "assumed" disclaimer, and the calculator "(live)" tag shows.
    expect(screen.queryByText('standby (assumed)')).toBeNull();
    expect(screen.getByText('(live)')).toBeTruthy();
  });

  it('does not treat static fallback watts as live profitability power', () => {
    setStore({
      status: { hashrate_ghs: 0, uptime_s: 0 },
      stats: {
        power: {
          wall_watts: 1350,
          watts: 1200,
          source: 'static_model_fallback',
          live_power_available: false,
          modeled: true,
          btu_h: 4606,
        },
      },
    });
    render(<EarningsPage />);

    expect(screen.getByText('standby (assumed)')).toBeTruthy();
    expect(screen.queryByText('(live)')).toBeNull();
  });

  it('does not render legacy fallback efficiency without live power provenance', () => {
    setStore({
      status: { hashrate_ghs: 0, uptime_s: 0 },
      stats: {
        power: {
          wall_watts: 1350,
          efficiency_jth: 33.5,
          source: 'static_model_fallback',
          source_detail: 'static_power_fallback_from_miner_state',
          live_power_available: false,
          modeled: true,
        },
      },
    });
    render(<EarningsPage />);

    expect(screen.queryByTestId('efficiency-jth-value')).toBeNull();
  });

  it('renders legacy efficiency when the same power object is live-provenance', () => {
    setStore({
      status: { hashrate_ghs: 0, uptime_s: 0 },
      stats: {
        power: {
          wall_watts: 1350,
          efficiency_jth: 33.5,
          source: 'pmbus',
          source_detail: 'pmbus_measured',
          live_power_available: true,
        },
      },
    });
    render(<EarningsPage />);

    expect(screen.getByTestId('efficiency-jth-value').textContent).toContain('33.5 J/TH');
  });
});

describe('EarningsPage — donation + pool fee net vs gross', () => {
  // RE-ANCHORED 2026-09-01 (C6): the firmware default flipped from 2% to the
  // 0% opt-in posture (operator decision). The honesty invariant inverts
  // symmetrically: unknown config must resolve to the SHARED 0% default
  // (never an invented take-rate), and an OPTED-IN donation must never be
  // silently zeroed by the earnings math. Both directions are pinned.
  it('defaults unknown donation to the firmware 0% opt-in default and never zeroes an opted-in take', () => {
    expect(DEFAULT_DONATION_PERCENT).toBe(0);
    expect(donationTakePercent(null)).toBe(0);
    expect(donationTakePercent(undefined)).toBe(0);
    expect(donationTakePercent({ enabled: false, percent: 2 })).toBe(0);
    expect(donationTakePercent({ enabled: true, percent: 2 })).toBe(2);
    expect(donationTakePercent({ enabled: true, percent: 3 })).toBe(3);
    expect(donationTakePercent({ enabled: true, percent: 5 })).toBe(5);
  });

  it('subtracts donation then pool fee from gross sats and does not reduce electricity', () => {
    const difficulty = 1e14;
    const hashrateGhs = 100_000;
    const watts = 1350;
    const btcPrice = 100_000;
    const kwh = 0.12;
    const gross = estimateDailyProfit(hashrateGhs, watts, btcPrice, kwh, difficulty);
    const net = estimateDailyProfit(hashrateGhs, watts, btcPrice, kwh, difficulty, {
      donationPercent: 2,
      poolFeePercent: 1,
    });
    const taken = applyTakeRates(gross.grossSats, 2, 1);

    expect(gross.sats).toBe(gross.grossSats);
    expect(net.grossSats).toBe(gross.grossSats);
    expect(net.sats).toBe(taken.netSats);
    expect(net.sats).toBe(Math.round(gross.grossSats * 0.98 * 0.99));
    expect(net.sats).toBeLessThan(net.grossSats);
    expect(net.revenue).toBeLessThan(net.grossRevenue);
    expect(net.cost).toBe(gross.cost);
    expect(net.profit).toBeCloseTo(net.revenue - net.cost, 10);
    expect(net.donationPercent).toBe(2);
    expect(net.poolFeePercent).toBe(1);
  });

  it('labels gross vs net and resolves the donation rate through the shared firmware default', () => {
    setStore({ status: { hashrate_ghs: 0, uptime_s: 0 }, stats: null });
    render(<EarningsPage />);

    expect(screen.getByTestId('earnings-net-sats').textContent).toMatch(/Net Sats/i);
    expect(screen.getByTestId('earnings-gross-sats').textContent).toMatch(/Gross/i);
    expect(screen.getByTestId('earnings-net-revenue').textContent).toMatch(/Net BTC Revenue/i);
    expect(screen.getByTestId('earnings-net-btc-profit').textContent).toMatch(/heat-credit is not included/i);
    expect(screen.getByTestId('earnings-donation-rate')).toBeTruthy();
    expect(screen.getByLabelText('Donation percent used in net earnings (firmware setting)')).toBeTruthy();
    // RE-ANCHORED (C6): the take-rate must flow through the shared helpers —
    // a hardcoded literal default here could drift from the firmware's 0%
    // opt-in default and silently mis-report net earnings in either
    // direction (previously: hidden 2% take; the guard inverted with the
    // default flip).
    expect(earningsSrc).toContain('DEFAULT_DONATION_PERCENT');
    expect(earningsSrc).toContain('donationTakePercent');
    expect(earningsSrc).not.toMatch(
      /donationPercent, setDonationPercent\] = useState\((?!DEFAULT_DONATION_PERCENT)/,
    );
  });
});

describe('EarningsPage — seasonal heat-credit is optional and not Bitcoin', () => {
  it('keeps heat-credit out of BTC profit math', () => {
    const difficulty = 1e14;
    const btc = estimateDailyProfit(100_000, 1350, 100_000, 0.12, difficulty, {
      donationPercent: 2,
      poolFeePercent: 1,
    });
    const heat = seasonalHeatCredit({
      wall_watts: 1350,
      displaced_fraction: 0.85,
      heating_season_active: 7 / 12,
      kwh_rate: 0.12,
    });
    expect(heat).toBeGreaterThan(0);
    expect(btc.profit).toBeCloseTo(btc.revenue - btc.cost, 10);
    expect(btc.profit + heat).not.toBe(btc.profit);
    expect('heatCredit' in btc).toBe(false);
  });

  it('renders heat-credit as an optional USD estimate, never as sats', () => {
    setStore({
      status: { hashrate_ghs: 100_000, uptime_s: 3600 },
      stats: {
        power: {
          wall_watts: 1350,
          source: 'pmbus',
          source_detail: 'pmbus_measured',
          live_power_available: true,
        },
      },
    });
    render(<EarningsPage />);

    const credit = screen.getByTestId('seasonal-heat-credit');
    expect(credit.textContent).toMatch(/OPTIONAL estimate — not Bitcoin/i);
    expect(credit.textContent).toMatch(/Off/i);
    expect(screen.getByTestId('seasonal-heat-credit-optional-label').textContent).toMatch(/never added to BTC earnings/i);
    expect(screen.getByTestId('bitcoin-net-excludes-heat-credit').textContent).toMatch(/never mixed into sats/i);

    const netProfit = screen.getByTestId('earnings-net-btc-profit').textContent ?? '';
    expect(netProfit).not.toMatch(/heat-credit \+/i);

    fireEvent.click(screen.getByLabelText('Include optional seasonal heat-credit estimate'));
    expect(screen.getByTestId('seasonal-heat-credit').textContent).toMatch(/\$/);
    expect(screen.getByTestId('seasonal-heat-credit').textContent).not.toMatch(/sats/i);
  });

  it('does not compute heat-credit from the standby 25 W assumption', () => {
    expect(earningsSrc).toContain('wattsFromTelemetry ? wallWatts : 0');
    expect(earningsSrc).toContain('heat-credit stays $0 rather than using standby watts');
    expect(earningsSrc).not.toContain('estimateHeatingOffset(effectiveWatts');
  });
});
