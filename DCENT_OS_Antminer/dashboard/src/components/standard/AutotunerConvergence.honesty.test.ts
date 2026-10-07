import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

/**
 * C3a (2026-09-01 gauntlet lane C3a) — autotune default-ON honesty tests.
 *
 * The convergence evidence surfaces the refuse-not-tune-blind substrate:
 * NotTunable reasons, first-boot park reasons, rung counts with Refused +
 * reasons, and the envelope version. These pins keep that surface HONEST:
 *
 * 1. no projected J/TH is ever displayed as measured (the convergence
 *    efficiency figure is labeled a model estimate everywhere it appears);
 * 2. the refusal reason is rendered, not swallowed;
 * 3. the NotTunable state is rendered as a refusal, never as a success.
 */
const cardSource = readFileSync('src/components/standard/AutotunerCard.tsx', 'utf8');
const pageSource = readFileSync('src/components/autotuner/AutoTunerPage.tsx', 'utf8');
const typesSource = readFileSync('src/api/types.ts', 'utf8');

describe('Autotuner convergence honesty (C3a)', () => {
  it('labels the convergence efficiency projection as a model estimate, never measured', () => {
    // The card renders the convergence J/TH figure only under an explicit
    // "model projection, not measured" label.
    expect(cardSource).toContain('Est. J/TH (model projection, not measured)');
    // The existing hero KPI stays "Est. J/TH" (the pre-C3a honesty pin).
    expect(pageSource).toContain('Est. J/TH <InfoDot term="efficiency_jth"');
    // The type contract documents the estimate pin.
    expect(typesSource).toContain('efficiency_jth_estimated: boolean;');
    expect(typesSource).toContain('ALWAYS a model-derived projection');
  });

  it('surfaces the NotTunable refusal and the first-boot park reason verbatim', () => {
    expect(cardSource).toContain('NOT TUNABLE — {status.not_tunable_reason}');
    expect(cardSource).toContain('Parked in Idle — {status.start_gate_park_reason}');
    expect(pageSource).toContain('NOT TUNABLE — {status.not_tunable_reason}');
    expect(pageSource).toContain('Parked in Idle — {status.start_gate_park_reason}');
  });

  it('renders the refused rung count with its reasons and the envelope version', () => {
    // Rung counts include Refused, and each refusal reason is rendered.
    expect(cardSource).toContain('Refused {status.convergence.rung_counts.refused}');
    expect(cardSource).toContain('refused: {reason}');
    // The evidence names the envelope generation it was produced under.
    expect(cardSource).toContain('status.convergence?.envelope_version');
    expect(pageSource).toContain('status?.convergence?.envelope_version');
  });

  it('never renders a projected efficiency when the estimate flag is absent', () => {
    // The card's convergence J/TH render is gated on the pinned estimate
    // flag — a payload without the flag renders an em-dash, never a number
    // that could be read as measured.
    expect(cardSource).toMatch(
      /efficiency_jth_estimated\s*\?\s*status\.convergence\.estimated_efficiency_jth\.toFixed\(2\)\s*:\s*'—'/,
    );
  });

  it('keeps a NotTunable variant from looking like a tuning success', () => {
    // The guard strip is a distinct evidence block (not part of the
    // progress/ETA lane), and the refusal text is styled as an error.
    expect(cardSource).toContain('data-testid="autotuner-not-tunable"');
    expect(cardSource).toContain("color: 'var(--red)'");
    expect(pageSource).toContain('data-testid="autotuner-page-not-tunable"');
  });
});
