// C6 (2026-09-01) donation-nudge honesty gate.
//
// The donation posture flipped to 0% default + opt-in nudge. This gate pins
// the copy contract of every customer-facing donation surface so the nudge
// can never regress into the old CLAIM_UNSAFE claims or pressure patterns:
//   • no "pays for itself" / autotuner-offsets-the-donation claim
//     (CLAIM_UNSAFE row in DCENT_OS_Antminer/docs/COMPETITIVE_FEATURE_MATRIX.md);
//   • no countdown / scarcity / pressure wording;
//   • "no mandatory fee" is stated on the nudge surfaces;
//   • the canonical fund link is on every donation surface;
//   • the dashboard default state is disabled @ 0% (mirrors DonationConfig);
//   • the compact nudge is dismissible.
//
// Modeled on customerCopy.honesty.test.ts (source-scan, no DOM).

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const COMPONENTS_DIR = join(process.cwd(), 'src/components');

const DONATION_SURFACES = [
  'common/DonationFeeCard.tsx',
  'wizard/DonationStep.tsx',
] as const;

function load(rel: string): string {
  return readFileSync(join(COMPONENTS_DIR, rel), 'utf8');
}

/** Strip comments so the truth-contract headers themselves (which NAME the
 * banned claims) don't trip the copy scan — same approach as
 * customerCopy.honesty.test.ts. */
function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

// Pressure patterns a "polished, not naggy" nudge must never use.
// NOTE: the verbs are anchored directly after "autotuner" so the honest
// NEGATED disclaimer ("the autotuner does not pay this donation") stays
// legal while the affirmative claim stays banned.
const BANNED_PRESSURE_PATTERNS: RegExp[] = [
  /pays for itself/i,
  /pay(?:s|ing)? for the donation/i,
  /autotuner (?:saves|pays|offsets)/i,
  /last chance/i,
  /act now/i,
  /expires?/i,
  /limited time/i,
  /only \d+ (?:left|remaining|days|hours)/i,
  /before it(?:'s| is) too late/i,
  /don(?:'t| not) wait/i,
  /hurry/i,
  /please leave (?:it on|at least)/i,
  /revenue model/i,
];

describe('donation nudge copy honesty (C6 zero-default posture)', () => {
  it('never claims the donation pays for itself or leans on pressure wording', () => {
    const offenders: string[] = [];
    for (const rel of DONATION_SURFACES) {
      const source = stripComments(load(rel));
      for (const pattern of BANNED_PRESSURE_PATTERNS) {
        if (pattern.test(source)) offenders.push(`${rel}: ${pattern}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('states "no mandatory fee" and carries the canonical fund link on every donation surface', () => {
    for (const rel of DONATION_SURFACES) {
      const source = load(rel);
      expect(source, `${rel} must state no mandatory fee`).toMatch(/no mandatory fee/i);
      expect(source, `${rel} must import the canonical fund destination`).toMatch(/import \{ DCENT_FUND_CANONICAL_URL(?: as FUND_URL)? \} from '\.\.\/\.\.\/utils\/links'/);
      expect(source, `${rel} must use that destination`).toMatch(/href=\{(?:DCENT_FUND_CANONICAL_URL|FUND_URL)\}/);
    }
  });

  it('dashboard donation default state is disabled at 0 percent (mirrors DonationConfig)', () => {
    const card = load('common/DonationFeeCard.tsx');
    expect(card).toContain('const DEFAULT_PERCENT = 0');
    expect(card).toMatch(/enabled: false/);
    // One-tap opt-in presets are 1/2/3 — never a hidden default-on take.
    expect(card).toMatch(/\[1, 2, 3\]\.map/);

    const wizard = load('wizard/SetupWizard.tsx');
    expect(wizard).toContain("donation: { enabled: false, percent: 0 }");
    expect(wizard).toContain('const DEFAULT_DONATION_PERCENT = 0');
  });

  it('the compact nudge is dismissible without burying the Settings control surface', () => {
    const card = load('common/DonationFeeCard.tsx');
    expect(card).toContain('aria-label="Dismiss donation nudge"');
    // Dismissal persists locally and the full Settings variant stays mounted.
    expect(card).toContain("variant === 'compact'");
    expect(card).toContain("variant = 'full'");
  });

  it('the earnings take-rate helper defaults to the firmware 0 percent opt-in default', () => {
    const thermal = readFileSync(join(process.cwd(), 'src/utils/thermal.ts'), 'utf8');
    expect(thermal).toContain('export const DEFAULT_DONATION_PERCENT = 0');
    // Opted-in takes flow through — the helper must keep applying them.
    expect(thermal).toContain('config.enabled === false');
  });
});
