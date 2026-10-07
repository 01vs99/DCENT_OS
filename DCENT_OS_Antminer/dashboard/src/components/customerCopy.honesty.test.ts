import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

const COMPONENTS_DIR = join(process.cwd(), 'src/components');

const BANNED_CUSTOMER_COPY = [
  /not implemented/i,
  /not yet available/i,
  /not yet wired/i,
  /not yet configured/i,
  /not exposed by this firmware build yet/i,
  /not exposed by/i,
  /not wired/i,
  /none are wired/i,
  /still not wired/i,
  /not available yet/i,
  /\buntested\b/i,
  /\bno api\b/i,
  /no [^'"\n.]*endpoint exists/i,
  /don't affect dcentrald/i,
  /not supported on this hardware path yet/i,
  /for ~20% hashrate improvement/i,
  /~20% hashrate improvement/i,
];

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(path, out);
    } else if (/\.tsx?$/.test(entry.name) && !/\.(test|spec)\.tsx?$/.test(entry.name)) {
      out.push(path);
    }
  }
  return out;
}

function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/^\s*\/\/.*$/gm, '');
}

describe('customer-facing dashboard copy', () => {
  it('uses product-grade in-development wording instead of dev-negative unavailable copy', () => {
    const offenders: string[] = [];
    for (const path of walk(COMPONENTS_DIR)) {
      const source = stripComments(readFileSync(path, 'utf8'));
      for (const pattern of BANNED_CUSTOMER_COPY) {
        if (pattern.test(source)) offenders.push(`${path}: ${pattern}`);
      }
    }

    expect(offenders).toEqual([]);
  });

  it('surfaces the canonical Fund URL in shell, nav, footer, and About chrome', () => {
    const required = [
      'AppShell.tsx',
      'standard/Sidebar.tsx',
      'standard/KitTopBar.tsx',
      'common/AboutPage.tsx',
    ];
    for (const rel of required) {
      const source = readFileSync(join(COMPONENTS_DIR, rel), 'utf8');
      expect(source, `${rel} must import the shared Fund helper`).toMatch(/import \{[^}]*fundContributeUrl[^}]*\} from '[^']*utils\/links'/);
      expect(source, `${rel} must render the shared Fund destination`).toContain('href={fundContributeUrl(');
    }
  });
});
