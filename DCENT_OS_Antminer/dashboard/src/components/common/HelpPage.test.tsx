// @vitest-environment jsdom
import React from 'react';
import { afterEach, describe, expect, it } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { readFileSync } from 'node:fs';
import { HelpPage, GuideText } from './HelpPage';
import { DonationStep } from '../wizard/DonationStep';
import { DCENT_DOCS_URL, DCENT_FUND_CANONICAL_URL, fundContributeUrl } from '../../utils/links';
import { normalizePageForMode } from '../../utils/router';
import { useMinerStore } from '../../store/miner';

afterEach(cleanup);
describe('bundled operator help and shared support destinations', () => {
  it('opens the quickstart in every mode and follows each bundled family link', () => {
    expect(DCENT_DOCS_URL).toBe('/#/help');
    for (const mode of ['heater', 'standard', 'hacker'] as const) {
      expect(normalizePageForMode(mode, 'help/AMLOGIC.md')).toBe('help/AMLOGIC.md');
    }
    useMinerStore.setState({ currentPage: 'help', mode: 'heater' });
    const result = render(<HelpPage />);
    expect(screen.getByRole('heading', { level: 1 }).textContent).toContain('beta quickstart');
    const links = Array.from(screen.getByRole('navigation', { name: 'Help guides' }).querySelectorAll('a'));
    expect(links.length).toBe(7);
    for (const link of links) {
      const page = link.getAttribute('href')!.slice(2);
      useMinerStore.setState({ currentPage: page });
      result.rerender(<HelpPage />);
      expect(screen.queryByText(/Guide not found/)).toBeNull();
      expect(screen.getByRole('heading', { level: 1 }).textContent!.length).toBeGreaterThan(5);
    }
    fireEvent.click(screen.getByRole('button', { name: 'Back to dashboard' }));
    expect(useMinerStore.getState().currentPage).toBe('heater-home');
  });

  it('escapes raw markup and refuses arbitrary link schemes', () => {
    const { container } = render(<GuideText text={'# Test\n\n<script>bad()</script> [bad](javascript:bad) **Safe** `literal`'} />);
    expect(container.querySelector('script')).toBeNull();
    expect(container.querySelector('a')).toBeNull();
    expect(container.querySelector('strong')?.textContent).toBe('Safe');
    expect(container.querySelector('code')?.textContent).toBe('literal');
  });

  it('renders the actual wizard Fund link and encodes placement as one parameter', () => {
    render(<DonationStep value={{ enabled: false, percent: 0 }} mode="heater" onChange={() => {}} />);
    expect(document.querySelector(`a[href="${DCENT_FUND_CANONICAL_URL}"]`)).not.toBeNull();
    const url = new URL(fundContributeUrl('settings&redirect=elsewhere'));
    expect(url.searchParams.get('placement')).toBe('settings&redirect=elsewhere');
    expect(url.searchParams.has('redirect')).toBe(false);
  });

  it('has one canonical declaration consumed by all six Fund surfaces', () => {
    const paths = ['AppShell.tsx', 'common/AboutPage.tsx', 'common/DonationFeeCard.tsx', 'wizard/DonationStep.tsx', 'standard/KitTopBar.tsx', 'standard/Sidebar.tsx'];
    for (const path of paths) {
      const source = readFileSync(`src/components/${path}`, 'utf8');
      expect(source).toMatch(/import \{[^}]*(?:DCENT_FUND_CANONICAL_URL|fundContributeUrl)[^}]*\} from '[^']*utils\/links'/);
      expect(source).not.toMatch(/(?:const|href=)[^\n]*https:\/\/d-central\.tech\/fund\//);
    }
  });
});
