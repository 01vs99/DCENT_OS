import { fundContributeUrl } from '../utils/links';
export { DCENT_FUND_CANONICAL_URL, fundContributeUrl } from '../utils/links';
// AppShell — unified shell that replaces the 3-way mode conditional in App.tsx.
// Provides hash routing sync, unified mode rendering, and page transition animation.

import React, { useEffect } from 'react';
import { useMinerStore } from '../store/miner';
import { setHash, normalizePageForMode } from '../utils/router';
import { StandardDashboard } from './standard/StandardDashboard';
import { HelpPage } from './common/HelpPage';

/** Cross-mode Fund chip for heater / hacker chrome (Standard uses Sidebar + KitTopBar). */
export function FundSupportLink({ placement }: { placement: string }) {
  return (
    <a
      href={fundContributeUrl(placement)}
      target="_blank"
      rel="noopener noreferrer"
      aria-label="Fund the Sovereign Stack"
      style={{
        position: 'fixed',
        right: 12,
        bottom: 12,
        zIndex: 30,
        fontSize: '0.75rem',
        fontWeight: 700,
        letterSpacing: '0.04em',
        textTransform: 'uppercase',
        color: 'var(--accent, #FAA500)',
        textDecoration: 'none',
        padding: '6px 12px',
        borderRadius: 999,
        background: 'rgba(250, 165, 0, 0.12)',
        border: '1px solid rgba(250, 165, 0, 0.32)',
      }}
    >
      Fund
    </a>
  );
}

// Code-split the two non-default mode trees. Standard is the default
// first-paint, so it stays eagerly imported (lazy-loading it would only add a
// Suspense flash on the most-common path). Hacker (the large password-gated
// Advanced tool tree — AdvancedDashboard + Console/CommandBar/NotificationCenter
// + ~30 lazy tools) and Heater load on demand, so a session that never leaves
// Standard never evaluates their module graphs.
//
// SINGLE-FILE BUILD CAVEAT: vite-plugin-singlefile inlines every emitted chunk
// back into one index.html, so this split does NOT reduce the on-disk bundle
// size. The win is runtime deferral — the non-default mode component modules
// are only evaluated/mounted when the operator switches into them — plus an
// explicit chunk graph that would shrink the initial payload immediately if the
// single-file constraint were ever relaxed.
const AdvancedDashboard = React.lazy(() =>
  import('./advanced/AdvancedDashboard').then(m => ({ default: m.AdvancedDashboard })),
);
const BasicDashboard = React.lazy(() =>
  import('./basic/BasicDashboard').then(m => ({ default: m.BasicDashboard })),
);

export function AppShell() {
  const mode = useMinerStore(s => s.mode);
  const currentPage = useMinerStore(s => s.currentPage);
  const setCurrentPage = useMinerStore(s => s.setCurrentPage);

  // Sync store -> hash (when currentPage changes programmatically)
  useEffect(() => {
    setHash(currentPage);
  }, [currentPage]);

  // Keep page/hash honest when crossing modes. Each mode has its own page
  // vocabulary; stale pages from a previous mode resolve to that mode's
  // primary landing page instead of rendering a mismatched URL.
  useEffect(() => {
    const normalizedPage = normalizePageForMode(mode, currentPage);
    if (normalizedPage !== currentPage) {
      setCurrentPage(normalizedPage);
    }
  }, [currentPage, mode, setCurrentPage]);

  // Render mode-appropriate layout.
  // Each dashboard component already has its own mode-class wrapper
  // (mode-basic, mode-standard, mode-hacker), so no extra wrapper here.
  // The lazy (non-default) modes need a Suspense ancestor; Standard renders
  // synchronously so the fallback never shows on the default path.
  const content =
    currentPage.split('/')[0] === 'help' ? (
      <HelpPage />
    ) : mode === 'heater' ? (
      <BasicDashboard />
    ) : mode === 'hacker' ? (
      <AdvancedDashboard />
    ) : (
      <StandardDashboard />
    );

  return (
    <React.Suspense
      fallback={
        <div className="mode-lazy-fallback" role="status" aria-live="polite">
          Loading…
        </div>
      }
    >
      {content}
      {mode !== 'standard' && <FundSupportLink placement="appshell" />}
    </React.Suspense>
  );
}
