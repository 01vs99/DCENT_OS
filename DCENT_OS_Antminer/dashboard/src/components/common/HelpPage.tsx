import React from 'react';
import { useMinerStore } from '../../store/miner';
import { getDefaultPageForMode } from '../../utils/router';
import quickstart from '../../../../docs/BETA_QUICKSTART.md?raw';
import install from '../../../../docs/INSTALL/README.md?raw';
import s9 from '../../../../docs/INSTALL/S9_XILINX.md?raw';
import native from '../../../../docs/INSTALL/AM2_NATIVE.md?raw';
import s19j from '../../../../docs/INSTALL/S19J_PRO_XILINX.md?raw';
import beaglebone from '../../../../docs/INSTALL/BEAGLEBONE.md?raw';
import amlogic from '../../../../docs/INSTALL/AMLOGIC.md?raw';

const guides: Record<string, { title: string; text: string }> = {
  'BETA_QUICKSTART.md': { title: 'Quickstart', text: quickstart },
  'README.md': { title: 'Installation', text: install },
  'S9_XILINX.md': { title: 'S9 family', text: s9 },
  'AM2_NATIVE.md': { title: 'Zynq SD trials', text: native },
  'S19J_PRO_XILINX.md': { title: 'S19j Pro Zynq', text: s19j },
  'BEAGLEBONE.md': { title: 'BeagleBone', text: beaglebone },
  'AMLOGIC.md': { title: 'Amlogic', text: amlogic },
};

// Small renderer for our bundled guide vocabulary. React escapes all text;
// raw HTML and arbitrary URL schemes are never interpreted.
function inline(text: string): React.ReactNode[] {
  return text.split(/(\[[^\]]+\]\([^)]+\)|`[^`]+`|\*\*[^*]+\*\*)/g).map((part, i) => {
    const link = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(part);
    if (link) {
      const filename = link[2].split('/').pop() ?? '';
      if (guides[filename]) return <a key={i} href={`#/help/${filename}`}>{link[1]}</a>;
      if (link[2].startsWith('https://')) return <a key={i} href={link[2]} target="_blank" rel="noopener noreferrer">{link[1]}</a>;
      return link[1];
    }
    if (part.startsWith('`')) return <code key={i}>{part.slice(1, -1)}</code>;
    if (part.startsWith('**')) return <strong key={i}>{part.slice(2, -2)}</strong>;
    return part;
  });
}

export function GuideText({ text }: { text: string }) {
  return <>{text.trim().split(/\n\s*\n/).map((block, i) => {
    if (block.startsWith('```')) return <pre key={i} style={{ overflowX: 'auto', padding: 12, background: 'var(--bg-elevated)' }}><code>{block.replace(/^```[^\n]*\n/, '').replace(/\n```$/, '')}</code></pre>;
    if (block.startsWith('# ')) return <h1 key={i}>{inline(block.slice(2))}</h1>;
    if (block.startsWith('## ')) return <h2 key={i}>{inline(block.slice(3))}</h2>;
    if (block.startsWith('- ')) return <ul key={i}>{block.split('\n').map((line, j) => <li key={j}>{inline(line.replace(/^- /, ''))}</li>)}</ul>;
    return <p key={i}>{inline(block)}</p>;
  })}</>;
}

export function HelpPage() {
  const page = useMinerStore(s => s.currentPage);
  const mode = useMinerStore(s => s.mode);
  const setCurrentPage = useMinerStore(s => s.setCurrentPage);
  const selected = page.split('/')[1] || 'BETA_QUICKSTART.md';
  const guide = guides[selected];
  return <main id="main-content" style={{ maxWidth: 880, margin: '0 auto', padding: 24, lineHeight: 1.7 }}>
    <button type="button" onClick={() => setCurrentPage(getDefaultPageForMode(mode))}>Back to dashboard</button>
    <nav aria-label="Help guides" style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBlock: 20 }}>
      {Object.entries(guides).map(([name, item]) => <a key={name} href={`#/help/${name}`} aria-current={selected === name ? 'page' : undefined}>{item.title}</a>)}
    </nav>
    {guide ? <GuideText text={guide.text} /> : <p>Guide not found. Choose a guide above.</p>}
  </main>;
}
