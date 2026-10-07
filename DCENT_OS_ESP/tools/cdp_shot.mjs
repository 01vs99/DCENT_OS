// Minimal Chrome DevTools Protocol screenshotter (no puppeteer): real wall-clock
// waits instead of --virtual-time-budget (which makes rAF animations spin the
// renderer to death), full-page capture, device metrics for mobile, and an
// optional JS expression evaluated (and printed) before the capture.
// usage: node cdp_shot.mjs <chrome.exe> <profileDir> <out.png> <url> <width> <height> <waitMs> [fullPage=1] [mobile=0] [jsBefore] [jsWaitMs]
import { spawn } from 'node:child_process';
import { writeFileSync, rmSync } from 'node:fs';

const [chrome, profile, out, url, w, h, waitMs, fullPage = '1', mobile = '0', jsBefore = '', jsWaitMs = '1500'] = process.argv.slice(2);
const port = 9333 + Math.floor(Math.random() * 500);
const proc = spawn(chrome, [
  '--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`,
  '--no-first-run', '--no-default-browser-check', '--hide-scrollbars', '--disable-gpu',
  `--window-size=${w},${h}`, 'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function json(path) {
  for (let i = 0; i < 40; i++) {
    try { const r = await fetch(`http://127.0.0.1:${port}${path}`, { method: 'PUT' }); if (r.ok) return r.json(); } catch {}
    await sleep(250);
  }
  throw new Error('devtools not reachable');
}

let WS = globalThis.WebSocket;
if (!WS) { WS = (await import('ws')).default; }

try {
  const target = await json(`/json/new?${encodeURIComponent('about:blank')}`);
  const ws = new WS(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
  let id = 0; const pending = new Map();
  ws.onmessage = (ev) => { const m = JSON.parse(typeof ev.data === 'string' ? ev.data : ev.data.toString()); if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); } };
  const send = (method, params = {}) => new Promise((res) => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });

  await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride', { width: +w, height: +h, deviceScaleFactor: 1, mobile: mobile === '1' });
  if (mobile === '1') await send('Emulation.setTouchEmulationEnabled', { enabled: true });
  await send('Page.navigate', { url });
  await sleep(+waitMs);
  if (jsBefore) {
    const m = await send('Runtime.evaluate', { expression: jsBefore, returnByValue: true, awaitPromise: true });
    const ex = m.result?.exceptionDetails;
    console.log('EVAL:', ex ? JSON.stringify(ex.exception?.description ?? ex) : JSON.stringify(m.result?.result?.value));
    await sleep(+jsWaitMs);
  }
  let clip = { x: 0, y: 0, width: +w, height: +h, scale: 1 };
  let beyond = false;
  if (fullPage === '1') {
    const m = await send('Runtime.evaluate', { expression: 'Math.max(document.body.scrollHeight, document.documentElement.scrollHeight)', returnByValue: true });
    const height = Math.min(m.result?.result?.value || +h, 12000);
    await send('Emulation.setDeviceMetricsOverride', { width: +w, height, deviceScaleFactor: 1, mobile: mobile === '1' });
    await sleep(600);
    clip = { x: 0, y: 0, width: +w, height, scale: 1 };
    beyond = true;
  }
  const shot = await send('Page.captureScreenshot', { format: 'png', clip, captureBeyondViewport: beyond });
  if (!shot.result) throw new Error('no screenshot: ' + JSON.stringify(shot.error));
  writeFileSync(out, Buffer.from(shot.result.data, 'base64'));
  console.log('wrote', out, Buffer.from(shot.result.data, 'base64').length, 'bytes');
  ws.close();
} finally {
  proc.kill();
  // The Chrome user-data dir is scratch: on 2026-09-02 hundreds of them (one per
  // capture, tens of MB each) took the C: volume to 0 bytes twice. Delete it once
  // Chrome has let go of its files, unless the caller wants to inspect it.
  if (process.env.CDP_KEEP_PROFILE !== '1') {
    await new Promise((r) => proc.once('exit', r));
    for (let i = 0; i < 5; i++) {
      try { rmSync(profile, { recursive: true, force: true }); break; } catch { await sleep(300); }
    }
  }
}
