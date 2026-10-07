#!/usr/bin/env node
// ═══════════════════════════════════════════════════════════════════════════
// DCENT_axe dashboard mock server — PC preview of a firmware-served UI.
// Lane P1-I1 of the DCENT_axe UI Gauntlet.
// Node >= 18, stdlib only. No npm dependencies, ever.
// ═══════════════════════════════════════════════════════════════════════════
//
// The dashboard is inline HTML/CSS/JS baked into the firmware image, so until
// this existed the only way to look at it was to flash a device. This server
// extracts the same bytes the firmware serves and puts them on localhost.
//
//   node axe_mock_server.mjs --src <dcentaxe/src> --port 8181 --scenario mining
//
// FLAGS
//   --src <dir>        directory holding dashboard.rs + dashboard/  (default: ../dcentaxe/src)
//   --port <n>         listen port                                  (default: 8181)
//   --scenario <name>  starting fixture scenario                    (default: mining)
//   --fixtures <dir>   fixture root                                 (default: ./fixtures)
//   --log <path>       request log (JSON lines)                     (default: ./requests.jsonl)
//   --live <ip|host>   proxy GETs to a real device (see LIVE MODE below)
//   --freeze-time      serve fixture timestamps verbatim instead of re-basing them
//   --lora             also append LORA_DASHBOARD_PANEL_HTML, as a `lora` build does
//   --host <addr>      bind address                                 (default: 127.0.0.1)
//   --replay-history   walk the device's OWN captured 60-row statistics history
//                      across successive /api/system/info polls, so the LIVE
//                      telemetry (hero, stat tiles, sparklines) moves over a
//                      capture instead of repeating one frozen frame (default off).
//                      Since lane P1-W6 the Performance chart seeds itself from
//                      /api/system/statistics, so this is no longer needed merely
//                      to get a populated chart.
//
// WHAT IT SERVES
//   GET  /  and  /index.html    the r##"…"## DASHBOARD_HTML literal out of dashboard.rs
//   GET  /dashboard/<file>      the files register_static() actually bakes — and only
//                               those. stats.css / flow.css / stats.js / flow.js exist
//                               on disk but are deliberately NOT baked (dashboard.rs:60,
//                               :71), so the mock 404s them exactly like the firmware.
//   GET  /api/*                 fixture JSON for the active scenario
//   POST/PATCH/DELETE/OPTIONS   accepted ONLY for (method, uri) pairs the firmware
//                               really registers — read out of api.rs / auth.rs /
//                               mcp.rs at startup. Everything else 404s, exactly as
//                               esp_http_server does, so a typo'd POST target
//                               cannot pass a click-through. Answered with the
//                               firmware's own success body where that body is a
//                               fixed literal.
//   GET  /__mock/*              mock-only introspection (state, requests, scenarios)
//
// The response headers for `/`, `/index.html` and `/dashboard/*` are PARSED OUT OF
// dashboard.rs at startup, not hard-coded here — if the firmware's header set
// changes, the mock follows it or refuses to start.
//
// SCENARIOS   mining · ready · standby · thermal-warning · no-sensor · pool-offline
//             safe-mode · restricted-image · first-run · sv2-unavailable
//   Switch live with `?scenario=<name>` on any request (it sticks for later
//   requests too, so the dashboard's own 15 s poll picks it up).
//   Force an endpoint to fail with `?fail=<path>[:status]`, clear with `?fail=`.
//
// TIME RE-BASING (on by default)
//   Fixtures are a frozen capture; the dashboard grades share proofs against a
//   600 s freshness window (dashboard.rs:2259), so verbatim fixtures would always
//   render "stale". Every recognised epoch field is shifted by one constant
//   delta (now - capturedAtUnixMs), which preserves every relative age exactly.
//   Fields shifted: keys ending `UnixMs` / `_unix_ms` / `Unix`, `currentTimestamp`,
//   `updatedAt`, and the `timestamp` column of /api/system/statistics rows.
//   `buildEpoch` is deliberately NOT shifted. `--freeze-time` disables all of it.
//
// LIVE MODE (`--live <ip>`) — READ-ONLY, NOT NEGOTIABLE
//   GET requests are proxied to the device. POST/PATCH/PUT/DELETE are NEVER
//   forwarded: they are answered locally by the mock and logged with
//   `"forwarded": false`. `--allow-writes` is rejected at startup. The campaign's
//   bench unit mines live and every write to it needs per-action operator
//   authorization (root , "Live-Hardware Safety").
//
// HYGIENE (see tools/README.md — these have both bitten this workspace)
//   Kill this server BY PID:  netstat -ano | findstr :<PORT>  ->  taskkill /PID <pid> /F
//   NEVER `taskkill /IM node.exe` or `/IM chrome.exe`.
//   Delete every Chrome profile dir a capture created.

import { createServer, request as httpRequest } from 'node:http';
import { readFileSync, existsSync, appendFileSync, readdirSync, statSync, mkdirSync } from 'node:fs';
import { join, dirname, resolve, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const flag = (n) => process.argv.includes(n);
function arg(name, dflt) {
  const i = process.argv.indexOf(name);
  return i > 0 && process.argv[i + 1] && !process.argv[i + 1].startsWith('--') ? process.argv[i + 1] : dflt;
}

const SRC = resolve(arg('--src', join(HERE, '..', 'dcentaxe', 'src')));
const PORT = parseInt(arg('--port', '8181'), 10);
const HOST = arg('--host', '127.0.0.1');
const FIXTURES = resolve(arg('--fixtures', join(HERE, 'fixtures')));
const LOG = resolve(arg('--log', join(process.cwd(), 'requests.jsonl')));
const LIVE = arg('--live', '');
const FREEZE = flag('--freeze-time');
const WITH_LORA = flag('--lora');

if (flag('--allow-writes')) {
  console.error('REFUSED: --allow-writes is not implemented. The bench device is mining live and\n' +
    'every write to it requires per-action operator authorization (root ,\n' +
    '"Live-Hardware Safety"). --live proxies GET only.');
  process.exit(2);
}

// ── extract the firmware's own bytes + headers out of dashboard.rs ──────────
const DASHBOARD_RS = join(SRC, 'dashboard.rs');
if (!existsSync(DASHBOARD_RS)) { console.error(`no dashboard.rs under --src ${SRC}`); process.exit(2); }
const RS = readFileSync(DASHBOARD_RS, 'utf8');

function fail(what) {
  console.error(`PARSE FAILURE: ${what}\n${DASHBOARD_RS} no longer matches what this mock knows how to\n` +
    'read. Fix the mock rather than letting it serve invented bytes or headers.');
  process.exit(3);
}

// DASHBOARD_HTML: the r##"…"## raw string literal (dashboard.rs:191).
function rawStringConst(name, text) {
  const open = new RegExp(`const\\s+${name}\\s*:\\s*&\\s*'?\\w*\\s*?str\\s*=\\s*r(#*)"`);
  const m = open.exec(text);
  if (!m) return null;
  const start = m.index + m[0].length;
  const close = `"${m[1]}`;
  const end = text.indexOf(close, start);
  if (end < 0) return null;
  return text.slice(start, end);
}
const DASHBOARD_HTML = rawStringConst('DASHBOARD_HTML', RS) ?? fail('could not find the DASHBOARD_HTML r##"…"## literal');

// The `lora` feature appends a second literal to the same response.
let LORA_HTML = '';
if (WITH_LORA) {
  const lp = join(SRC, 'lora_task.rs');
  LORA_HTML = existsSync(lp) ? (rawStringConst('LORA_DASHBOARD_PANEL_HTML', readFileSync(lp, 'utf8')) ?? '') : '';
  if (!LORA_HTML) fail('--lora given but LORA_DASHBOARD_PANEL_HTML was not found in lora_task.rs');
}

// Header tuples, read out of the two handler bodies (never invented here).
function headerPairs(block) {
  const out = [];
  for (const m of block.matchAll(/\(\s*"([A-Za-z0-9-]+)"\s*,\s*("([^"]*)"|content_type)\s*\)/g)) {
    out.push([m[1], m[2] === 'content_type' ? null : m[3]]);
  }
  return out;
}
const staticBlock = RS.slice(RS.indexOf('fn register_static('), RS.indexOf('pub fn register_dashboard('));
if (staticBlock.length < 50) fail('could not isolate register_static()');
const STATIC_HEADERS = headerPairs(staticBlock);
if (!STATIC_HEADERS.some(([k, v]) => k === 'Content-Type' && v === null)) fail('register_static() no longer takes content_type from its argument');
if (!STATIC_HEADERS.some(([k]) => k === 'Cache-Control')) fail('register_static() has no Cache-Control header');

const rootRe = /"\/"\s*,\s*Method::Get/.exec(RS);
const rootStart = rootRe ? rootRe.index : -1;
const rootEnd = rootStart < 0 ? -1 : RS.indexOf('.expect("Failed to register GET /")', rootStart);
if (rootStart < 0 || rootEnd < 0) fail('could not isolate the GET / handler');
const HTML_HEADERS = headerPairs(RS.slice(rootStart, rootEnd));
if (!HTML_HEADERS.length) fail('GET / handler exposes no header tuples');

// The exact asset set register_static() bakes, in registration order, with the
// content-type the firmware picks for each.
const ctVars = {};
for (const m of RS.matchAll(/let\s+(css|js)\s*=\s*"([^"]+)"\s*;/g)) ctVars[m[1]] = m[2];
const BAKED = new Map();
for (const m of RS.matchAll(/register_static\(\s*server,\s*"(\/dashboard\/[^"]+)"\s*,\s*[A-Z_0-9]+\s*,\s*(css|js)\s*,?\s*\)/g)) {
  const ct = ctVars[m[2]];
  if (!ct) fail(`register_static() uses content-type variable "${m[2]}" but its value was not found`);
  BAKED.set(m[1], { file: basename(m[1]), contentType: ct });
}
if (BAKED.size === 0) fail('found no register_static() asset registrations');

// The exact (uri, method) pairs the firmware registers for non-GET traffic,
// read out of api.rs / auth.rs / mcp.rs the same way the asset set is read out
// of dashboard.rs. Round 1 answered EVERY non-GET from a default arm, so
// `POST /api/definitely/not/a/route` came back 200 {"status":"ok"} and a typo'd
// POST target looked green. esp_http_server 404s an unregistered (uri, method),
// and so does this now.
const ROUTE_SOURCES = ['api.rs', 'auth.rs', 'mcp.rs'];
const WRITE_ROUTES = new Map();   // uri -> Set(METHOD)
const READ_ROUTES = new Map();    // uri -> Set(METHOD), informational
for (const f of ROUTE_SOURCES) {
  const p = join(SRC, f);
  if (!existsSync(p)) fail(`route source ${f} is missing from --src ${SRC}`);
  const src = readFileSync(p, 'utf8');
  for (const m of src.matchAll(/fn_handler\(\s*"([^"]+)"\s*,\s*Method::([A-Za-z]+)\s*,/g)) {
    const [uri, method] = [m[1], m[2].toUpperCase()];
    const into = method === 'GET' || method === 'HEAD' ? READ_ROUTES : WRITE_ROUTES;
    if (!into.has(uri)) into.set(uri, new Set());
    into.get(uri).add(method);
  }
}
if (WRITE_ROUTES.size === 0) fail('found no non-GET fn_handler() registrations in api.rs/auth.rs/mcp.rs');
const WRITE_ROUTE_COUNT = [...WRITE_ROUTES.values()].reduce((n, s) => n + s.size, 0);

// ── fixtures ────────────────────────────────────────────────────────────────
const SCENARIOS = existsSync(FIXTURES)
  ? readdirSync(FIXTURES).filter((d) => !d.startsWith('_') && statSync(join(FIXTURES, d)).isDirectory()).sort()
  : [];
if (!SCENARIOS.length) { console.error(`no scenario directories under ${FIXTURES}`); process.exit(2); }
let scenario = arg('--scenario', 'mining');
if (!SCENARIOS.includes(scenario)) { console.error(`unknown scenario "${scenario}". have: ${SCENARIOS.join(', ')}`); process.exit(2); }

const META = existsSync(join(FIXTURES, '_base', 'meta.json'))
  ? JSON.parse(readFileSync(join(FIXTURES, '_base', 'meta.json'), 'utf8')) : {};
const CAPTURED_AT = META.capturedAtUnixMs || 0;

const slug = (apiPath) => apiPath.replace(/^\/api\//, '').replace(/\/+$/, '').replace(/\//g, '_');
function fixtureFor(apiPath, scen) {
  const s = slug(apiPath);
  for (const dir of [scen, '_base']) {
    const p = join(FIXTURES, dir, `${s}.json`);
    if (existsSync(p)) return { path: p, from: dir };
  }
  return null;
}

// Shift every recognised epoch field by one constant delta so relative ages hold.
const EPOCH_MS_KEY = /(UnixMs|_unix_ms)$/;
const EPOCH_S_KEY = /^(updatedAt|ntimeUnix|receivedUnix|started_unix|finished_unix)$|Unix$/;
function rebase(node, dMs) {
  if (Array.isArray(node)) { node.forEach((v) => rebase(v, dMs)); return node; }
  if (node && typeof node === 'object') {
    for (const k of Object.keys(node)) {
      const v = node[k];
      if (typeof v === 'number' && v > 0) {
        if (k === 'buildEpoch') continue;                       // build time: never shifted
        if (k === 'currentTimestamp' || EPOCH_MS_KEY.test(k)) { node[k] = v + dMs; continue; }
        if (EPOCH_S_KEY.test(k)) { node[k] = v + Math.round(dMs / 1000); continue; }
      }
      rebase(v, dMs);
    }
    // /api/system/statistics: rows are positional, the epoch lives in the
    // column named by `labels`.
    if (Array.isArray(node.labels) && Array.isArray(node.statistics)) {
      const ti = node.labels.indexOf('timestamp');
      if (ti >= 0) for (const row of node.statistics) if (typeof row[ti] === 'number' && row[ti] > 0) row[ti] += dMs;
    }
  }
  return node;
}

// ── how big is the page, honestly ───────────────────────────────────────────
// The literal is read off DISK, so its size depends on the checkout's line
// endings: `core.autocrlf = true` gives Windows worktrees CRLF while git stores
// LF, and DASHBOARD_HTML is ~900 lines, so the two differ by ~900 bytes. Worse,
// `String.length` counts UTF-16 code units, not bytes, and the page contains
// multi-byte glyphs. Round 1 printed one bare number, which invited exactly the
// wrong reading.
//
// NONE of these three is an image-size budget number. The firmware's cost is
// the LF bytes git stores, compiled into a `&str` and then linked, measured by
// `espflash save-image` — see tools/README.md.
function htmlSize() {
  const lf = DASHBOARD_HTML.replace(/\r\n/g, '\n');
  return {
    chars: DASHBOARD_HTML.length,
    bytesAsServed: Buffer.byteLength(DASHBOARD_HTML, 'utf8'),
    bytesLfNormalised: Buffer.byteLength(lf, 'utf8'),
    lineEndings: DASHBOARD_HTML.includes('\r\n') ? 'CRLF (this checkout)' : 'LF',
    note: 'not an image-size budget number — measure with espflash save-image',
  };
}

// ── history replay (--replay-history), default OFF ──────────────────────────
// SUPERSEDED IN PART by lane P1-W6 (2026-09-03): the dashboard now DOES read
// /api/system/statistics — `seedChart()` fetches it on boot and after every
// reconnect — so a fresh load already shows the device's own ~60-minute history
// and this flag is no longer needed just to get a non-empty panel. What is still
// true: `update(d)` appends one client point per poll on top of the seed, and
// `drawChart()` draws nothing until two points exist.
//
// The flag remains useful for one thing it still does uniquely: making
// /api/system/info's LIVE telemetry (hashrate/power/temp) walk the captured
// history, so the hero, stat tiles and sparklines move over a capture instead of
// repeating one frozen frame.
//
// With --replay-history each successive /api/system/info walks the NEXT row of
// the device's own captured 60-row /api/system/statistics history, overriding
// exactly four telemetry fields with values the bench unit really reported.
// This is a REPLAY of measured data, not synthesis: no value is invented, the
// order is the order it was recorded in, and the response is tagged
// `X-Mock-Replay: <row>/<total>` so an artifact taken this way is identifiable.
// The last row is held once the history is exhausted.
const REPLAY = flag('--replay-history');
const REPLAY_FIELDS = { hashrate: ['hashRate', 'hashRate_1m'], power: ['power'], asicTemp: ['temp'] };
let replayIdx = -1;
const REPLAY_ROWS = (() => {
  const p = join(FIXTURES, '_base', 'system_statistics.json');
  if (!existsSync(p)) return [];
  const j = JSON.parse(readFileSync(p, 'utf8'));
  if (!Array.isArray(j.labels) || !Array.isArray(j.statistics)) return [];
  const col = {};
  for (const k of Object.keys(REPLAY_FIELDS)) col[k] = j.labels.indexOf(k);
  return j.statistics.map((row) => {
    const o = {};
    for (const [k, i] of Object.entries(col)) if (i >= 0 && typeof row[i] === 'number') o[k] = row[i];
    return o;
  });
})();
if (REPLAY && !REPLAY_ROWS.length) fail('--replay-history given but _base/system_statistics.json has no usable rows');

function applyReplay(data) {
  if (!REPLAY || !REPLAY_ROWS.length) return null;
  replayIdx = Math.min(replayIdx + 1, REPLAY_ROWS.length - 1);
  const row = REPLAY_ROWS[replayIdx];
  for (const [src, dsts] of Object.entries(REPLAY_FIELDS)) {
    if (typeof row[src] !== 'number') continue;
    for (const d of dsts) data[d] = row[src];
  }
  return `${replayIdx + 1}/${REPLAY_ROWS.length}`;
}

// ── request-scoped mock control ─────────────────────────────────────────────
const failures = new Map();  // path -> status
function applyControls(url) {
  const q = url.searchParams;
  if (q.has('scenario')) {
    const want = q.get('scenario');
    if (SCENARIOS.includes(want)) { if (want !== scenario) console.log(`scenario -> ${want}`); scenario = want; }
    else console.log(`ignored unknown ?scenario=${want}`);
  }
  if (q.has('fail')) {
    const spec = q.get('fail');
    if (!spec) { failures.clear(); console.log('cleared forced failures'); }
    else {
      const [p, st] = spec.split(':');
      failures.set(p.startsWith('/') ? p : `/${p}`, parseInt(st || '500', 10));
      console.log(`forced failure ${p} -> ${st || 500}`);
    }
  }
}

// ── request log ─────────────────────────────────────────────────────────────
mkdirSync(dirname(LOG), { recursive: true });
function logRequest(entry) {
  try { appendFileSync(LOG, JSON.stringify(entry) + '\n', 'utf8'); } catch (e) { console.error('log write failed', e.message); }
}

// ── POST/DELETE table ───────────────────────────────────────────────────────
// Bodies marked `firmware` are the exact literals the firmware writes; bodies
// marked `mock` are this server's own stand-in (the real handler builds them at
// runtime from device state we do not have).
const WRITE_RESPONSES = [
  [/^\/api\/mining\/stop$/,               200, '{"status":"stopped"}',                              'firmware api.rs:4719'],
  [/^\/api\/mining\/start$/,              200, '{"status":"started"}',                              'firmware api.rs:4743'],
  [/^\/api\/mining\/autotune$/,           200, '{"success":true}',                                  'firmware api.rs:3299'],
  [/^\/api\/system\/restart$/,            200, '{"message":"System will restart shortly."}',        'firmware api.rs:3518'],
  [/^\/api\/system\/clear-safe-mode$/,    200, '{"message":"Safe mode cleared. Rebooting."}',       'firmware api.rs:3801'],
  [/^\/api\/swarm\/config$/,              200, '{"status":"ok","roomTempSource":"local"}',          'firmware api.rs:4962'],
  [/^\/api\/system\/OTA$/,                200, '{"success":true,"message":"Upload accepted; boot proof pending."}', 'mock'],
  [/^\/api\/auth\/(setup|session|password)$/, 200,
    '{"status":"ok","passwordSet":true,"session":{"id":"mock-session","token":"mock-bearer-token","expiresAt":0}}', 'firmware auth.rs:578,697,768 shape'],
  [/^\/api\/auth\/session\/current$/,     200, '{"status":"ok"}',                                   'mock'],
  [/^\/api\/auth\/owner-reset$/,          200, '{"status":"ok"}',                                   'mock'],
  [/^\/api\/system\/self-test\/(run|cancel)$/, 200, '{"status":"ok"}',                              'mock'],
  [/^\/api\/system\/coredump$/,           200, '{"status":"ok"}',                                   'mock'],
];
function writeResponse(path) {
  for (const [re, status, body, prov] of WRITE_RESPONSES) if (re.test(path)) return { status, body, prov };
  return { status: 200, body: '{"status":"ok"}', prov: 'mock default' };
}

// Is this (method, uri) pair one the firmware actually registers? Anything else
// must 404, exactly as esp_http_server does for an unregistered URI — a mock
// that answers 200 to a route the device has never heard of is worse than no
// mock, because a typo'd POST target then passes a click-through.
function writeRouteAllowed(method, path) {
  const methods = WRITE_ROUTES.get(path);
  return !!methods && methods.has(method.toUpperCase());
}

// ── live proxy (GET only) ───────────────────────────────────────────────────
function proxyGet(path, headers) {
  return new Promise((resolve_) => {
    const r = httpRequest({ host: LIVE, port: 80, path, method: 'GET', headers: { 'X-Requested-With': 'XMLHttpRequest', ...headers } }, (up) => {
      const chunks = [];
      up.on('data', (c) => chunks.push(c));
      up.on('end', () => resolve_({ status: up.statusCode || 502, headers: up.headers, body: Buffer.concat(chunks) }));
    });
    r.setTimeout(8000, () => { r.destroy(); resolve_(null); });
    r.on('error', () => resolve_(null));
    r.end();
  });
}

// ── server ──────────────────────────────────────────────────────────────────
function send(res, status, headers, body, extra = {}) {
  const h = {};
  for (const [k, v] of headers) if (v !== null) h[k] = v;
  Object.assign(h, { 'X-Mock-Server': 'axe_mock_server.mjs', 'X-Mock-Scenario': scenario }, extra);
  res.writeHead(status, h);
  res.end(body);
}

const srv = createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;
  applyControls(url);

  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', async () => {
    const raw = Buffer.concat(chunks);
    let status = 200;
    let logBody = null;
    if (raw.length) {
      // An OTA upload is a raw firmware image; log its size, not its bytes.
      let binary = false;
      for (let k = 0; k < Math.min(raw.length, 512); k++) {
        const b = raw[k];
        if (b === 0 || b < 0x09 || (b > 0x0d && b < 0x20)) { binary = true; break; }
      }
      logBody = binary ? `<binary ${raw.length} bytes>` : raw.toString('utf8').slice(0, 4096);
    }
    let forwarded = false;
    let note = '';

    try {
      // ── mock-only introspection ─────────────────────────────────────────
      if (path.startsWith('/__mock/')) {
        let body = '{}';
        if (path === '/__mock/state') {
          body = JSON.stringify({
            scenario, scenarios: SCENARIOS, fixtures: FIXTURES, src: SRC, log: LOG,
            live: LIVE || null, freezeTime: FREEZE, lora: WITH_LORA,
            replayHistory: REPLAY ? { rows: REPLAY_ROWS.length, served: replayIdx + 1,
              source: '_base/system_statistics.json (device capture, replayed not synthesized)' } : false,
            capturedAtUnixMs: CAPTURED_AT, forcedFailures: [...failures.entries()],
            bakedAssets: [...BAKED.keys()],
            writeRoutes: Object.fromEntries([...WRITE_ROUTES].map(([u, m]) => [u, [...m].sort()])),
            // Three different numbers, none of them an image-size budget. See
            // htmlSize() and tools/README.md "The HTML byte count is not a budget".
            html: htmlSize(),
          }, null, 1);
        } else if (path === '/__mock/requests') {
          body = existsSync(LOG) ? readFileSync(LOG, 'utf8') : '';
        } else { status = 404; body = '{"error":"unknown mock route"}'; }
        send(res, status, [['Content-Type', 'application/json']], body);
        return;
      }

      // ── writes: never forwarded, always logged ──────────────────────────
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        // Unregistered (method, uri) -> 404, like esp_http_server.
        if (!writeRouteAllowed(req.method, path)) {
          status = 404;
          const known = WRITE_ROUTES.has(path)
            ? `the firmware registers ${path} for ${[...WRITE_ROUTES.get(path)].sort().join('/')}, not ${req.method}`
            : `no fn_handler() in api.rs/auth.rs/mcp.rs registers ${path} for any write method`;
          note = `unregistered-write: ${known}`;
          send(res, 404, [['Content-Type', 'application/json']],
            JSON.stringify({ error: 'no such route', detail: known }));
          return;
        }
        // CORS preflight: the firmware answers 200 with COMPAT_HEADERS and an
        // empty body (api.rs:2296) — not the JSON success shape.
        if (req.method === 'OPTIONS') {
          note = 'firmware api.rs COMPAT_HEADERS preflight';
          send(res, 200, [['Content-Type', 'application/json']], '');
          return;
        }
        const r = writeResponse(path);
        const forced = failures.get(path);
        status = forced || r.status;
        const body = forced
          ? JSON.stringify({ error: 'forced mock failure', detail: `?fail=${path}` })
          : r.body;
        note = forced ? 'forced-failure' : r.prov;
        send(res, status, [['Content-Type', 'application/json']], body);
        return;
      }

      // ── GET / and /index.html ──────────────────────────────────────────
      if (path === '/' || path === '/index.html') {
        if (LIVE) {
          const up = await proxyGet(path, {});
          if (up) { forwarded = true; status = up.status; res.writeHead(status, { ...up.headers, 'X-Mock-Scenario': 'live', 'X-Mock-Proxied': LIVE }); res.end(up.body); return; }
          note = 'live proxy failed, served local literal';
        }
        send(res, 200, HTML_HEADERS, DASHBOARD_HTML + LORA_HTML);
        return;
      }

      // ── GET /dashboard/<file> ──────────────────────────────────────────
      if (path.startsWith('/dashboard/')) {
        const baked = BAKED.get(path);
        if (!baked) {
          // Present on disk but not include_str!'d: the firmware 404s it too.
          status = 404; note = existsSync(join(SRC, 'dashboard', basename(path))) ? 'on disk but not baked' : 'no such asset';
          send(res, 404, [['Content-Type', 'text/plain; charset=utf-8']], `404 ${path} is not baked into the firmware image\n`);
          return;
        }
        const file = join(SRC, 'dashboard', baked.file);
        if (!existsSync(file)) { status = 500; send(res, 500, [['Content-Type', 'text/plain']], `include_str! source missing: ${file}\n`); return; }
        send(res, 200, STATIC_HEADERS.map(([k, v]) => [k, k === 'Content-Type' ? baked.contentType : v]), readFileSync(file));
        return;
      }

      // ── GET /api/* ─────────────────────────────────────────────────────
      if (path.startsWith('/api/')) {
        const forced = failures.get(path);
        if (forced) {
          status = forced; note = 'forced-failure';
          send(res, forced, [['Content-Type', 'application/json']], JSON.stringify({ error: 'forced mock failure', detail: `?fail=${path}` }));
          return;
        }
        if (LIVE) {
          const up = await proxyGet(path + url.search, {});
          if (up) { forwarded = true; status = up.status; res.writeHead(status, { ...up.headers, 'X-Mock-Scenario': 'live', 'X-Mock-Proxied': LIVE }); res.end(up.body); return; }
          note = 'live proxy failed, served fixture';
        }
        const fx = fixtureFor(path, scenario);
        if (!fx) {
          status = 404; note = 'no fixture';
          send(res, 404, [['Content-Type', 'application/json']], JSON.stringify({ error: 'no fixture', detail: `${slug(path)}.json not found in ${scenario}/ or _base/` }));
          return;
        }
        let data = JSON.parse(readFileSync(fx.path, 'utf8'));
        if (!FREEZE && CAPTURED_AT) data = rebase(data, Date.now() - CAPTURED_AT);
        note = `fixture:${fx.from}`;
        const extra = { 'X-Mock-Fixture': `${fx.from}/${slug(path)}.json` };
        if (path === '/api/system/info') {
          const rp = applyReplay(data);
          if (rp) { extra['X-Mock-Replay'] = rp; note += ` replay:${rp}`; }
        }
        send(res, 200, [['Content-Type', 'application/json']], JSON.stringify(data), extra);
        return;
      }

      status = 404; note = 'unrouted';
      send(res, 404, [['Content-Type', 'text/plain; charset=utf-8']], `404 ${path}\n`);
    } catch (e) {
      status = 500; note = `mock error: ${e.message}`;
      try { send(res, 500, [['Content-Type', 'application/json']], JSON.stringify({ error: 'mock server error', detail: e.message })); } catch { /* headers already sent */ }
    } finally {
      logRequest({
        ts: new Date().toISOString(), method: req.method, path, query: url.search || '',
        scenario, status, forwarded, note,
        contentType: req.headers['content-type'] || null,
        bodyBytes: raw.length, body: logBody,
      });
    }
  });
});

srv.listen(PORT, HOST, () => {
  console.log(`axe_mock_server  http://${HOST}:${PORT}/   pid ${process.pid}`);
  console.log(`  src        ${SRC}`);
  const hs = htmlSize();
  console.log(`  html       ${hs.bytesAsServed} bytes as served [${hs.lineEndings}] · ` +
    `${hs.bytesLfNormalised} bytes LF-normalised · ${hs.chars} UTF-16 chars` +
    `${WITH_LORA ? ` (+ ${Buffer.byteLength(LORA_HTML, 'utf8')} lora bytes)` : ''}`);
  console.log('             ^ NOT an image-size budget number (line-ending dependent; ' +
    'the firmware cost is the LF bytes, measured by espflash save-image)');
  console.log(`  assets     ${BAKED.size} baked: ${[...BAKED.keys()].map((k) => basename(k)).join(' ')}`);
  console.log(`  writes     ${WRITE_ROUTE_COUNT} registered (method, uri) pairs from ${ROUTE_SOURCES.join(' + ')}; everything else 404s`);
  console.log(`  html hdrs  ${HTML_HEADERS.map(([k, v]) => `${k}: ${v}`).join(' | ')}`);
  console.log(`  asset hdrs ${STATIC_HEADERS.map(([k, v]) => `${k}: ${v === null ? '<per-asset>' : v}`).join(' | ')}`);
  console.log(`  scenario   ${scenario}   (of ${SCENARIOS.join(', ')})`);
  console.log(`  fixtures   ${FIXTURES}${FREEZE ? '  [time frozen]' : `  [time re-based from ${META.capturedAtIso || 'unknown'}]`}`);
  if (REPLAY) console.log(`  replay     ${REPLAY_ROWS.length} rows of the device's OWN recorded history feed /api/system/info (hashRate, hashRate_1m, power, temp)`);
  console.log(`  log        ${LOG}`);
  if (LIVE) console.log(`  LIVE       GET -> http://${LIVE}/   (writes are never forwarded)`);
  console.log(`  stop with  netstat -ano | findstr :${PORT}   ->   taskkill /PID <pid> /F     (never /IM node.exe)`);
});
srv.on('error', (e) => { console.error(`listen failed: ${e.message}`); process.exit(1); });
