#!/usr/bin/env node
// DCENT_axe UI Gauntlet — fixture builder (lane P1-I1).
//
// Reads a READ-ONLY capture of the bench device's GET endpoints and writes the
// scrubbed, scenario-split fixture tree consumed by axe_mock_server.mjs.
//
//   node _build_fixtures.mjs --raw <dir-with-raw-capture> [--out <fixtures-dir>]
//                            [--scrub <raw>/scrub-map.json]
//
// The raw capture is produced with GETs only (never POST/PATCH/DELETE) and stays
// in the gitignored evidence root; only the scrubbed output of this script is
// meant to live in the repo. The literal identifiers being removed live in
// `scrub-map.json` NEXT TO THE RAW CAPTURE, never in this file — writing them
// here would put the very strings the scrub exists to remove back in the repo.
//
// SCRUB CONTRACT — every rule is applied to the serialized JSON text of every
// endpoint, so nested copies (swarm nodeId, discovery apiUrl/mcpUrl, mDNS
// hostname, shared-config network block) are covered too:
//   Wi-Fi SSID .......... -> "MOCK-WIFI-SSID"
//   MAC (colon form) .... -> "02:00:00:00:00:01"
//   MAC (packed form) ... -> "020000000001"    (swarm/local node ids)
//   Hostname ............ -> "dcentaxe-mock"
//   LAN IPv4 ............ -> "192.0.2.42"      (RFC 5737 TEST-NET-1)
//   Pool worker/wallet .. -> "bc1pMOCK…MOCK"
//   Donation worker ..... -> "MOCK_WORKER"
//   Coinbase scriptHex .. -> deadbeef… of the same length, opcode/prefix bytes
//                          preserved so block-tile.js's scriptHexToAddress()
//                          still decodes a well-formed (and obviously fake)
//                          address.
//
// Nothing else is rewritten: pool hostnames, firmware version, git hash, board
// ids, block header fields and public chain data are left exactly as measured.

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));

function arg(name, dflt) {
  const i = process.argv.indexOf(name);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : dflt;
}
const RAW = arg('--raw', join(HERE, '..', '..', '..', '.axe-gauntlet', 'pass1', 'P1-I1', 'raw-capture'));
const OUT = arg('--out', HERE);

const ENDPOINTS = [
  'system_info', 'system', 'pools', 'presets', 'autotuner_modes', 'schedule',
  'achievements', 'swarm', 'auth_status', 'mining_block', 'system_statistics',
  'config_shared', 'system_self-test_status',
];

// ── scrub ───────────────────────────────────────────────────────────────────
// The from -> to pairs live with the raw capture (gitignored), not here.
const SCRUB_MAP = arg('--scrub', join(RAW, 'scrub-map.json'));
if (!existsSync(SCRUB_MAP)) {
  console.error(`missing scrub map: ${SCRUB_MAP}\n` +
    'It must be a { "rules": [[from, to], ...] } JSON file living beside the raw\n' +
    'capture in the gitignored evidence root. Refusing to write unscrubbed fixtures.');
  process.exit(1);
}
const TEXT_RULES = JSON.parse(readFileSync(SCRUB_MAP, 'utf8')).rules;
if (!Array.isArray(TEXT_RULES) || !TEXT_RULES.length) { console.error('scrub map has no rules'); process.exit(1); }

// Coinbase output scripts carry real wallet scriptPubKeys. Keep the opcode
// prefix (so the type is still P2TR / P2WPKH / OP_RETURN) and replace only the
// payload with a repeating 0xdeadbeef pattern of identical length.
const SCRIPT_PREFIXES = ['5120', '0014', '6a24aa21a9ed', '76a914', 'a914', '0020'];
function scrubScriptHex(hex) {
  const h = String(hex || '').toLowerCase();
  for (const p of SCRIPT_PREFIXES) {
    if (h.startsWith(p) && h.length > p.length) {
      const n = h.length - p.length;
      return p + 'deadbeef'.repeat(Math.ceil(n / 8)).slice(0, n);
    }
  }
  return h ? 'deadbeef'.repeat(Math.ceil(h.length / 8)).slice(0, h.length) : h;
}
function walkScripts(node) {
  if (Array.isArray(node)) { node.forEach(walkScripts); return; }
  if (node && typeof node === 'object') {
    for (const k of Object.keys(node)) {
      if ((k === 'scriptHex' || k === 'script') && typeof node[k] === 'string') node[k] = scrubScriptHex(node[k]);
      else walkScripts(node[k]);
    }
  }
}
function scrub(obj) {
  let text = JSON.stringify(obj);
  for (const [from, to] of TEXT_RULES) text = text.split(from).join(to);
  const out = JSON.parse(text);
  walkScripts(out);
  return out;
}

// ── load + scrub the base set ───────────────────────────────────────────────
const base = {};
for (const name of ENDPOINTS) {
  const p = join(RAW, `${name}.json`);
  if (!existsSync(p)) { console.error(`missing raw capture: ${p}`); process.exit(1); }
  base[name] = scrub(JSON.parse(readFileSync(p, 'utf8')));
}

const CAPTURED_AT = base.system_statistics.currentTimestamp;
if (!Number.isFinite(CAPTURED_AT)) { console.error('no currentTimestamp in statistics capture'); process.exit(1); }

const clone = (o) => JSON.parse(JSON.stringify(o));

// Zero the hashrate/power columns of the trailing statistics rows so a
// ready/standby scenario's chart matches its headline numbers.
function flattenStats(stats, rows) {
  const s = clone(stats);
  const idx = {};
  s.labels.forEach((l, i) => { idx[l] = i; });
  const from = Math.max(0, s.statistics.length - rows);
  for (let r = from; r < s.statistics.length; r++) {
    for (const l of ['hashrate', 'hashrate_15s', 'hashrate_30s']) if (idx[l] != null) s.statistics[r][idx[l]] = 0;
    if (idx.power != null) s.statistics[r][idx.power] = 12.5;
  }
  return s;
}

function idle(info) {
  info.hashRate = 0;
  for (const k of ['hashRate_1m', 'hashRate_5m', 'hashRate_10m', 'hashRate_15m']) info[k] = 0;
  info.hashRate_1h = null;
  info.efficiency = null;
  info.power = 12.5;
  info.current = 1074.2;
  info.errorPercentage = 0;
  if (info.dcentaxe) {
    info.dcentaxe.autotuner.hashrate15s = 0;
    info.dcentaxe.autotuner.hashrate30s = 0;
    info.dcentaxe.dispatcher.noncesFound = 0;
    if (info.dcentaxe.dcentSwarm) info.dcentaxe.dcentSwarm = info.dcentaxe.dcentSwarm;
  }
  if (info.dcentSwarm && info.dcentSwarm.home) {
    info.dcentSwarm.home.heatWatts = 12.5;
    info.dcentSwarm.home.heatBtuH = 42.6;
    info.dcentSwarm.home.heatingActive = false;
  }
  return info;
}

// ── scenarios ───────────────────────────────────────────────────────────────
// Each entry returns the endpoint files that DIFFER from `_base/`.
// `system_info.json` is written in full for every scenario (it drives nearly the
// whole UI, so a reader never has to diff two files to know what a scenario is).
const SCENARIOS = {
  // Exactly what the bench device reported: enabled + hashing + pool connected.
  mining: () => ({ system_info: clone(base.system_info) }),

  // Permitted but producing nothing yet (chips idle, pool still up).
  ready: () => {
    const i = idle(clone(base.system_info));
    i.dcentaxe.miningEnabled = true;
    return { system_info: i, system_statistics: flattenStats(base.system_statistics, 12) };
  },

  // Operator paused mining.
  standby: () => {
    const i = idle(clone(base.system_info));
    i.dcentaxe.miningEnabled = false;
    return { system_info: i, system_statistics: flattenStats(base.system_statistics, 12) };
  },

  // Still mining, but hot enough that the health tile must say HOT (`ct>90`,
  // dashboard.rs:2290).
  'thermal-warning': () => {
    const i = clone(base.system_info);
    i.temp = 92.5; i.temp2 = 91.0; i.vrTemp = 105.5;
    i.fanspeed = 100; i.manualFanSpeed = 100; i.fanrpm = 5980; i.fan2rpm = 5960;
    i.dcentaxe.boardTemp = 91.0; i.dcentaxe.inletTemp = 92.5; i.dcentaxe.outletTemp = 91.0;
    return { system_info: i };
  },

  // sensorsOk=false, and tempSource OMITTED — api.rs:1605 emits None (skipped)
  // when the sensors did not read, so the fixture must not carry the key.
  'no-sensor': () => {
    const i = clone(base.system_info);
    i.sensorsOk = false;
    i.temp = 0; i.temp2 = 0; i.vrTemp = 0;
    i.fanrpm = 0; i.fan2rpm = 0;
    delete i.dcentaxe.tempSource;
    i.dcentaxe.boardTemp = null; i.dcentaxe.inletTemp = null; i.dcentaxe.outletTemp = null;
    return { system_info: i };
  },

  // Chips hashing, pool gone: submissions pending, last accepted proof stale.
  'pool-offline': () => {
    const i = clone(base.system_info);
    i.poolConnected = false;
    i.responseTime = 0;
    i.acceptanceRateKnown = false;
    const pt = i.dcentaxe.poolTruth;
    pt.connected = false;
    pt.responseTimeMs = 0;
    pt.sharesPending = 4;
    pt.sharesUnresolved = 4;
    pt.oldestPendingSubmitAgeMs = 186000;
    pt.lastShareAcceptedUnixMs = CAPTURED_AT - 900000;   // > the 600 s freshness window
    pt.lastShareResponseUnixMs = CAPTURED_AT - 900000;
    pt.lastShareSubmitUnixMs = CAPTURED_AT - 186000;
    pt.recentEvents = [
      { tsUnixMs: CAPTURED_AT - 186000, kind: 'share_submitted', detail: 'job=6a72bdc0000157c1 diff=4104.2' },
      { tsUnixMs: CAPTURED_AT - 180000, kind: 'pool_disconnected', detail: 'solo.ckpool.org:3333 read timeout' },
    ];
    const pools = clone(base.pools);
    if (pools[0]) {
      pools[0].connected = false;
      pools[0].authorized = false;
      pools[0].oldest_pending_submit_age_ms = 186000;
      pools[0].last_share_accepted_unix_ms = CAPTURED_AT - 900000;
      pools[0].last_reject_reason = '';
    }
    return { system_info: i, pools };
  },

  // Task watchdog tripped: safe mode, mining refused, coredump waiting.
  'safe-mode': () => {
    const i = idle(clone(base.system_info));
    i.safeMode = true;
    i.wdtResetCount = 5;
    i.resetReason = 'Task watchdog';
    i.coredumpPresent = true;
    i.dcentaxe.miningEnabled = false;
    i.uptime = 214; i.uptimeSeconds = 214;
    return { system_info: i };
  },

  // A lab-only / identity-only image: the deployment banner must fire
  // (dashboard.rs:2485).
  'restricted-image': () => {
    const i = idle(clone(base.system_info));
    i.dcentaxe.miningEnabled = false;
    Object.assign(i.dcentaxe.deployment, {
      hardwareFamily: 'bitaxe',
      releaseScope: 'internal',
      supportTier: 'unsupported',
      evidenceLevel: 'none',
      runtimeMode: 'identity-only',
      installPolicy: 'lab-only',
      packagePolicy: 'internal',
      flashLayout: 'standard',
      productionBlockers: ['identity-only-image', 'no-mining-runtime', 'unsigned-ota'],
    });
    return { system_info: i };
  },

  // Fresh flash: no pool configured, no history, egg-stage companion. This is
  // the state the first-run wizard's heuristic keys off (an empty #pUrl, fed by
  // loadCfg() -> GET /api/system).
  'first-run': () => {
    const i = idle(clone(base.system_info));
    i.stratumURL = ''; i.stratumPort = 0; i.stratumUser = '';
    i.poolConnectionInfo = ''; i.poolConnected = false; i.poolDifficulty = 0;
    i.sharesAccepted = 0; i.sharesRejected = 0; i.acceptanceRate = 0; i.acceptanceRateKnown = false;
    i.bestDiff = 0; i.bestSessionDiff = 0; i.bestEverDiff = 0;
    i.uptime = 96; i.uptimeSeconds = 96;
    i.responseTime = 0;
    i.dcentaxe.achievements = 0; i.dcentaxe.achievementCount = 0; i.dcentaxe.lifetimeShares = 0;
    i.dcentaxe.creatureStage = 'Egg'; i.dcentaxe.creatureMood = 5;
    Object.assign(i.dcentaxe.poolTruth, {
      connected: false, difficulty: 0, sharesSubmitted: 0, sharesAccepted: 0, sharesRejected: 0,
      sharesPending: 0, sharesUnresolved: 0, oldestPendingSubmitAgeMs: 0, responseTimeMs: 0,
      lastShareSubmitUnixMs: 0, lastShareResponseUnixMs: 0, lastShareAcceptedUnixMs: 0,
      lastShareRejectedUnixMs: 0, lastRejectReason: '', activePool: '',
      rejectReasonCounts: [], recentEvents: [],
    });
    i.dcentaxe.dispatcher.noncesFound = 0;
    i.dcentaxe.dispatcher.ticketDifficulty = 0;
    const sys = clone(base.system);
    sys.stratumURL = ''; sys.stratumPort = 0; sys.stratumUser = ''; sys.stratumPassword = '';
    return { system_info: i, system: sys, pools: [] };
  },

  // The build has no stratum-v2 feature (stratumV2Available=false, exactly as the
  // bench device reports) WHILE the stored config still asks for v2 — the conflict
  // the V2 option gate at dashboard.rs:2429-2436 has to render honestly.
  'sv2-unavailable': () => {
    const i = clone(base.system_info);
    i.stratumV2Available = false;
    i.stratumProtocol = 'v2';
    i.stratumV2Status = 'not included in this firmware build';
    i.dcentaxe.poolTruth.protocol = 'stratum-v2';
    const sys = clone(base.system);
    sys.stratumProtocol = 'v2';
    sys.fallbackStratumProtocol = 'v2';
    sys.stratumV2Available = false;
    sys.stratumV2Status = 'not included in this firmware build';
    return { system_info: i, system: sys };
  },
};

// ── write ───────────────────────────────────────────────────────────────────
function writeJson(dir, name, value) {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, `${name}.json`), JSON.stringify(value, null, 1) + '\n', { encoding: 'utf8' });
}

const baseDir = join(OUT, '_base');
for (const name of ENDPOINTS) writeJson(baseDir, name, base[name]);
writeJson(baseDir, 'meta', {
  capturedAtUnixMs: CAPTURED_AT,
  capturedAtIso: new Date(CAPTURED_AT).toISOString(),
  capturedFrom: 'bench BitAxe Hex Supra (board 702, 6x BM1368) — READ-ONLY GETs, 2026-09-03',
  firmware: `${base.system_info.firmwareType} ${base.system_info.version} (${base.system_info.gitHash})`,
  endpoints: ENDPOINTS,
  // Only the REPLACEMENTS are listed. Writing the originals here would put the
  // very strings the scrub removed back into the committed fixture tree.
  scrubbed: [
    'wifi ssid -> "MOCK-WIFI-SSID"',
    'mac address (colon + packed forms) -> "02:00:00:00:00:01" / "020000000001"',
    'hostname / mdns hostname -> "dcentaxe-mock"',
    'lan ipv4 (incl. swarm apiUrl/mcpUrl) -> "192.0.2.42" (RFC 5737 TEST-NET-1)',
    'pool worker / wallet -> "bc1pMOCK…MOCK"',
    'donation worker -> "MOCK_WORKER"',
    'coinbase scriptHex payloads -> deadbeef pattern (script-type prefix kept)',
  ],
  note: 'Time-valued fields are re-based to wall clock by axe_mock_server.mjs; run it with --freeze-time to serve these bytes verbatim.',
});

let count = 0;
for (const [name, build] of Object.entries(SCENARIOS)) {
  const files = build();
  const dir = join(OUT, name);
  for (const [ep, value] of Object.entries(files)) { writeJson(dir, ep, value); count++; }
  console.log(`${name.padEnd(18)} ${Object.keys(files).join(', ')}`);
}
console.log(`\nwrote ${ENDPOINTS.length + 1} base files + ${count} scenario overrides into ${OUT}`);
