// axeos_bar_server.mjs — serves the BUILT AxeOS (ESP-Miner) Angular app against a
// synthesized fixture, so the DCENT_axe UI Gauntlet can render "the bar" side by side
// with our own dashboard at the same four viewports.
//
// Campaign: dcentaxe-ui-gauntlet-20260903, lane P1-I5 (bar refresh + baseline captures).
// Bar pin: ESP-Miner v2.15.1 = 78a03e3b5e7600aa8691a7c319ccb4efce72719b (2026-08-29).
//
// This is DELIBERATELY a separate file from lane P1-I1's `axe_mock_server.mjs` (which
// serves OUR dashboard out of `dashboard.rs`). P1-I1 had not landed when this lane ran,
// so rather than half-write another lane's deliverable and collide at merge, the AxeOS
// side lives here. If/when P1-I1 lands, fold this in as its `--axeos` mode; the fixture
// below is the payload to reuse.
//
// The fixture is SYNTHESIZED from the v2.15.1 API contract
// (`main/http_server/axe-os/src/app/generated/models/system-info.ts`, 114 top-level
// fields) shaped to look like the campaign's bench device (BitAxe Hex Supra, board 702,
// 6x BM1368). It is NOT a capture from a real AxeOS device — no AxeOS unit was contacted.
// Values are plausible and internally consistent; they are not measurements.
//
// Node stdlib only (http, fs, path, crypto). No dependencies.
//
// usage:
//   node axeos_bar_server.mjs --dist <path-to-dist/axe-os> [--port 8199] [--scenario mining]
//
// Kill it by PID (netstat -ano | findstr :<port>), never by image name.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { readFileSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';

const argv = process.argv.slice(2);
const arg = (name, dflt) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
};

const DIST = path.resolve(arg('--dist', './dist/axe-os'));
const PORT = Number(arg('--port', '8199'));
const SCENARIO = arg('--scenario', 'mining');

if (!existsSync(DIST)) {
  console.error(`dist not found: ${DIST}`);
  console.error('build it first: cd main/http_server/axe-os && npm ci && npx ng build --configuration=production');
  process.exit(2);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
  '.pdf': 'application/pdf',
};

// ---------------------------------------------------------------- fixture ----

// Deterministic pseudo-noise so repeated captures are byte-comparable.
let tick = 0;
const wobble = (base, amp, phase = 0) => +(base + amp * Math.sin((tick + phase) / 7)).toFixed(2);

const POOLS = [
  {
    id: 0,
    stratumURL: 'public-pool.io',
    stratumPort: 21496,
    stratumUser: 'bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.bitaxe-hex',
    stratumPassword: 'x',
    stratumProtocol: 'SV1',
    stratumTLS: 0,
    stratumCert: '',
    stratumSuggestedDifficulty: 1000,
    stratumExtranonceSubscribe: true,
    stratumDecodeCoinbase: true,
  },
  {
    id: 1,
    stratumURL: 'solo.ckpool.org',
    stratumPort: 3333,
    stratumUser: 'bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    stratumPassword: 'x',
    stratumProtocol: 'SV1',
    stratumTLS: 0,
    stratumCert: '',
    stratumSuggestedDifficulty: 0,
    stratumExtranonceSubscribe: false,
    stratumDecodeCoinbase: true,
  },
];

const SCENARIOS = {
  mining: { hashRate: 3120.4, miningPaused: false, sharesAccepted: 18422, overheat_mode: 0 },
  paused: { hashRate: 0, miningPaused: true, sharesAccepted: 18422, overheat_mode: 0 },
  overheat: { hashRate: 0, miningPaused: true, sharesAccepted: 18422, overheat_mode: 1 },
};
const S = SCENARIOS[SCENARIO] ?? SCENARIOS.mining;

function systemInfo() {
  return {
    ASICModel: 'BM1368',
    actualFrequency: 490,
    apEnabled: 0,
    autofanspeed: 1,
    axeOSVersion: 'v2.15.1',
    bestDiff: 41200000,
    bestSessionDiff: 2870000,
    blockFound: 0,
    blockHeight: 918442,
    blockSignals: ['BIP-110'],
    boardVersion: '702',
    coinbaseOutputs: [
      { value: 312500000, address: 'bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' },
      { value: 18420000, address: 'bc1qyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy' },
    ],
    coinbaseValueTotalSatoshis: 330920000,
    coinbaseValueUserSatoshis: 312500000,
    coreVoltage: 1200,
    coreVoltageActual: 1198,
    cpuUsage: wobble(21, 4),
    current: wobble(6420, 120),
    display: 'SSD1306 (128x32)',
    displayTimeout: 0,
    errorPercentage: wobble(0.42, 0.15),
    expectedHashrate: 3240,
    fallbackStratumCert: '',
    fallbackStratumDecodeCoinbase: true,
    fallbackStratumExtranonceSubscribe: false,
    fallbackStratumPort: 3333,
    fallbackStratumProtocol: 'SV1',
    fallbackStratumSuggestedDifficulty: 0,
    fallbackStratumTLS: false,
    fallbackStratumURL: 'solo.ckpool.org',
    fallbackStratumUser: 'bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    fallbackStratumV2AuthorityPubkey: '',
    fallbackStratumV2ChannelType: 'standard',
    fan2rpm: 0,
    fanrpm: 4820,
    fanspeed: 62,
    freeHeap: 118432,
    freeHeapInternal: 92160,
    freeHeapSpiram: 6291456,
    frequency: 490,
    fullHostname: 'bitaxe-hex.local',
    hashRate: S.hashRate ? wobble(S.hashRate, 90) : 0,
    hashRate_10m: S.hashRate ? wobble(S.hashRate, 30, 3) : 0,
    hashRate_1h: S.hashRate ? wobble(S.hashRate, 12, 5) : 0,
    hashRate_1m: S.hashRate ? wobble(S.hashRate, 60, 1) : 0,
    hashrateMonitor: {
      asics: Array.from({ length: 6 }, (_, i) => ({
        domains: [520 + i, 522 + i, 519 + i, 521 + i],
        errorCount: i,
        total: 2082 + i * 3,
      })),
    },
    hostname: 'bitaxe-hex',
    idfVersion: 'v5.4.1',
    invertscreen: 0,
    ipv4: '203.0.113.42',
    ipv6: 'fe80::1a2b:3c4d:5e6f:7a8b',
    isPSRAMAvailable: 1,
    isUsingFallbackStratum: 0,
    macAddr: 'AA:BB:CC:11:22:33',
    manualFanSpeed: 60,
    maxAllocHeap: 65536,
    maxPower: 100,
    mdnsHostname: 'bitaxe-hex',
    minFanSpeed: 25,
    minFreeHeap: 96000,
    miningPaused: S.miningPaused,
    networkDifficulty: 142000000000000,
    nominalVoltage: 12,
    overclockEnabled: 1,
    overheat_mode: S.overheat_mode,
    partitions: [
      { label: 'factory', version: 'v2.15.1', isCurrent: false, isFactory: true, usagePercent: 88, compileDate: 'Aug 29 2026', compileTime: '10:41:02' },
      { label: 'ota_0', version: 'v2.15.1', isCurrent: true, isFactory: false, usagePercent: 91, compileDate: 'Aug 29 2026', compileTime: '10:41:02' },
      { label: 'ota_1', version: 'v2.15.0', isCurrent: false, isFactory: false, usagePercent: 90, compileDate: 'Aug 21 2026', compileTime: '08:12:44' },
    ],
    poolConnectionInfo: 'IPv4',
    poolDifficulty: 1000,
    pools: POOLS,
    power: wobble(77.4, 1.8),
    primaryPoolIndex: 0,
    resetReason: 'ESP_RST_POWERON',
    responseShareBatch: 1,
    responseTime: wobble(42, 8),
    rotation: 0,
    runningPartition: 'ota_0',
    scriptsig: '/public-pool.io/',
    secondaryPoolIndex: 1,
    sharesAccepted: S.sharesAccepted,
    sharesPending: 0,
    sharesRejected: 37,
    sharesRejectedReasons: [
      { count: 21, message: 'Job not found' },
      { count: 11, message: 'Above target' },
      { count: 5, message: 'Duplicate share' },
    ],
    showNewBlock: false,
    smallCoreCount: 1276,
    ssid: 'bench-wifi',
    statsFrequency: 30,
    statsLimit: 720,
    stratumCert: '',
    stratumDecodeCoinbase: true,
    stratumExtranonceSubscribe: true,
    stratumPort: 21496,
    stratumProtocol: 'SV1',
    stratumSuggestedDifficulty: 1000,
    stratumTLS: false,
    stratumURL: 'public-pool.io',
    stratumUser: 'bc1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.bitaxe-hex',
    stratumV2AuthorityPubkey: '',
    stratumV2ChannelType: 'standard',
    temp: wobble(58.4, 2.2),
    temp2: wobble(57.1, 2.0, 2),
    temptarget: 60,
    totalHashes: 812000000000000,
    totalLog2Work: 49.5,
    totalUptimeSeconds: 1892344,
    uptimeSeconds: 184622,
    useCustomWWW: 0,
    version: 'v2.15.1',
    voltage: wobble(12040, 40),
    vrTemp: wobble(51.2, 1.6),
    wifiRSSI: -54,
    wifiStatus: 'Connected!',
    workReceived: 91244,
  };
}

const STAT_LABELS = [
  'hashrate', 'hashrate_1m', 'hashrate_10m', 'hashrate_1h', 'errorPercentage',
  'asicTemp', 'asicTemp2', 'vrTemp', 'asicVoltage', 'voltage', 'power', 'current',
  'fanSpeed', 'fanRpm', 'fan2Rpm', 'wifiRssi', 'freeHeap', 'responseTime', 'timestamp',
];

function statistics() {
  const now = Date.now();
  const rows = [];
  const N = 720;
  for (let i = 0; i < N; i++) {
    const t = i / 30;
    const hr = 3120 + 140 * Math.sin(t) + 40 * Math.sin(t * 3.1);
    rows.push([
      +hr.toFixed(1),
      +(hr + 18 * Math.sin(t + 1)).toFixed(1),
      +(hr + 8 * Math.sin(t + 2)).toFixed(1),
      +(hr + 3 * Math.sin(t + 3)).toFixed(1),
      +(0.4 + 0.2 * Math.sin(t * 2)).toFixed(3),
      +(58 + 2.5 * Math.sin(t * 0.8)).toFixed(1),
      +(57 + 2.3 * Math.sin(t * 0.8 + 1)).toFixed(1),
      +(51 + 1.8 * Math.sin(t * 0.6)).toFixed(1),
      1198,
      +(12040 + 45 * Math.sin(t * 1.4)).toFixed(0),
      +(77 + 2.4 * Math.sin(t * 1.1)).toFixed(1),
      +(6420 + 130 * Math.sin(t * 1.1)).toFixed(0),
      62,
      4820,
      0,
      -54,
      118432,
      +(42 + 9 * Math.sin(t * 1.7)).toFixed(1),
      now - (N - i) * 30000,
    ]);
  }
  return { currentTimestamp: now, labels: STAT_LABELS, statistics: rows };
}

function scoreboard() {
  return Array.from({ length: 20 }, (_, i) => ({
    rank: i + 1,
    difficulty: Math.round(2870000 / (i + 1)),
    extranonce2: (i * 7919).toString(16).padStart(8, '0'),
    job_id: (1000 + i).toString(16),
    nonce: ((0xe20a0000 + i * 4919) >>> 0).toString(16),
    ntime: Math.floor(Date.now() / 1000) - i * 3600,
    since: i * 3600 + 120,
    version_bits: (0x1fffe000 & (i * 0x2000)).toString(16).padStart(8, '0'),
  }));
}

const ASIC = {
  ASICModel: 'BM1368',
  deviceModel: 'Hex',
  swarmColor: 'purple',
  asicCount: 6,
  hashDomains: 4,
  defaultFrequency: 490,
  frequencyOptions: [400, 425, 450, 475, 485, 490, 500, 525, 550, 575],
  defaultVoltage: 1200,
  voltageOptions: [1100, 1150, 1200, 1250, 1300],
};

const WIFI_SCAN = {
  networks: [
    { ssid: 'bench-wifi', rssi: -54, authmode: 3 },
    { ssid: 'bench-wifi-5g', rssi: -67, authmode: 3 },
    { ssid: 'neighbour-2g', rssi: -81, authmode: 3 },
  ],
};

const LOG_LINES = [
  'I (184622) asic_result: Ver: 20000000 Nonce e20a222c diff 1284.0 of 1000',
  'I (184684) stratum_task: tx: {"id":4,"method":"mining.submit","params":[...]}',
  'I (184701) stratum_api: rx: {"id":4,"result":true,"error":null}',
  'I (184702) SystemModule: Share accepted! 18422/37',
  'I (185100) power_management: T: 58.4 C, VR: 51.2 C, P: 77.4 W, F: 62% 4820 RPM',
  'I (185640) statistics: hashrate 3120.4 GH/s (10m 3118.9)',
];

// ------------------------------------------------------------- static ----

function serveStatic(req, res, urlPath) {
  let rel = urlPath === '/' ? '/index.html' : urlPath;
  rel = rel.split('?')[0];
  const full = path.join(DIST, path.normalize(rel).replace(/^([/\\])+/, ''));
  if (!full.startsWith(DIST)) { res.writeHead(403).end('forbidden'); return; }
  if (existsSync(full) && statSync(full).isFile()) {
    const body = readFileSync(full);
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(full).toLowerCase()] ?? 'application/octet-stream',
      'Content-Length': body.length,
      'Cache-Control': 'no-store',
    });
    res.end(body);
    return;
  }
  // SPA fallback (the app uses HashLocationStrategy, so this is only hit for typos)
  const idx = path.join(DIST, 'index.html');
  const body = readFileSync(idx);
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': body.length });
  res.end(body);
}

const json = (res, obj, code = 200) => {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
};

// ------------------------------------------------------------- server ----

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
  const p = url.pathname;

  if (req.method === 'OPTIONS') { res.writeHead(204).end(); return; }

  if (p.startsWith('/api/')) {
    if (req.method === 'GET') {
      switch (p) {
        case '/api/system/info': tick++; return json(res, systemInfo());
        case '/api/system/asic': return json(res, ASIC);
        case '/api/system/statistics': return json(res, statistics());
        case '/api/system/scoreboard': return json(res, scoreboard());
        case '/api/system/wifi/scan': return json(res, WIFI_SCAN);
        case '/api/system/boot': return json(res, { bootPartition: 'ota_0' });
        case '/api/theme': return json(res, { colorScheme: 'dark', primaryColor: '#F80421' });
        case '/api/system/logs': {
          const body = Buffer.from(LOG_LINES.join('\n') + '\n');
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Content-Length': body.length });
          return res.end(body);
        }
        default: return json(res, {}, 404);
      }
    }
    // Every write the UI makes is accepted, so click-through probes exercise the real path.
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      console.log(`[req] ${req.method} ${p} ${body.slice(0, 300)}`);
      json(res, { message: 'ok' });
    });
    return;
  }

  serveStatic(req, res, p);
});

// Minimal RFC-6455 server: handshake + server->client text frames. Enough for the
// two AxeOS sockets (`/api/ws/live` telemetry push, `/api/ws` log stream); it never
// needs to READ a client frame, so no unmasking is implemented.
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function wsFrame(str) {
  const payload = Buffer.from(str);
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.from([0x81, len]);
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = 0x81; header[1] = 126; header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, payload]);
}

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  const p = req.url.split('?')[0];
  if (!key || (p !== '/api/ws' && p !== '/api/ws/live')) { socket.destroy(); return; }
  const accept = createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  console.log(`[ws] client connected on ${p}`);

  let n = 0;
  const timer = setInterval(() => {
    try {
      if (p === '/api/ws/live') {
        tick++;
        const i = systemInfo();
        socket.write(wsFrame(JSON.stringify({
          event: 'update',
          data: {
            hashRate: i.hashRate, hashRate_1m: i.hashRate_1m, hashRate_10m: i.hashRate_10m,
            hashRate_1h: i.hashRate_1h, temp: i.temp, temp2: i.temp2, vrTemp: i.vrTemp,
            power: i.power, voltage: i.voltage, current: i.current, fanrpm: i.fanrpm,
            fanspeed: i.fanspeed, sharesAccepted: i.sharesAccepted, sharesRejected: i.sharesRejected,
            uptimeSeconds: i.uptimeSeconds + n, errorPercentage: i.errorPercentage,
            cpuUsage: i.cpuUsage, freeHeap: i.freeHeap, responseTime: i.responseTime,
            version: i.version,
          },
        })));
      } else {
        // AxeOS's LogsComponent buffers until the payload ENDS WITH '\n'
        // (`logs.component.ts`: `if (this.logBuffer.endsWith('\n'))`). A frame
        // without the newline is accumulated and never rendered — the pane just
        // stays blank. Keep the terminator.
        socket.write(wsFrame(LOG_LINES[n % LOG_LINES.length] + '\n'));
      }
      n++;
    } catch { clearInterval(timer); }
  }, p === '/api/ws/live' ? 2000 : 700);

  socket.on('close', () => clearInterval(timer));
  socket.on('error', () => { clearInterval(timer); socket.destroy(); });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`AxeOS bar server (v2.15.1 dist) on http://127.0.0.1:${PORT}/  scenario=${SCENARIO}`);
  console.log(`dist: ${DIST}`);
});
