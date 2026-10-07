# `DCENT_OS_ESP/tools/` — DCENT_axe dashboard preview harness

The DCENT_axe web dashboard is **compiled into the firmware image**: the page is a
`r##"…"##` raw-string literal in `dcentaxe/src/dashboard.rs`, and the ten CSS/JS assets are
`include_str!`'d and served by `register_dashboard`. Before this directory existed there was
**no way to look at the dashboard without flashing a physical BitAxe** — no dev server, no
extractor, no fixture set anywhere in the workspace. Reviewers could not click a single button.

These tools put the exact bytes the firmware serves on `http://127.0.0.1:<port>/`, back them with
scrubbed fixtures captured from a real device, and drive them through headless Chrome.

| file | what it is |
|---|---|
| `axe_mock_server.mjs` | Node, stdlib only. Extracts `DASHBOARD_HTML`, serves the baked assets with the firmware's own headers, serves `/api/*` from fixtures, logs every request to `requests.jsonl`, optional read-only proxy to a real device. |
| `fixtures/` | 10 scenario fixture sets + `_base/`, built by `fixtures/_build_fixtures.mjs` from a scrubbed read-only capture of the bench device. |
| `cdp_shot.mjs` | Chrome DevTools Protocol screenshotter, copied **unchanged** from `projects/dcent-pool/tools/cdp_shot.mjs` (SHA-256 `bc9fa6fa03bf4d641379f1b7783460f8c7c80ce968e197643ea11c167626968e`). Do not fork it — fix it in the pool tree and re-copy. |

---

## 🔴 Two hard rules. Both of these have already cost this workspace real damage.

### 1. Kill processes **by PID**, never by image name.

```bash
netstat -ano | findstr :8181        # find the pid listening on your port
taskkill /PID <pid> /F              # kill exactly that process
```

**Never** run `taskkill /IM chrome.exe`, `/IM node.exe`, `/IM python.exe`, `/IM cargo.exe` or
`/IM rustc.exe`. On 2026-09-02 an agent's `taskkill /IM chrome.exe` **closed the operator's own
browser**, and other lanes, other agents and the operator's editor all run node/python on this
machine. `cdp_shot.mjs` already kills the Chrome it spawned via its child handle; anything else
you start, you kill by its pid.

### 2. Delete **every** Chrome profile directory you create.

Headless Chrome writes tens of megabytes into its `--user-data-dir` on every launch. On
2026-09-02 thirty-two of those directories (~28 GB) took the C: volume to **0 bytes free** and
ENOSPC killed an unrelated test suite. `cdp_shot.mjs` deletes its own profile dir on exit unless
`CDP_KEEP_PROFILE=1`; if you set that flag, or write your own probe, **you** delete it. Check
free space when you are done:

```powershell
Get-PSDrive C | Select-Object Used, Free
```

Profiles are scratch and always deletable. Keep the PNGs, delete the profiles.

---

## Running the mock

```bash
cd DCENT_OS_ESP
node tools/axe_mock_server.mjs --src "$PWD/dcentaxe/src" --port 8181 --scenario mining \
     --log "$PWD/../.axe-gauntlet/pass1/<lane>/requests.jsonl"
```

Then open `http://127.0.0.1:8181/`. The dashboard has **no router** — all seven pages live in one
document and are switched with `go(0..6)`:

| n | page | element |
|---|---|---|
| 0 | Dashboard | `#p0` / nav `#n0` |
| 1 | Pool | `#p1` / `#n1` |
| 2 | Logs | `#p2` / `#n2` |
| 3 | Network | `#p3` / `#n3` |
| 4 | System | `#p4` / `#n4` |
| 5 | Settings | `#p5` / `#n5` |
| 6 | Swarm | `#p6` / `#n6` |

### Flags

| flag | default | meaning |
|---|---|---|
| `--src <dir>` | `../dcentaxe/src` | directory holding `dashboard.rs` + `dashboard/` |
| `--port <n>` | `8181` | listen port |
| `--host <addr>` | `127.0.0.1` | bind address |
| `--scenario <name>` | `mining` | starting fixture scenario |
| `--fixtures <dir>` | `tools/fixtures` | fixture root |
| `--log <path>` | `./requests.jsonl` | request log (JSON Lines) |
| `--live <ip>` | — | proxy **GET only** to a real device (see below) |
| `--freeze-time` | off | serve fixture timestamps verbatim instead of re-basing them |
| `--lora` | off | also append `LORA_DASHBOARD_PANEL_HTML`, as a `--features lora` image does |

### Startup output

On listen, the server logs a line like:

```
  html       28219 bytes as served [CRLF (this checkout)] · 27331 bytes LF-normalised · 27331 UTF-16 chars
             ^ NOT an image-size budget number (line-ending dependent; the firmware cost is the LF bytes, measured by espflash save-image)
```

**Neither `bytesAsServed` nor `bytesLfNormalised` is an image-size budget number.** `bytesAsServed`
depends on the checkout's line endings (`core.autocrlf = true` gives Windows worktrees CRLF while
git stores LF — on a ~900-line literal that is a ~900-byte swing that has nothing to do with the
firmware); `bytesLfNormalised` is closer but still `String.length`/UTF-8 arithmetic on a dev
machine, not the compiled-and-linked `&str` the toolchain produces. The only number that counts
against the OTA budget (README §3 of the campaign `README.md`, `Hex Supra`'s 3,145,728-byte slot)
is `espflash save-image`, same toolchain, same features, before/after. Treat both printed numbers
as a sanity check that the mock parsed something roughly page-shaped, never as a byte-budget claim.

### Live switching

Any request may carry query parameters that change server state and stick for later requests
(so the dashboard's own 15 s poll picks them up without a reload):

```
http://127.0.0.1:8181/?scenario=thermal-warning     switch scenario
http://127.0.0.1:8181/?fail=/api/pools:503          force one route to fail
http://127.0.0.1:8181/?fail=                        clear forced failures
```

Mock-only introspection (these are **not** firmware routes and cost no handler slot):
`GET /__mock/state` (active scenario, scenario list, baked asset list, forced failures) and
`GET /__mock/requests` (the request log).

---

## Fidelity — what the mock copies from the firmware, and what it does not

**Copied, by parsing `dashboard.rs` at startup — never hard-coded here:**

- The page body is the `r##"…"##` `DASHBOARD_HTML` literal (`dashboard.rs:191`), byte for byte.
- `GET /` and `/index.html` headers come from the `GET /` handler (`dashboard.rs:112-117`):
  `Content-Type: text/html; charset=utf-8`, `Cache-Control: no-cache`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`.
- `GET /dashboard/*` headers come from `register_static` (`dashboard.rs:90-94`): the per-asset
  content type (`text/css; charset=utf-8` / `application/javascript; charset=utf-8`, from the
  `css`/`js` locals at `dashboard.rs:157-158`), `Cache-Control: public, max-age=300`,
  `X-Content-Type-Options: nosniff`.
- The **asset set** is read from the `register_static` call list (`dashboard.rs:159-186`), so the
  mock serves exactly the ten files the firmware bakes. `stats.css`, `flow.css`, `stats.js` and
  `flow.js` exist on disk but are deliberately **not** baked (`dashboard.rs:59-62`, `:69-72`), so
  the mock 404s them exactly like the firmware does.

If any of those shapes stops matching, the mock **refuses to start** with a `PARSE FAILURE`
message rather than silently serving invented headers. Fix the mock; do not let it drift.

**Not copied — know these before you draw a conclusion from the mock:**

- ESP-side HTTP behaviour: chunked write sizes, the 8 s request timeout, `MAX_URI_HANDLERS`
  pressure, real TLS, and the actual latency of a 240 MHz Xtensa.
- Real auth. `/api/auth/*` writes return a canned session; there is no token validation, so
  `ensureWriteAuth` never actually gates anything on the mock. Auth behaviour must be proven on
  a device.
- Binary responses. `GET /api/system/coredump?download=1` returns 404 (the fixture loader is
  JSON-only); on a device with `coredumpPresent:true` it returns an ELF.
- **The dashboard makes one external network call the mock cannot intercept:**
  `https://mempool.space/api/v1/fees/recommended` (`dashboard.rs:2036`), an absolute URL. On a
  networked workstation it succeeds and the mempool-fee widget shows live internet data; offline it
  fails silently. That is firmware behaviour, not a mock artifact.
- OTA. `POST /api/system/OTA` is accepted and its body length logged, but nothing is validated.

---

## Fixtures

`fixtures/_base/` is a complete, scrubbed capture of the bench BitAxe Hex Supra
(board 702, 6× BM1368, DCENT_axe v0.3.0), taken with **read-only GETs** on 2026-09-03.
Each scenario directory holds only the endpoint files that **differ**; anything not present there
falls back to `_base/`. Every scenario carries a complete `system_info.json`, because that one
endpoint drives nearly the whole UI and a reader should not have to diff two files to know what a
scenario means.

| scenario | what it is |
|---|---|
| `mining` | exactly what the device reported — enabled, hashing, pool connected |
| `ready` | permitted but zero hashrate (chips idle, pool up) |
| `standby` | `dcentaxe.miningEnabled=false` |
| `thermal-warning` | 92.5 °C die / 105.5 °C VR — trips the `ct>90` HOT branch (`dashboard.rs:2290`) |
| `no-sensor` | `sensorsOk=false`, temps 0, and `dcentaxe.tempSource` **omitted** — `api.rs:1605` emits `None` when the sensors did not read, so the key must be absent, not null |
| `pool-offline` | chips hashing, pool gone, 4 submits pending, last accepted proof 15 min stale |
| `safe-mode` | `safeMode=true`, `wdtResetCount=5`, coredump present, mining refused |
| `restricted-image` | `installPolicy: lab-only`, `runtimeMode: identity-only` — fires the deployment banner (`dashboard.rs:2485`) |
| `first-run` | no pool configured, no history, Egg-stage companion — the state the first-run wizard keys off. Its `system_statistics.json` is the tree's **one synthesized fixture** (see below) |
| `sv2-unavailable` | `stratumV2Available=false` (the device's real value) **while the stored config asks for v2** — the conflict the V2 option gate at `dashboard.rs:2429-2436` must render honestly |

### The one synthesized fixture — `first-run/system_statistics.json` (lane P1-W6, 2026-09-03)

Every other file under `fixtures/` is a scrubbed read-only capture of the bench Hex Supra. This one
is **not a capture**: no device was contacted for it, and it says so in its own `_fixture` key (mock
metadata; the firmware emits `currentTimestamp` / `labels` / `statistics` and nothing else). It
exists because `first-run` means *no history yet*, and that is a distinct branch of the handler:
when `history.samples` is empty, `api.rs:1814-1861` still answers with exactly **one** row built
from the live snapshot whose `timestamp` equals `currentTimestamp`. Without this file the scenario
fell back to `_base` and served 60 rows of history to a device that has none. Its values are copied
from this scenario's own `first-run/system_info.json`, so the two cannot disagree. The dashboard
renders it as `no window yet · 1 sample · 1 from device` and draws no line — one point is not a
series.

### Time re-basing (on by default)

The fixtures are a frozen capture, and the dashboard grades share proofs against a 600 s freshness
window (`dashboard.rs:2259`). Served verbatim, the `mining` scenario would always render "accepted
proof stale". The server therefore shifts every recognised epoch field by **one constant delta**
(`Date.now - capturedAtUnixMs`, from `fixtures/_base/meta.json`), which preserves every relative
age exactly. Shifted: keys ending `UnixMs` / `_unix_ms` / `Unix`, `currentTimestamp`, `updatedAt`,
and the `timestamp` column of `/api/system/statistics`. **`buildEpoch` is deliberately not
shifted.** `--freeze-time` turns the whole mechanism off.

### Rebuilding the fixtures

```bash
node tools/fixtures/_build_fixtures.mjs --raw <evidence-root>/raw-capture
```

The literal identifiers being removed live in `scrub-map.json` **next to the raw capture in the
gitignored evidence root**, never in this tree — writing them into a committed file would put back
the very strings the scrub exists to remove. The builder refuses to run without it. What it
replaces: Wi-Fi SSID, MAC (colon and packed forms), hostname/mDNS name, LAN IPv4 (including the
swarm `apiUrl`/`mcpUrl`), pool worker/wallet, donation worker, and the coinbase `scriptHex`
payloads (script-type prefix kept, payload replaced with a `deadbeef` pattern of identical length
so `block-tile.js`'s `scriptHexToAddress` still decodes a well-formed, obviously fake address).
Pool hostnames, firmware version, git hash, board ids and public chain data are left as measured.

---

## Live device mode (`--live <ip>`) — read-only, not negotiable

```bash
node tools/axe_mock_server.mjs --src "$PWD/dcentaxe/src" --port 8182 --live <device-ip>
```

GET requests are proxied to the device and tagged `X-Mock-Proxied`. **POST / PATCH / PUT / DELETE
are never forwarded** — they are answered locally and logged with `"forwarded": false`.
`--allow-writes` is rejected at startup with exit code 2. The bench unit mines live; every write to
it needs the operator's per-action authorization (root , "Live-Hardware Safety").

---

## Screenshots and click-through

Rendering is not testing. Every primary action must be **clicked** and its outcome asserted before
a critic sees a lane.

```bash
node tools/cdp_shot.mjs "C:/Program Files/Google/Chrome/Application/chrome.exe" \
  <profileDir> <out.png> "http://127.0.0.1:8181/?scenario=mining" \
  <w> <h> <waitMs> <fullPage 0|1> <mobile 0|1> "<jsBefore>" <jsWaitMs>
```

Campaign assertion, passed as `jsBefore` (it is printed as `EVAL:`):

```js
document.querySelector('.page.ac')?.id+'|'+_curPage+'|'+document.documentElement.scrollWidth+'|'+innerWidth
```

⚠ **That expression cannot see horizontal overflow under mobile emulation.** With
`Emulation.setDeviceMetricsOverride{mobile:true}`, `window.innerWidth` reports the *visual*
viewport, which Chrome inflates to the content width when the page overflows — so an overflowing
page reports `scrollWidth === innerWidth` and looks clean. The layout viewport is
`document.documentElement.clientWidth`. Compare against **that** when you are checking overflow.
Measured on this dashboard at 390 CSS px: `clientWidth` 390, `scrollWidth` 667–705, i.e. every page
overflows by ~280–315 px, while the prescribed expression reports `705|705`. Evidence:
`projects/.axe-gauntlet/pass1/P1-I1/overflow.md`.

The lane's own probes (`clickthrough_probe.mjs`, `overflow_probe.mjs`) live in that evidence folder
rather than here, so this directory stays the four files the lane was asked to ship.

⚠ **The Dashboard page's PERFORMANCE chart is no longer empty on first load** (changed by lane
`P1-W6`, 2026-09-03 — this paragraph used to say the opposite and the old advice is now wrong).
`seedChart` fetches `GET /api/system/statistics` on boot and again after every reconnect, so a
capture taken immediately after `cdp_shot.mjs` navigates shows the device's own ~60-minute history
(the `_base` fixture is 60 rows at 60 s). The client ring (`HRH`/`TH`/`PH`/`TSH`) still appends one
point per poll on top of that. Two consequences for captures:

- You no longer need `<waitMs> ≥ 31000` to photograph a populated chart; ~3 s is enough. Wait longer
  only when you specifically want live points appended on top of the seed.
- To photograph the **fallback** (no device history), force the endpoint down:
  `?fail=/api/system/statistics:503` — the chart falls back to the client-only ring and the window
  label reads `… · device history unavailable`. Clear it with `?fail=`.

The mock still has no history-*synthesising* flag: it replays `/api/system/statistics` fixture
snapshots as-is (re-basing only their `timestamp` column) and never invents chart data server-side.

---

## Measurement station — CR refusal (`measure_image.sh` / `measure_cr_check.py`)

`tools/measure_image.sh` (the Gauntlet campaign's Stage-M measurement station — see
) is a **different** tool from the mock
server documented above: it builds each board's release image, runs `espflash save-image`, and
writes `measure.json`, the byte-budget document a blind critic is handed. It lives in this same
`tools/` directory, so its behaviour is documented here rather than in a second README.

**Why a CR check exists at all.** `dashboard.rs` bakes ten CSS/JS files in with `include_str!`.
`include_str!` **keeps carriage-return bytes** (proven with a one-file `rustc` experiment,
`PROGRESS.md` 2026-09-03 ~14:10/~14:35): on a `core.autocrlf=true` Windows worktree, every embedded
line gains one extra `\r` byte that survives all the way into the compiled `&str` and the linked
image. Measured once as **1,893 CR bytes** across the embedded assets of one worktree — an image
that looked ~1.9 KB bigger than the same source on an LF checkout, for a reason that had nothing to
do with any lane's actual change. The station used to build straight from whatever line endings the
tree happened to have and had no way to tell a reader this had happened.

**What the check does.** Before anything else runs — before the handler census, before the host
gate, before any board build, and regardless of `--skip-build`/`--skip-host-gate` (it is a
SOURCE-state check, not a build-state one) — `measure_image.sh` calls
`tools/measure_cr_check.py --dcentaxe-src <root>/dcentaxe/src`. That script:

1. Parses `dashboard.rs` for every `include_str!("...")` / `include_bytes!("...")` invocation and
   builds the file list from the macro invocations themselves — **never a hard-coded list**, so a
   newly-embedded asset is covered automatically the moment it is added.
2. For `dashboard.rs` itself and every file it names, prints a table of on-disk bytes, CR-byte
   count, and the **LF-normalised byte count** (on-disk bytes minus CR bytes) side by side:

   ```
   path                                             on-disk     cr  lf-normalised
   dashboard.rs                                      246206      0         246206
   dashboard/tokens.css                                7895      0           7895
   ...
   TOTAL CR bytes across 11 embedded-asset file(s): 0
   measure_cr_check: PASS (0 CR bytes)
   ```
3. **Fails closed** (station exit code **2**) the moment the total is nonzero, with a message
   pointing at this section and at the `--allow-cr` escape hatch.

**`--allow-cr`** downgrades that refusal to a loud stderr warning and lets the run continue (exit
0), for a deliberate CRLF-checkout smoke run that is not trying to produce a comparable byte-budget
number. Every board-byte figure such a run produces is **known-inflated** and must not be quoted
against an LF baseline or used for a lane's D8/H1 verdict.

**Normalising a CRLF worktree instead of using `--allow-cr`:** the fix that actually restores a
comparable measurement is to check out the tree LF, not to waive the check. `.gitattributes` pins
`text eol=lf` for `DCENT_OS_ESP/**` source files going forward; an already-CRLF worktree
needs its working copy converted (the lead's `station_lf_copy.sh` builds an LF copy of a worktree at
an equal-length path for exactly this reason — see the campaign's `GAUNTLET_LOOP.md`).

**`measure.json`'s shape is unchanged.** The CR check is a station-side gate with its own console
output and exit code; it does not touch `tools/measure_assemble.py` (the sole writer of
`measure.json`) or any of that document's keys, so a previously-tracked baseline or a script reading
`measure.json` (`station_lf_copy.sh`, `check_measure_ports.py`, a critic's tooling) keeps working
unmodified. The per-asset byte table already present in `measure.json`'s `assets` key (dashboard.rs
plus `api.rs`/`main.rs`/`mcp.rs`/`auth.rs`, from `measure_assemble.py`'s `ASSET_SOURCES`) is a
broader, separate list from the CR check's dashboard-embed-only enumeration and is not affected.

Exit codes (station): `0` = measured and every board fits its slot, or the CR check found bytes and
`--allow-cr` was given; `1` = a board's image exceeds its OTA slot, the handler census failed, or a
requested tool is missing; `2` = the embedded-asset CR check failed (a CR byte was found without
`--allow-cr`, or `dashboard.rs`/a file it embeds could not be located).

---

Support open firmware: **<https://d-central.tech/fund/>** — every DCENT_ project carries this link.
