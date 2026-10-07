# A1246 first-contact bench runbook (NO-GO pending trust anchors and authorization)

> **Current disposition: NO-GO.** The coordinator accepted host-only workflow
> lane `w1-identityschema` on 2026-08-23, but `op-ceremony` is still incomplete
> and the named physical session still requires the exact authorizations below.
> Do not execute this card yet. The verifier now resolves the
> generic `a1246` target to one of three held stock-profile contracts from the
> captured VERSION/HWTYPE/SWTYPE tuple and independently observed X2/X3
> topology. It rejects generic or operator-forced ASIC labels. This is a stock
> contract identification, not proof obtained from physical ASIC markings.

This is the operator's bench session plan for converting the next hour with the
owned AvalonMiner A1246 into an **admissible discovery receipt** — the first
live-proof artifact for the K210 gauntlet. The unit is claimed in hand with
zero live proof so far; today the gauntlet reports (host-only check,
2026-08-23):

```
K210_MODEL_GATE_OK model=a1246 production_ready=false first_blocker=exact_model_identity
```

A successful session moves `a1246` to `first_blocker=stock_restore` with
`exact_model_identity` qualified, and nothing else.

The eventual session has two physically separate phases. Phase A is a
de-energized, locked-out, discharged visual inspection. Phase B begins only
after every cover is reinstalled and uses normal closed-chassis stock power
for read-only management queries. The receipt records exactly four phase
actions: `deenergized_visual_inspection_power_down`,
`visual_identity_inspection`, `closed_chassis_stock_power_restoration`, and
`stock_read_only_management_queries`. The power-down/restoration pair makes
the historical power-state change explicit; none of these actions grants any
future authority or permits energized cover removal, probing, cable movement,
configuration, reboot, or firmware writes.

**Authorization gate (read first).** Per the workspace Live-Hardware Safety
rule: *do not contact, flash, reboot, or run live/destructive commands on any
live miner unless the operator explicitly authorizes that exact action.* This
session requires a pre-existing operator authorization, recorded before any
capture, that names: this exact unit (label `a1246-unit-01`), the UTC interval
of the session, the de-energized lockout/discharge/visual-inspection phase,
the later fully reassembled closed-chassis stock-power/API phase, and exactly
the four receipt actions above. Each phase needs explicit operator approval;
one broad phrase such as "visual inspection" is not sufficient authority for
cover removal or stock power. The
trust-anchor ceremony itself (`K210_TRUST_ANCHOR_CEREMONY.md`) requires
nothing live, but bundle admission additionally requires the observer key
pinned per that ceremony.

---

## 1. Preconditions

Hardware / bench:

- A1246 (A12 generation, K210 controller, generic A3200-family target row;
  rated 90 TH/s, air-cooled) is owned by D-Central, physically on the
  bench, and connected to the operator-controlled bench LAN with a known IP.
- Stock state untouched: **no writes, no reboots, no flashing, no `ascset` or
  any other mutating API command, no firmware or config changes of any kind.**
  Stock Avalon K210 firmware has no SSH and no shell; the only interface used
  is the read-only CGMiner API (TCP 4028) and the camera.
- Phase A begins with stock shutdown through the unit's normal operator-
  approved means, upstream AC isolation, lockout/tagout, and an operator-
  approved absence-of-energy/discharge check. No cover is opened until that
  check is complete. Hash boards and PSU are de-energized throughout Phase A.
- Before Phase B, reinstall the controller-compartment cover and every guard,
  confirm no cable or connector was disturbed, and close the chassis. Hash
  boards may then be energized only in the unit's normal stock mining
  configuration. No frequency/voltage/fan/PSU command is permitted.
- All photographs must be achievable **without disassembling the PSU**. The
  PSU enclosure stays closed for the whole session.

Host / tooling (verified on the bench host 2026-08-23):

- `py -3` (Python 3.12) available; scripts run as
  `py -3 DCENT_OS_AvalonMiner/scripts/...` from the repository root.
- OpenSSH `ssh-keygen` available (needed for `create`/`verify`).
- `nc` is **not** present in Git Bash on this host — use the Python 4028
  fallback in Section 5 wherever this runbook shows an `nc` form.
- The discovery observer key pair exists and, for full admission, the observer
  public key is pinned in `k210_models.json`
  (`K210_TRUST_ANCHOR_CEREMONY.md`). If the pin has not landed yet, the
  session is still worth running: create and directly verify the bundle now,
  and admit it after the pin (Section 9).

Evidence workspace (host-side only):

```
C:\evidence\a1246-unit-01\capture.json      <- capture descriptor (edited template)
C:\evidence\a1246-unit-01\source\           <- evidence root: the 9 files below
C:\evidence\a1246-unit-01\signed-bundle\    <- created by the tool; must NOT pre-exist
```

Generate a fresh session UUID now and note it (used in the descriptor):

```bash
py -3 -c "import uuid; print(uuid.uuid4())"
```

## 2. Required evidence — the nine kinds and their capture

The verifier admits exactly one evidence item per required kind, each with a
unique path below the evidence root, method and media type bound to the kind
(photos = `visual_inspection` + canonical PNG; API responses =
`stock_read_only_management` + JSON; authored records = `offline_record` +
JSON or text). Max 32 items, max 256 MB per file, max 1 GB total. Three
optional kinds may be added (Section 7).

| # | Kind | File name | Method / media | How to capture |
|---|---|---|---|---|
| 1 | `collection_log` | `collection_log.json` | `offline_record` / `application/json` | Authored: the session's timestamped log (Section 6) |
| 2 | `controller_front_photo` | `controller_front_photo.png` | `visual_inspection` / `image/png` | Camera/export (Section 4) |
| 3 | `controller_back_photo` | `controller_back_photo.png` | `visual_inspection` / `image/png` | Camera/export (Section 4) |
| 4 | `cooling_topology_photo` | `cooling_topology_photo.png` | `visual_inspection` / `image/png` | Camera/export (Section 4) |
| 5 | `hashboard_topology_record` | `hashboard_topology_record.json` | `offline_record` / `application/json` | Authored record (Section 6) |
| 6 | `miner_label_photo` | `miner_label_photo.png` | `visual_inspection` / `image/png` | Camera/export: the miner's nameplate/serial label |
| 7 | `psu_label_photo` | `psu_label_photo.png` | `visual_inspection` / `image/png` | Camera/export: PSU rating/serial label as visible **without opening the PSU** |
| 8 | `stock_stats_response` | `stock_stats_response.json` | `stock_read_only_management` / `application/json` | `stats` over 4028 (Section 5) |
| 9 | `stock_version_response` | `stock_version_response.json` | `stock_read_only_management` / `application/json` | `version` over 4028 (Section 5) |

Photo discipline: one clear, legible frame per required kind; the labeled
serials, silkscreen text, connector layout, and fan arrangement must be
readable at full resolution. Retain the camera originals outside the signed
evidence root, then export each admitted copy as a non-interlaced 8-bit RGB or
RGBA PNG without cropping, retouching, or content edits. Note each file's
capture time in UTC for the descriptor's `acquired_at_utc`. The verifier checks
PNG chunks/CRCs, fully inflates the bounded IDAT stream, validates every
scanline, and requires dimensions of at least 64x64; JPEG and arbitrary bytes
with an image suffix are rejected. This decoding check does not perform OCR or
replace the observer's review of visible labels.

## 3. Session authorization record

Before touching the unit, write down (it goes into the descriptor in
Section 8):

- `operator_reference` (<=160 printable ASCII chars) — the operator's
  reference for this exact authorization, e.g.
  `DCENT-2026-09-01-A1246-RO-DISCOVERY-bench`.
- `valid_from_utc` / `valid_until_utc` — the UTC window covering the whole
  bench hour (e.g. `2026-09-01T17:00:00Z` to `2026-09-01T19:00:00Z`).
- Authorized actions (exact set, no additions):
  `deenergized_visual_inspection_power_down`,
  `visual_identity_inspection`, `closed_chassis_stock_power_restoration`,
  `stock_read_only_management_queries`.

Chronology is enforced by the verifier: every evidence `acquired_at_utc` must
fall within `[valid_from, observed_at]`, and `observed_at` within
`[valid_from, valid_until]`. Use real UTC timestamps — the receipt's validity
is internal to these recorded times, not to when it is later admitted.

## 4. Phase A — de-energized photographic pass (kinds 2,3,4,6,7)

Do not combine this pass with powered API collection. Record upstream AC
isolation, lockout/tagout, and the completed absence-of-energy/discharge check
in the collection log before opening the controller compartment. If the exact
zero-energy procedure is unavailable or the operator is not qualified to
perform it, stop; external photos may be retained as notes but the required
controller-board evidence is incomplete.

Controller-board identification — expected class: **MM3v2**. Do not choose a
variant before capture. The admitted held contracts are
`a1246-a3200lc-2hash` (`22062202_be77c30_a769bbf`, `MM3v2_X2`,
`MM315[_OOW]`, A3200LC-Plus), `a1246-a3201-2hash`
(`22011902_4ec6bb0_3e42b91`, `MM3v2_X2`, `MM314[_OOW]`, A3201-Plus), and
`a1246-a3201-temp65` (`22011901_4ec6bb0_3e42b91`, `MM3v2_X3`,
`MM314[_OOW]`, A3201-Plus). A1246N is a separate physical target whose held
contract is `a1246n` (`23021601_66620f1_27c9e34`, `MM3v2_X3`,
`MM315[_OOW]`, A3200-Plus). Confirm the unit in front of you by observation;
never select a row from the expected topology alone:

- `controller_front_photo`: the controller module's connector face as
  installed — Ethernet port, LEDs, the data-cable connectors running to the
  hash boards, fan leads, controller power input. No cables need to be
  disturbed.
- `controller_back_photo`: the board/PCB face showing **PCB silkscreen model
  and revision** (expect an MM3v2-class marking; record exactly what is
  printed — e.g. board model, board rev, date code). On A12 units the
  controller sits in its own controller compartment: opening that compartment
  lid is in scope only after the Phase A zero-energy gate; **opening the PSU
  enclosure is not**. If the
  PCB face cannot be brought into view without unmounting hardware, capture
  the best accessible view and record the limitation in the collection log —
  but do not unmount boards or disconnect cables to get a prettier photo.
- `cooling_topology_photo`: the machine's air-cooling layout — fan positions
  (intake/exhaust), shroud/duct arrangement, and how airflow passes the hash
  boards, from one angle that shows the whole topology.
- `miner_label_photo`: the miner nameplate — model (`AvalonMiner A1246`),
  serial, ratings.
- `psu_label_photo`: the PSU label — model, rated watts, serial, ratings — as
  visible with the PSU intact. `psu_rated_watts` in the identity comes from
  this label (bounded 1..10000; note the held AUP's product string says
  "P3600W", which is the package power class, not a substitute for the label).

Record observed `fan_or_pump_count`, `hashboard_count`, and per-board
identifiers now (they feed the identity in Section 8). Expected shape: A1246
is air-cooled with multiple fans (record the actual count, 1..32). The held
contracts include both two-board `MM3v2_X2` and three-board `MM3v2_X3` units;
the receipt must describe the physical unit in front of you and match topology
to the stock tuple. Do not force a near-neighbor profile from board count.

At the end of Phase A, reinstall the controller lid and all guards, inspect the
unit for tools/foreign objects or disturbed wiring, and record closed-chassis
reassembly. Phase B is forbidden until this is complete.

## 5. Phase B — closed-chassis read-only stock API pass (kinds 8,9)

Obtain the separately recorded Phase B authorization, restore normal stock
power with the chassis fully closed, and do not reopen any cover while the unit
is energized. Use the allowlisted `k210_discovery_collect.py` collector from
the workflow; the raw socket examples below are retained only as review
reference until their framing is validated on the named stock build.

Canonical commands (any host with `nc`):

```bash
echo "version" | nc <A1246_IP> 4028 > stock_version_response.json
echo "stats"   | nc <A1246_IP> 4028 > stock_stats_response.json
echo "estats"  | nc <A1246_IP> 4028 > stock_estats_response.json   # optional (Section 7)
```

This bench host's Git Bash has no `nc` (verified 2026-08-23). Python fallback,
validated host-only — run from the repository root, set `ip`, and repeat for
`cmd`/`out` as `version`/`stats`(/`estats`):

```bash
py -3 - <<'EOF'
import socket
ip = "192.168.101.XX"      # A1246 CGMiner API address on the bench LAN
cmd = "version"            # version | stats | estats
out = r"C:\evidence\a1246-unit-01\source\stock_version_response.json"
with socket.create_connection((ip, 4028), timeout=10) as s:
    s.sendall((cmd + "\n").encode())
    data = b"".join(iter(lambda: s.recv(4096), b""))
open(out, "wb").write(data.rstrip(b"\x00"))
print(data.decode(errors="replace"))
EOF
```

Save the raw response bytes (trailing NUL/whitespace may be trimmed); the
verifier hashes the file exactly as snapshotted. If the payload contains pool
usernames or other credentials/personal identifiers, redact and set the
item's `redaction` accordingly (`credentials_removed` /
`personal_identifiers_removed`) — never bundle live credentials.

Expected A1246 / K210-era content to sanity-check before accepting the
capture (per the held fms-core reference
 and the HiveON RE
protocol notes):

- `version` — JSON with a `STATUS` array (`"Status":"S"`) and a `VERSION`
  array whose first object carries the MM3-era identity fields:
  - firmware `VERSION` shaped `YYMMDDNN_gitshort_gitshort` (the held A1246
    stock line is `22062202_be77c30_a769bbf`; sibling A1246 builds
    `22011901_4ec6bb0_3e42b91` / `22011902_4ec6bb0_3e42b91`; some older stock
    builds spell the key `VERION` — a known 2019 firmware typo). The on-unit
    string may differ from the held profile if the unit was updated; record
    exactly what the unit reports.
  - `HWTYPE` in the MM3-era controller class — admitted A1246 contracts use
    `MM3v2_X2` or `MM3v2_X3`, and it must agree with both physical and stats
    topology.
  - `SWTYPE` is `MM315[_OOW]` on the held A3200LC/A1246N contracts and
    `MM314[_OOW]` on the two held A3201 contracts.
  - `UPAPI` (upgrade API version integer), `DNA` (unit DNA string), `MAC`.
  - Product/model fields starting with `AvalonMiner` / model A1246.
- `stats` — `STATUS` plus a `STATS` array: a miner-level object followed by
  per-hashboard module objects (MM3 `MM ID0`-style structures with per-board
  frequency, temperature, fan, and voltage fields). This response is what
  binds the observed hashboard topology to the live unit.

These four identity fields feed the descriptor verbatim:
`stock_firmware_version` (VERSION), `stock_hwtype` (HWTYPE),
`stock_swtype` (SWTYPE), `stock_dna` (DNA).

Read-only discipline: `version`, `stats`, `estats`, `summary`, `pools`,
`devs`, `config` are queries; **anything else — especially `ascset`,
`setpool`, or any reboot/upgrade verb — is out of scope for this session.**
One query burst; if the API errors or hangs, stop and record it in the
collection log; do not "troubleshoot" with writes or reboots.

## 6. Authored records (kinds 1,5)

`collection_log.json` — the session log, e.g.:

```json
{
  "session": "a1246-unit-01 first-contact read-only discovery",
  "operator": "<name>",
  "authorization_reference": "DCENT-2026-09-01-A1246-RO-DISCOVERY-bench",
  "events": [
    {"time_utc": "2026-09-01T17:05:00Z", "event": "deenergized_visual_inspection_power_down: Phase A explicitly authorized; stock shutdown, upstream AC isolation, lockout/tagout, and approved absence-of-energy/discharge check completed"},
    {"time_utc": "2026-09-01T17:10:00Z", "event": "visual_identity_inspection: miner label and psu label photographed with unit de-energized (no PSU disassembly)"},
    {"time_utc": "2026-09-01T17:20:00Z", "event": "de-energized controller compartment opened; silkscreen photographed; no cables unmounted"},
    {"time_utc": "2026-09-01T17:30:00Z", "event": "controller lid and guards reinstalled; no disturbed wiring/tools/foreign objects; chassis closed"},
    {"time_utc": "2026-09-01T17:38:00Z", "event": "closed_chassis_stock_power_restoration: Phase B separately authorized; normal closed-chassis stock power restored"},
    {"time_utc": "2026-09-01T17:40:00Z", "event": "stock_read_only_management_queries: version+stats queried over 4028 with chassis closed; responses saved"},
    {"time_utc": "2026-09-01T17:50:00Z", "event": "hashboard topology recorded; session closed; no writes/reboots performed"}
  ],
  "anomalies": [],
  "stopped_reason": null
}
```

Those six top-level keys are the exact compact log schema. Alternatively, use
the richer `collection_log.json` emitted by `k210_discovery_collect.py` and
append the Phase A events without removing or adding top-level fields. Any
non-null stop reason, collector fault, unknown stop/deviation field, or failed
command result makes the discovery receipt inadmissible.

`hashboard_topology_record.json` — the physical hash-board topology: board
count, each board's printed identifier/serial, which controller data
connectors are occupied, fan-to-board association as observed. Facts only;
this record is authored offline from the visual pass. The top-level object must
contain integer `hashboard_count` and array `hashboard_identifiers`; both must
exactly match the descriptor. Do not put `asic_family`, `profile_id`,
`stock_profile`, or any other variant label in this record: topology records
cannot force the stock-profile resolution.

## 7. Optional evidence (add only if captured)

Up to three additional kinds are admissible, each still one item with a
unique path: `stock_estats_response` (`estats` query, JSON),
`uart_pad_photo` (UART pads on the controller, canonical PNG, no probing —
photograph only), `flash_marking_photo` (flash IC marking if visible without
board removal). Add matching entries to the descriptor's evidence array with
the correct kind/method/media type; the bundle member check is exact, so no
undeclared file may exist under the evidence root paths.

## 8. Assemble, sign, and directly verify the bundle

Generate the descriptor template (host-only, verified):

```bash
py -3 DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py template \
  --model a1246 \
  --out C:\evidence\a1246-unit-01\capture.json
```

Then edit `capture.json`, replacing every placeholder:

- `authorization` — the Section 3 reference and UTC window; leave
  `authorized_actions` exactly as generated (the four phase actions).
- `actions_performed` — leave the generated booleans unchanged: the required
  shutdown/restoration means `power_state_changed` is truthfully `true`, while
  configuration, cooling commands, firmware writes, hash-work injection, and
  reboot remain `false`.
- `capture_session_id` — the fresh UUID from Section 1.
- `observer_id` — the observer principal tied to the signing key (printable,
  `^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$`, e.g. `k210-observer-01`).
- `observed_at_utc` — session close time, inside the authorization window.
- Each evidence item's `acquired_at_utc` — real UTC times within
  `[valid_from, observed_at]`.
- `identity` — the 20-field exact set. The template deliberately emits
  `asic_family = REPLACE_FROM_RESOLVED_STOCK_PROFILE`, zero numeric sentinels,
  and other visible placeholders; it is not an admissible receipt. Replace the
  ASIC field only after the captured stock tuple matches one held contract:
  `A3200LC-Plus`, `A3201-Plus`, or (for target `a1246n`) `A3200-Plus`. Generic
  `A3200`, unknown firmware tuples, topology-selected labels, placeholders, and
  contradictions between the descriptor, version response, stats response,
  or topology record are rejected. `manufacturer` remains `Canaan`,
  `marketing_model` is the exact target, and `controller_soc` remains `K210`.
  Fill the remaining fields from observation:
  `controller_board_model` / `controller_board_revision` (silkscreen,
  expected MM3v2-class), `controller_serial` (or
  `REPLACE_OR_NOT_PRESENT`-resolved value if none), `cooling_class` = `air`,
  `cooling_controller`, `fan_or_pump_count` (1..32), `hashboard_count`
  (1..8), `hashboard_identifiers` (exactly `hashboard_count` unique strings),
  `miner_serial`, `psu_model`, `psu_rated_watts` (1..10000, from the PSU
  label), `psu_serial` (or not-present resolution), and the four `stock_*`
  fields from Section 5.
- `unit_label` — `a1246-unit-01` (lowercase identifier form).

Create the signed bundle (immutable snapshot of the evidence files + canonical
receipt + SSHSIG signature under `dcent-k210-discovery-v1`; refuses to
overwrite an existing output):

```bash
py -3 DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py create \
  --capture C:\evidence\a1246-unit-01\capture.json \
  --evidence-root C:\evidence\a1246-unit-01\source \
  --private-key C:\secure\dcent-k210-observer \
  --bundle-out C:\evidence\a1246-unit-01\signed-bundle
```

Directly verify the bundle and every snapshotted byte (this proves consistency
with the supplied key; it does not by itself make the key trusted by the
gauntlet):

```bash
py -3 DCENT_OS_AvalonMiner/scripts/k210_discovery_receipt.py verify \
  --bundle C:\evidence\a1246-unit-01\signed-bundle \
  --public-key C:\secure\dcent-k210-observer.pub
```

Expected output includes `"state":"verified_signed_exact_unit_discovery"`,
`"identity_gate_eligible":true`, `"evidence_semantics_verified":true`,
`"variant_profile_id":"<exact-held-profile>"`,
`"authority_granted":false`, and
`"observer_key_id_sha256":"<64-hex>"` — that key ID must equal the pinned
`discovery_contract.trust_anchor.key_id_sha256`.

## 9. Admit into the gauntlet and confirm the gate state

With the observer key pinned (ceremony Section 5/6):

```bash
py -3 DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py check \
  --model a1246 --corpus required \
  --discovery-bundle C:\evidence\a1246-unit-01\signed-bundle
```

Expected result:

```
K210_MODEL_GATE_OK model=a1246 production_ready=false first_blocker=stock_restore
```

Gate-level expectations (add `--format json` to see the full object):

- `exact_model_identity` — qualifies: state `signed_exact_unit_discovery`,
  evidence citing the receipt ID, the unit fingerprint, and the observer key.
- `stock_restore` — **still blocked**: state `held_package_verified` (the
  pinned stock profile's AUP bytes verify, `--corpus required`) with blocker
  "held stock package is not an exact-unit backup and no restore/readback
  drill exists". With `--corpus skip` this shows `pinned_metadata_only`
  instead — blocked either way.
- `boot_policy` — still `missing_measurement`; `replacement_firmware` — still
  `packaged_safe_idle_pipeline_sentinel_only`; `asic_control`,
  `thermal_power_safety`, `rollback_recovery`, `bench_mining`,
  `endurance_faults`, `release_authority` — all still blocked.
- `production_ready` stays false; admission grants no authority.

The matrix-wide view (`verified_discovery_receipts` becomes 1):

```bash
py -3 DCENT_OS_AvalonMiner/scripts/k210_gauntlet.py report \
  --corpus required \
  --discovery-bundle C:\evidence\a1246-unit-01\signed-bundle
```

Admission constraints the gauntlet enforces on top of the bundle's own
verification: one discovery receipt per target row, no duplicate receipt IDs,
no unit fingerprint reused across rows, and the signer must be the pinned
observer key.

**If the manifest pin has not landed yet:** run Section 8 anyway (create +
direct verify). The receipt's chronology is internal to its recorded
timestamps, so a bundle created inside the authorized window remains
admissible later; run Section 9 after the pin.

## 10. Safety and boundary footer

- `w1-identityschema` is accepted, but this card remains NO-GO until the seven
  trust anchors pass `op-ceremony` and the exact physical phases are separately
  authorized. When those conditions hold,
  Phase A is de-energized/locked-out/discharged and Phase B is fully closed-
  chassis stock power; energized cover removal is never permitted.
- No power modification, no frequency/voltage/fan commanding, no PSU
  disassembly, no firmware writes, no reboots, no `ascset`/upgrade verbs —
  for the whole session, even for "quick checks". The four historical phase
  actions are exactly those in the authorization block.
- Hash boards are de-energized for every cover-open visual action. They may be
  energized only after reassembly, under the separately authorized normal
  stock Phase B. Any other power state requires its own exact authorization.
- Stop conditions (end the session, record the stop in the collection log,
  power down only through the unit's normal means if warranted): burning
  smell, visible smoke, fan failure or abnormal noise, overtemperature
  reports in `stats`, any API error or hang (do not retry with writes), any
  discovery that would require opening the PSU or unmounting
  boards/cables, or any doubt about the authorization window.
- The tools used have no miner transport; the receipt records past
  observations only and grants no contact, configuration, reboot, power,
  cooling, hashing, write, install, or release authority. The next gate
  (`stock_restore`) requires its own destructive-adjacent, separately
  authorized, dual-signed recovery drill — nothing in this session starts
  that work.
- Never commit private keys, raw credentials, pool secrets, or unredacted
  personal data into the repository or the bundle.
