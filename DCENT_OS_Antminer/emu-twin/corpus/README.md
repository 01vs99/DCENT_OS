# emu-twin/corpus — provenance-labeled vendor-capture fixtures

**Owner:** WS9 / RE-corpus workstream (DCENT_RE). Campaign:
 (WS9 corpus wave 1, agent I4).

**Fund/support:** https://d-central.tech/fund/

## What lives here

Competitor-firmware captures distilled into **data tables + behavioral notes** for the
emulation twin: expected-power oracles, preset tables, silicon characterization curves,
board/facility policy maps. Every file starts with a `_provenance` (or PROVENANCE HEADER)
block: source path, capture date, label, method, caveats. `PROVENANCE_MANIFEST.md` carries
one line per artifact — the orchestrator's commit gate checks it.

## Oracle-class policy (BINDING — plan.md §11 C2-F2)

**measured-anchor := measured by DCENT_OS instrumentation on DCENT_OS-controlled
hardware. Nothing else.**

Every artifact in this directory is **ORACLE-CLASS**:
- usable for: emulation-twin expected-value oracles, convergence/sanity bounds, parity
  test targets, displayed vendor-comparison references, clean-room behavioral specs.
- NEVER usable as: a shipped DCENT_OS default profile/preset/constant. Competitor
  firmware captures (any provenance label ending in `-proprietary`) must not leak into
  shippable defaults through `PointConfidence::Measured` or any other path.

## GPL quarantine (plan.md §11 C2 majors)

No GPL-licensed corpus code, Braiins headers, or vendor source may enter this directory's
consumers in `emu-twin/` or `tools/trust/` (MIT/Apache tooling). This directory holds
**data tables and behavioral facts with provenance labels only** — no vendor code. Any
adoption of [BRAIINS-OS-GPL] base code into the (GPL-3.0) firmware itself is a separate
decision with attribution/source-offer obligations.

## Artifacts (wave 1)

| File | Contents | Label |
|---|---|---|
| `vnish_presets_1_3_5_delta.json` | VNish 1.3.5 universal preset DB (752 rows, 38 arrays), row-level delta vs 1.2.7 master (764 rows), key-surface delta, signature scheme, 47-tarball manifest | [VNISH-proprietary] |
| `braiins_20260915_policy_notes.md` | Braiins OS/OS+ 26.08.1 (+22.08.1/23.10.1) ssh-package census: boot/process policy, GPIO/fan map, tuner packaging, feeds status | [BRAIINS-OS-GPL] + [BRAIINS-OS+-proprietary] |
| `luxos_bm1362_21step.json` | LuxOS 21-step BM1362 V/f/W/TH silicon table (Step −16..+4) with per-row provenance | [LUXOS-proprietary] |

`raw/` is scratch (gitignored): read-only copies used during extraction; deletable at any
time — all durable data is in the three fixtures above and the KB notes.

## ePIC note

No ePIC artifacts this wave. If added later, the six mandatory caveats (root ,
2026-08-01 rule) go in the per-artifact header AND the manifest line.
