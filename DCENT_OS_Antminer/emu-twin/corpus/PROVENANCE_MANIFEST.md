# PROVENANCE MANIFEST — emu-twin/corpus

One line per artifact. Format: `file | source corpus | label | oracle-class | caveats`.
The orchestrator's commit gate checks this file before any corpus artifact is committed
(plan.md §11 C2, mechanized corpus review gate).

| file | source corpus | label | oracle-class | caveats |
|---|---|---|---|---|
| `vnish_presets_1_3_5_delta.json` |  (47 tarballs) + baseline  (1.2.6/1.2.7) + refs `research/protocols/POWER_PROFILES_CATALOG.md`, `research/re-armada-2026-04-25/thermal-vnish-*` | [VNISH-proprietary] | YES — never a shipped default (C2-F2) | strings-only desk extraction; power-target pairs (V/f derived at runtime, not stored); S21-family hydro sibling attribution ambiguous where rows shared (label_confidence marks); thermal/fan numeric constants compiled not string-extractable (key surface only); vendor planning tables, not unit measurements |
| `braiins_20260915_policy_notes.md` |  (5 ssh tarballs) + refs `extractions/s19k/live-probe-78-2026-04-29/`, `extractions/s9/braiins_*.rs` | [BRAIINS-OS-GPL] (scripts/board policy) + [BRAIINS-OS+-proprietary] (bosminer/boser/tuner facts) | YES — behavioral oracles/parity targets only; GPL code adoption is separate GPL-3.0-obligations decision | ssh packages = first-stage initramfs only (bosminer.toml templates/updater feeds live in system partition, not held here); am1-s9/am2-s17 sysupgrade root is squashfs (not unpacked); cvitek rootfs container unparsed (magic 1a853802); 26.08.1 bosminer/boser UPX-packed so tuner strings not directly greppable (held 0.9.0 unpacked binaries remain authoritative) |
| `luxos_bm1362_21step.json` |  (from own .79 unit live capture `captures/08-cgminer-api.txt` + operator anchors) | [LUXOS-proprietary, captured from own .79 unit running LuxOS] | YES — golden twin oracle / convergence bound; NEVER a shipped default (C2-F2) | 13/21 rows live-provenance (12 verbatim + Step 0 anchor); 8 rows reconstructed by proven linear cadence (+25 MHz/+0.150 V per step) and flagged row_provenance=reconstructed — re-verify on next live session; Step +4 voltage may clamp at APW 14.5 V; dsPIC DAC granularity ~0.03 V (targets, not absolutes); watts AC-side (PSU losses in); single-unit single-silicon sample = bounds, not law |
| `README.md` | (this directory's policy doc) | [DCENT-internal] | n/a | binding statements of C2-F2 measured-anchor definition + GPL quarantine; fund link |
| `PROVENANCE_MANIFEST.md` | (this file) | [DCENT-internal] | n/a | keep 1 line per artifact; update in same change as any new/modified artifact |

Scratch: `raw/` (gitignored) holds transient read-only copies (hwscan binaries, cpio
extracts, intermediate JSONs). Not committed, not referenced by fixtures' consumers;
safe to delete. Held corpora were never modified in place.
