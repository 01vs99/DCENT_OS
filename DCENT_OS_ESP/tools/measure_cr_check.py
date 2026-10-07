#!/usr/bin/env python3
"""measure_cr_check.py - DCENT_axe UI Gauntlet embedded-asset CR refusal (P1-I6).

WHY THIS FILE EXISTS
====================
`main.rs` proved (rustc 1.90 experiment, `PROGRESS.md` 2026-09-03 ~14:10/~14:35):
`include_str!` KEEPS carriage-return bytes. `dashboard.rs` bakes its CSS/JS
assets in with `include_str!`, so a CRLF checkout (Windows `core.autocrlf=true`
worktrees) inflates the built image by roughly one byte per embedded line -
measured as **1,893 CR bytes** in one worktree's embedded assets vs 0 on `main`
(lane P1-O2's station run). The measurement station used to build straight from
whatever line endings the tree happened to have, so a CRLF worktree quietly
produced byte-budget numbers that were not comparable to an LF baseline - the
lead's `station_lf_copy.sh` exists only because nothing else caught this.

This script is the CLOSED check `P1-O4-r1`/the P1-I3 successor asked for: it
enumerates dashboard.rs's embedded assets from the `include_str!`/`include_bytes!`
macro invocations THEMSELVES (never a hard-coded list, so a new asset is
covered the moment it is embedded), reports on-disk bytes / CR-byte count /
LF-normalised bytes per file, and FAILS CLOSED when any CR byte is present -
unless `--allow-cr` is given, in which case it prints a loud warning and still
succeeds (for a deliberate CRLF-checkout smoke run that is not measuring bytes).

USAGE
=====
  python tools/measure_cr_check.py --dcentaxe-src <path/to/dcentaxe/src> [--allow-cr] [--json <out>]

Exit codes:
  0 = every enumerated file has 0 CR bytes, OR CR bytes are present and
      --allow-cr was given (a warning is still printed to stderr)
  2 = CR bytes are present and --allow-cr was NOT given (FAIL CLOSED), or
      dashboard.rs / a file it names via include_str!/include_bytes! could not
      be found on disk
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

# Matches `include_str!("dashboard/foo.js")` / `include_bytes!("dashboard/foo.png")`.
# Deliberately NOT the `concat!(env!("CARGO_MANIFEST_DIR"), "...")` shape used
# elsewhere in this workspace (e.g. dcentaxe-core's `main.rs` source contracts) -
# dashboard.rs embeds its own assets with a plain relative string literal, and
# this pattern is what actually appears there today. A future asset embedded a
# different way would not be enumerated by this regex; that is a scanner
# limitation, not a silent allowlist - re-check this pattern if dashboard.rs's
# embedding style ever changes.
INCLUDE_RE = re.compile(r'include_(?:str|bytes)!\(\s*"([^"]+)"\s*\)')


def enumerate_assets(dcentaxe_src: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """Returns (relative_paths, error). `relative_paths[0]` is always
    `dashboard.rs` itself; the rest are every distinct path named by an
    `include_str!`/`include_bytes!` invocation inside it, in file order."""
    dashboard_rs = os.path.join(dcentaxe_src, "dashboard.rs")
    if not os.path.isfile(dashboard_rs):
        return None, f"dashboard.rs not found at {dashboard_rs}"
    with open(dashboard_rs, "r", encoding="utf-8", newline="") as fh:
        text = fh.read()
    paths = ["dashboard.rs"]
    for m in INCLUDE_RE.finditer(text):
        rel = m.group(1)
        if rel not in paths:
            paths.append(rel)
    return paths, None


def measure(dcentaxe_src: str, rel_paths: List[str]) -> Tuple[List[Dict[str, Any]], List[str], int]:
    rows: List[Dict[str, Any]] = []
    missing: List[str] = []
    total_cr = 0
    for rel in rel_paths:
        full = os.path.join(dcentaxe_src, rel.replace("/", os.sep))
        if not os.path.isfile(full):
            missing.append(rel)
            continue
        with open(full, "rb") as fh:
            blob = fh.read()
        on_disk = len(blob)
        cr = blob.count(b"\r")
        lf = on_disk - cr
        total_cr += cr
        rows.append(
            {
                "path": rel,
                "on_disk_bytes": on_disk,
                "cr_bytes": cr,
                "lf_normalised_bytes": lf,
            }
        )
    return rows, missing, total_cr


def print_table(rows: List[Dict[str, Any]]) -> None:
    print(f"{'path':45s} {'on-disk':>10s} {'cr':>6s} {'lf-normalised':>14s}")
    for r in rows:
        marker = "  <-- CRLF" if r["cr_bytes"] else ""
        print(
            f"{r['path']:45s} {r['on_disk_bytes']:10d} {r['cr_bytes']:6d} "
            f"{r['lf_normalised_bytes']:14d}{marker}"
        )


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dcentaxe-src", required=True, help="path to dcentaxe/src")
    ap.add_argument(
        "--allow-cr",
        action="store_true",
        help="print a loud warning and exit 0 instead of refusing when CR bytes are found",
    )
    ap.add_argument("--json", help="also write the per-file rows + total as JSON to this path")
    args = ap.parse_args(argv)

    rel_paths, err = enumerate_assets(args.dcentaxe_src)
    if err:
        print(f"measure_cr_check: {err}", file=sys.stderr)
        return 2

    assert rel_paths is not None
    rows, missing, total_cr = measure(args.dcentaxe_src, rel_paths)
    if missing:
        print(
            "measure_cr_check: asset(s) named by include_str!/include_bytes! in "
            "dashboard.rs do not exist on disk: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2

    print_table(rows)
    print(f"TOTAL CR bytes across {len(rows)} embedded-asset file(s): {total_cr}")

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"files": rows, "total_cr_bytes": total_cr}, fh, indent=2)
            fh.write("\n")

    if total_cr == 0:
        print("measure_cr_check: PASS (0 CR bytes)")
        return 0

    if args.allow_cr:
        print(
            f"measure_cr_check: WARNING - {total_cr} CR byte(s) found across the embedded "
            "dashboard assets (CRLF checkout). --allow-cr was given, so the station "
            "continues, but every byte-budget figure this run produces is INFLATED by "
            "roughly one byte per embedded CRLF line and must NOT be compared against an "
            "LF baseline. See tools/README.md \"CR refusal\".",
            file=sys.stderr,
        )
        return 0

    print(
        f"measure_cr_check: REFUSED - {total_cr} CR byte(s) found across the embedded "
        "dashboard assets. `include_str!` keeps carriage returns, so a CRLF checkout "
        "inflates the image by roughly one byte per embedded line (measured: 1,893 CR "
        "bytes on one worktree, PROGRESS.md 2026-09-03 ~14:10). Normalise the checkout to "
        "LF (see tools/README.md \"CR refusal\") or re-run with --allow-cr to proceed "
        "anyway with a loud warning.",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
