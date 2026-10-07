#!/usr/bin/env python3
"""measure_assemble.py - the ONE writer of the DCENT_axe Gauntlet `measure.json`.

WHY THIS FILE EXISTS
====================
`tools/measure_image.sh` and `tools/measure_image.ps1` are two ports of the same
measurement station (GAUNTLET_LOOP.md Stage M). Round 1 of lane `P1-I3` shipped
them with two independent JSON writers - a Python heredoc in the shell script and
a `ConvertTo-Json` over PowerShell hashtables in the other - and they did not
agree on the shape of the document a blind critic is handed:

  * `xtensa_check` was a JSON array from the shell port; from PowerShell it was
    whatever the pipeline happened to produce - `null` for zero boards, a bare
    string for one board, an array only for two or more (PowerShell unrolls
    single-element pipelines).
  * `boards` and `host_gate.suites` were dictionaries in one port and
    `[ordered]@{}` in the other, which `ConvertTo-Json` renders as `{}` but which
    a mis-typed local had already once coerced into a string array (the round-1
    `$boards`/`[string[]]$Boards` collision that made the station unrunnable on
    Windows).

A critic comparing two lanes measured on two different machines would be diffing
two different schemas without being told. So the ports no longer WRITE anything:
they each produce three plain TSV/JSON inputs in a work directory and hand them
to this module, which is the single source of the document's shape.

Divergence is now impossible by construction, and `tools/check_measure_ports.py`
proves it end to end by running both ports and diffing their output.

INPUTS (all in <work>, all optional except handlers.json)
========================================================
  handlers.json  the `--json` output of tools/count_handlers.py
  boards.tsv     one row per board, tab separated, no header:
                 board, bytes, slot, text, data, bss, flash_size, image_path
  gate.tsv       one row per host-gate suite, tab separated, no header:
                 label, passed, failed, status

USAGE
=====
  python tools/measure_assemble.py --work <dir> --root <DCENT_OS_ESP>
                                   --repo <repo root> --out <measure.json>
                                   --lane <id> [--baseline <measure.json>]
  python tools/measure_assemble.py --schema      # print the schema skeleton

Exit codes: 0 = written and every measured board fits its OTA slot;
            1 = a board's image exceeds its slot, or an input is unreadable.
Fail-closed: an image that does not fit is a failed lane, never a warning.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List

# Bump when the document's shape changes. It is written into measure.json so a
# critic can tell two documents apart, and `check_measure_ports.py` asserts both
# ports carry the same one.
SCHEMA_VERSION = 1

# The exact top-level keys, in order. `baseline` / `delta_vs_baseline` appear
# only when a baseline was supplied; everything else is unconditional, so an
# absent board list is `{}` and an absent gate is a zeroed object - never a
# missing key, and never `null`.
TOP_LEVEL_KEYS = [
    "schema_version",
    "lane",
    "commit",
    "boards",
    "handlers",
    "host_gate",
    "xtensa_check",
    "assets",
]
OPTIONAL_KEYS = ["baseline", "delta_vs_baseline"]

BOARD_KEYS = [
    "bytes", "slot", "percent_used", "fits_slot",
    "text", "data", "bss", "flash_size", "image",
]

ASSET_SOURCES = [
    "dcentaxe/src/dashboard.rs",
    "dcentaxe/src/api.rs",
    "dcentaxe/src/main.rs",
    "dcentaxe/src/mcp.rs",
    "dcentaxe/src/auth.rs",
]


def read_tsv(work: str, name: str) -> List[List[str]]:
    path = os.path.join(work, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [line.rstrip("\r\n").split("\t") for line in fh if line.strip()]


def build_boards(rows: List[List[str]], repo: str) -> Dict[str, Dict[str, Any]]:
    boards: Dict[str, Dict[str, Any]] = {}
    for board, byts, slot, text, data, bss, flash, img in rows:
        # Both ports hand over whatever path they built; the document always
        # carries a repo-relative forward-slash path, so two machines with
        # different checkout roots produce comparable evidence.
        if os.path.isabs(img):
            try:
                img = os.path.relpath(img, repo)
            except ValueError:
                pass
        b, s = int(byts), int(slot)
        boards[board] = {
            "bytes": b,
            "slot": s,
            "percent_used": round(100.0 * b / s, 2) if s else None,
            "fits_slot": b <= s,
            "text": int(text),
            "data": int(data),
            "bss": int(bss),
            "flash_size": flash,
            "image": img.replace("\\", "/"),
        }
    return boards


def build_host_gate(rows: List[List[str]]) -> Dict[str, Any]:
    host_gate: Dict[str, Any] = {"passed": 0, "failed": 0, "suites": {}}
    for label, passed, failed, status in rows:
        host_gate["suites"][label] = {
            "passed": int(passed), "failed": int(failed), "status": status
        }
        host_gate["passed"] += int(passed)
        host_gate["failed"] += int(failed)
    return host_gate


def build_assets(root: str) -> Dict[str, Any]:
    paths = list(ASSET_SOURCES)
    asset_dir = os.path.join(root, "dcentaxe", "src", "dashboard")
    if os.path.isdir(asset_dir):
        for name in sorted(os.listdir(asset_dir)):
            if name.endswith((".css", ".js")):
                paths.append("dcentaxe/src/dashboard/" + name)

    assets: Dict[str, Any] = {}
    include_str_total = 0
    for rel in paths:
        full = os.path.join(root, rel.replace("/", os.sep))
        if not os.path.exists(full):
            continue
        size = os.path.getsize(full)
        # Count lines the same way on both ports: number of `\n`-terminated runs,
        # plus a trailing unterminated line if the file does not end in a newline.
        with open(full, "rb") as fh:
            blob = fh.read()
        lines = blob.count(b"\n") + (1 if blob and not blob.endswith(b"\n") else 0)
        assets[rel] = {"bytes": size, "lines": lines}
        if "/dashboard/" in rel:
            include_str_total += size
    assets["_include_str_asset_total"] = {"bytes": include_str_total}
    return assets


def git_commit(repo: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", repo, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30,
        )
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def schema_skeleton() -> Dict[str, Any]:
    """The document's shape, as a key -> type-name map. Used by the port check."""
    return {
        "schema_version": "int",
        "lane": "str",
        "commit": "str",
        "boards": {"<board>": {k: "scalar" for k in BOARD_KEYS}},
        "handlers": {
            "used": "int", "cap": "int", "headroom": "int",
            "estimate_const": "int", "estimate_matches_measured": "bool",
            "per_file": {"<file>": "object"}, "delta": "int (only with --baseline)",
        },
        "host_gate": {"passed": "int", "failed": "int",
                      "suites": {"<label>": {"passed": "int", "failed": "int",
                                             "status": "str"}}},
        "xtensa_check": "list[str] (always a list, even for 0 or 1 board)",
        "assets": {"<path>": {"bytes": "int", "lines": "int"}},
        "baseline": "str (only with --baseline)",
        "delta_vs_baseline": "{<board>: int} (only with --baseline)",
    }


def assemble(work: str, root: str, repo: str, lane: str, baseline: str) -> Dict[str, Any]:
    with open(os.path.join(work, "handlers.json"), encoding="utf-8") as fh:
        handlers = json.load(fh)

    boards = build_boards(read_tsv(work, "boards.tsv"), repo)
    host_gate = build_host_gate(read_tsv(work, "gate.tsv"))

    result: Dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "lane": lane,
        "commit": git_commit(repo),
        "boards": boards,
        "handlers": {
            "used": handlers.get("used"),
            "cap": handlers.get("cap"),
            "headroom": handlers.get("headroom"),
            "estimate_const": handlers.get("estimate_const"),
            "estimate_matches_measured": handlers.get("estimate_matches_measured"),
            "per_file": handlers.get("per_file"),
        },
        "host_gate": host_gate,
        # ALWAYS a list. The PowerShell port used to emit a bare string here for a
        # single board and `null` for none, because PowerShell unrolls pipelines.
        "xtensa_check": sorted(boards),
        "assets": build_assets(root),
    }

    if baseline and os.path.exists(baseline):
        with open(baseline, encoding="utf-8") as fh:
            base = json.load(fh)
        result["baseline"] = os.path.relpath(baseline, repo).replace("\\", "/")
        result["delta_vs_baseline"] = {
            b: boards[b]["bytes"] - base.get("boards", {}).get(b, {}).get("bytes", 0)
            for b in sorted(boards) if b in base.get("boards", {})
        }
        base_used = base.get("handlers", {}).get("used")
        if base_used is not None and handlers.get("used") is not None:
            result["handlers"]["delta"] = handlers["used"] - base_used

    return result


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--schema", action="store_true",
                    help="print the schema skeleton and exit")
    ap.add_argument("--work", help="directory holding handlers.json/boards.tsv/gate.tsv")
    ap.add_argument("--root", help="DCENT_OS_ESP")
    ap.add_argument("--repo", help="repository root")
    ap.add_argument("--out", help="measure.json to write")
    ap.add_argument("--lane", default="baseline")
    ap.add_argument("--baseline", default="")
    args = ap.parse_args(argv)

    if args.schema:
        print(json.dumps(schema_skeleton(), indent=2))
        return 0

    for required in ("work", "root", "repo", "out"):
        if not getattr(args, required):
            ap.error(f"--{required} is required unless --schema is given")

    result = assemble(args.work, args.root, args.repo, args.lane, args.baseline)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    print("wrote " + args.out)

    over = [b for b, v in result["boards"].items() if not v["fits_slot"]]
    if over:
        print("image exceeds OTA slot: " + ", ".join(sorted(over)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
