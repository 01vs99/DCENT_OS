#!/usr/bin/env python3
"""Export the release-train install-route catalog for the toolbox (C2 lane).

Campaign:  lane C2
("Homer friendly" pleb install). The toolbox's guided install flow needs the
authoritative per-model install routes — the SAME data
``release_train.py --plan`` composes — without importing the firmware repo at
runtime (the toolbox ships to PyPI as a standalone package).

This exporter is the single generation point for
``../dcent-toolbox/src/dcent_toolbox/data/install_route_catalog.json``:

  * train targets and their publish postures come from ``release_train.TARGETS``
    (never re-typed here);
  * admission rings come from the same ``board_desc.rs`` parser the train uses
    (``release_train.load_admissions``);
  * the generated JSON records the exporting git HEAD so a drift test can pin
    the catalog to the commit that produced it.

Run from ``DCENT_OS_Antminer/scripts`` (or anywhere; paths resolve via
``__file__``):

    python3 export_install_route_catalog.py            # write the toolbox copy
    python3 export_install_route_catalog.py --check    # verify no drift

The toolbox side fails CLOSED when the catalog is absent or malformed, and
cross-checks every row against the generated hardware-enablement matrix at
runtime — the catalog carries routes, the matrix stays the install authority.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, SCRIPT_DIR)
import release_train as train  # noqa: E402

SCHEMA_VERSION = 1
DEFAULT_OUTPUT = os.path.normpath(
    os.path.join(
        os.path.dirname(SCRIPT_DIR),  # DCENT_OS_Antminer
        "..",
        "dcent-toolbox",
        "src",
        "dcent_toolbox",
        "data",
        "install_route_catalog.json",
    )
)

# Friendly model display names for the catalog rows. Presentation only — every
# installability FACT in the catalog is composed from release_train data.
DISPLAY_NAMES = {
    "s9": "Antminer S9",
    "s9i": "Antminer S9i",
    "s9j": "Antminer S9j",
    "s9se": "Antminer S9 SE (C43)",
    "s9k": "Antminer S9k (C43)",
    "s15": "Antminer S15 (BM1391)",
    "t15": "Antminer T15 (BM1391)",
    "am2-s19jpro": "Antminer S19j Pro (XIL Zynq control board)",
    "am3-s19kpro": "Antminer S19k Pro",
    "am3-s19xp": "Antminer S19 XP",
    "am3-s19jxp": "Antminer S19j XP",
    "am2-s19pro": "Antminer S19 Pro",
    "s17-s17pro": "Antminer S17 / S17 Pro",
    "s17plus": "Antminer S17+",
    "t17": "Antminer T17",
    "t17plus": "Antminer T17+",
}

# Guide document per train target (docs/guides/ in the toolbox). Empty string
# means no dedicated quickstart yet — surfaced honestly by the toolbox.
GUIDES = {
    "s9": "quickstart-s9.md",
    "s9i": "quickstart-native-am1-sd.md",
    "s9j": "quickstart-native-am1-sd.md",
    "s9se": "quickstart-native-am1-sd.md",
    "s9k": "quickstart-native-am1-sd.md",
    "s15": "quickstart-bm1391-sd.md",
    "t15": "quickstart-bm1391-sd.md",
    "am2-s19jpro": "quickstart-s19j-pro.md",
    "am3-s19kpro": "quickstart-s19k-pro.md",
    "s17-s17pro": "quickstart-s17-family-sd-trial.md",
    "s17plus": "quickstart-s17-family-sd-trial.md",
    "t17": "quickstart-s17-family-sd-trial.md",
    "t17plus": "quickstart-s17-family-sd-trial.md",
}


def _source_git_head(dcentos_dir: str) -> str:
    """HEAD of the newest commit that touched the catalog's source files.

    Recording the branch HEAD would force a regen on every unrelated commit;
    pinning to the last commit that changed release_train.py / board_desc.rs
    keeps ``--check`` stable until the sources actually change.
    """
    sources = [
        "scripts/release_train.py",
        "scripts/release_producer.py",
        "dcentrald/dcentrald-common/src/board_desc.rs",
    ]
    heads = []
    for rel in sources:
        head = ""
        # Windows-created linked worktrees contain a drive-letter gitdir that
        # Linux Git cannot resolve. WSL may use Windows Git for this read-only
        # lookup; it must produce the same catalog on both hosts.
        programs = ["git"]
        if os.name != "nt" and shutil.which("git.exe"):
            programs.append("git.exe")
        for program in programs:
            try:
                completed = subprocess.run(
                    [program, "log", "-1", "--format=%H", "--", rel],
                    cwd=dcentos_dir, capture_output=True, text=True, check=True,
                )
                head = completed.stdout.strip()
                break
            except (OSError, subprocess.CalledProcessError):
                continue
        if head:
            heads.append(head)
    return heads[0] if heads else "unknown"


def build_catalog(dcentos_dir: str | None = None) -> dict:
    """Compose the catalog from release_train.TARGETS + board_desc rings."""
    dcentos_dir = dcentos_dir or train.DCENTOS_DIR
    admissions = train.load_admissions(dcentos_dir)
    aliases = train.load_aliases(dcentos_dir)

    routes = []
    for target in train.TARGETS:
        ring = admissions.get(target.board_target, "Unknown")
        routes.append({
            "train_name": target.name,
            "display_name": DISPLAY_NAMES.get(target.name, target.name),
            "board_target": target.board_target,
            "canonical_board_target": train.canonical_board_target(
                target.board_target, aliases
            ),
            "install_route": target.install_route,
            "admission_ring": ring,
            "channel": ring.lower(),
            "artifact_kind": (
                "sd_boot_trial"
                if target.install_route == train.ROUTE_SD_TRIAL
                else "sysupgrade"
            ),
            "executable_lane": bool(target.lane_command),
            "blocked_reason": target.blocked_reason,
            "train_notes": target.notes,
            "guide": GUIDES.get(target.name, ""),
        })

    return {
        "schema_version": SCHEMA_VERSION,
        "source": "DCENT_OS_Antminer/scripts/release_train.py",
        "admissions_source": (
            "DCENT_OS_Antminer/dcentrald/dcentrald-common/src/board_desc.rs"
        ),
        "generated_utc": dt.datetime.now(dt.timezone.utc).isoformat(
            timespec="seconds"
        ),
        "generated_from_git_head": _source_git_head(dcentos_dir),
        "publish_state": (
            "no_signed_images_published_yet_drop_1_pending_key_ceremony"
        ),
        "routes": sorted(routes, key=lambda row: row["train_name"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help="output JSON path (default: the toolbox data copy)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="verify the existing file matches a fresh export; exit 1 on drift",
    )
    args = parser.parse_args(argv)

    catalog = build_catalog()
    payload = json.dumps(catalog, indent=2, sort_keys=True) + "\n"

    def _stable(text: str) -> str:
        """Drop the volatile generation timestamp so --check is deterministic."""
        catalog_json = json.loads(text)
        catalog_json.pop("generated_utc", None)
        return json.dumps(catalog_json, indent=2, sort_keys=True)

    if args.check:
        try:
            with open(args.output, "r", encoding="utf-8") as handle:
                current = handle.read()
        except OSError:
            print(f"DRIFT: {args.output} is missing — regenerate it", file=sys.stderr)
            return 1
        try:
            matches = _stable(current) == _stable(payload)
        except json.JSONDecodeError:
            matches = False
        if not matches:
            print(
                f"DRIFT: {args.output} does not match release_train.py — "
                "regenerate with export_install_route_catalog.py",
                file=sys.stderr,
            )
            return 1
        print("OK: install route catalog matches release_train.py")
        return 0

    with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(payload)
    print(f"wrote {args.output} ({len(catalog['routes'])} routes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
