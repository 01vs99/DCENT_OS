#!/usr/bin/env python3
"""CI gate: every Buildroot defconfig named in an authoritative doc exists on disk.

Hardware-enablement campaign 2026-08-02, IMPLEMENTATION_QUEUE rank 11 (H6 G-10).

Background: ``
claimed ``dcentos_cv1835_s19jpro_defconfig`` as a product defconfig, but the
configs dir holds exactly 12 ``*_defconfig`` files (plus 2 ``.fragment`` and a
README) and no CV1835 defconfig has ever been committed — a false capability
claim. This gate makes that class of drift a CI failure.

Scope: **authoritative current-truth docs only** (listed below). Historical
wave archives under ``docs/dev/`` deliberately stay out of scope — they record
past states (including never-committed planned defconfigs such as
``dcentos_inno_t2tz_defconfig``) and must not be edited to satisfy a gate.
Add a doc here when it becomes a current capability claim surface.

Negation rule: a token on a line that *denies* existence (e.g. the cvitek
board README's "No ``dcentos_cv1835_s19jpro_defconfig`` is committed") is a
correct claim about a missing file and is skipped. The heuristic is a
lowercase substring check for the markers in ``NEGATION_MARKERS`` on the same
line as the token.

Exit 0 on success; non-zero with printed failures otherwise.
Run ``--self-test`` to exercise the token/negation parser against fixtures.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIGS_DIR = (
    REPO_ROOT / "projects" / "dcentos" / "br2_external_dcentos" / "configs"
)

# Current-truth docs whose defconfig mentions are capability claims.
AUTHORITATIVE_DOCS = (
    REPO_ROOT / "SUPPORT_MATRIX.md",
    REPO_ROOT
    / "projects"
    / "dcentos"
    / "docs"
    / "CV1835_STATUS.md",
    CONFIGS_DIR / "README_KERNEL_VERSIONS.md",
)

TOKEN_RE = re.compile(r"\bdcentos_[a-z0-9_]+_defconfig\b")

# A token on a line containing one of these (case-insensitive) is a claim of
# ABSENCE, not existence, and is exempt from the exists-on-disk requirement.
NEGATION_MARKERS = (
    "no `",
    "not committed",
    "none on disk",
    "does not exist",
    "phantom",
    "never existed",
    "future defconfig",
)


def is_negated(line: str) -> bool:
    lowered = line.lower()
    return any(marker in lowered for marker in NEGATION_MARKERS)


def collect_claims(text: str) -> list[tuple[int, str]]:
    """Return (line_number, token) for every non-negated defconfig mention."""
    claims: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if is_negated(line):
            continue
        for token in TOKEN_RE.findall(line):
            claims.append((lineno, token))
    return claims


def main() -> int:
    failures: list[str] = []

    if not CONFIGS_DIR.is_dir():
        print(f"FAIL: configs dir missing: {CONFIGS_DIR}")
        return 1

    on_disk = {p.name for p in CONFIGS_DIR.glob("*_defconfig")}
    if len(on_disk) < 12:
        failures.append(
            f"configs dir census: expected >= 12 *_defconfig files, found "
            f"{len(on_disk)} in {CONFIGS_DIR}"
        )

    for doc in AUTHORITATIVE_DOCS:
        if not doc.is_file():
            failures.append(f"authoritative doc missing: {doc}")
            continue
        text = doc.read_text(encoding="utf-8", errors="replace")
        rel = doc.relative_to(REPO_ROOT)
        for lineno, token in collect_claims(text):
            if token not in on_disk:
                failures.append(
                    f"{rel}:{lineno} names `{token}` which does not exist in "
                    f"{CONFIGS_DIR.relative_to(REPO_ROOT)} — either commit the "
                    f"defconfig, correct the doc, or phrase the mention as an "
                    f"explicit absence claim (see NEGATION_MARKERS)."
                )

    if failures:
        print("check_defconfig_doc_references: FAIL")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(
        "check_defconfig_doc_references: OK "
        f"({len(on_disk)} defconfigs on disk; {len(AUTHORITATIVE_DOCS)} docs checked)"
    )
    return 0


def self_test() -> int:
    """Fixture tests for the token/negation parser (no filesystem access)."""
    fixture = "\n".join(
        [
            "| **AM1** | Zynq-7000 | `dcentos_s9_defconfig` |",
            "- No `dcentos_cv1835_s19jpro_defconfig` is committed. A future defconfig must",
            "plain mention dcentos_am3_s21_defconfig here",
            "twice dcentos_am3_bb_defconfig and dcentos_am3_bb_s19jpro_defconfig",
        ]
    )
    claims = collect_claims(fixture)
    expected = [
        (1, "dcentos_s9_defconfig"),
        (3, "dcentos_am3_s21_defconfig"),
        (4, "dcentos_am3_bb_defconfig"),
        (4, "dcentos_am3_bb_s19jpro_defconfig"),
    ]
    if claims != expected:
        print(f"self-test FAIL: got {claims!r}, expected {expected!r}")
        return 1
    if not is_negated("none on disk — no `dcentos_cv1835_*` defconfig"):
        print("self-test FAIL: 'none on disk' line not treated as negated")
        return 1
    if is_negated("| **AM3-BB** | AM335x | `dcentos_am3_bb_s19jpro_defconfig` |"):
        print("self-test FAIL: plain claim wrongly treated as negated")
        return 1
    print("check_defconfig_doc_references --self-test: OK")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv[1:]:
        sys.exit(self_test())
    sys.exit(main())
