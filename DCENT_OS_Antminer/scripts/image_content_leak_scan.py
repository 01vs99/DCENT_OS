#!/usr/bin/env python3
"""Fail when a staged DCENT_OS rootfs carries internal lab/workspace details.

Release images must not ship operator lab identity (a specific unit's MAC,
home/office LAN addresses, the ``xil`` home-unit seed), workspace paths, or
internal citations (memory-rule slugs, ``, ``,
``). This scanner walks a staged root filesystem (Buildroot
``TARGET_DIR`` or an extracted image rootfs) and reports every text-file hit.

Scope:

* Only text files are scanned (a NUL byte in the first 8 KiB or an ELF/other
  binary magic marks a file as binary and it is skipped). Small ``.gz`` members
  are decompressed and scanned as text. Symlinks are never followed.
* "Strong" patterns (unit MAC, ``xil``, workspace paths, operator account)
  apply to every text file in the tree.
* Memory-rule slugs are ``feedback_*`` identifiers and multi-word
  ``reference_*`` / ``project_*`` identifiers (or such ``.md`` names); short
  API field names like  are not slugs.
* "Owned" patterns (lab IP prefixes, memory-rule slugs, internal doc paths)
  apply to every text file outside third-party package trees (``usr/lib/``,
  ``lib/``, ``usr/share/`` other than DCENT_OS's own share directories, and
  ``usr/include/``), so vendor/package text cannot false-positive.

Exit status: 0 clean, 1 findings, 2 usage error. Host-only; no network,
hardware, or rootfs mutation.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_TEXT_BYTES = 64 * 1024 * 1024
MAX_GZIP_BYTES = 16 * 1024 * 1024
BINARY_MAGICS = (b"\x7fELF", b"hsqs", b"\x89PNG", b"\xff\xd8\xff", b"GIF8", b"PK\x03\x04")

# Joined from parts so this scanner's own source never matches itself if it
# is ever scanned.
_MAC = "32:30:41:27" + ":f6:ab"
_WORKSPACE = "DCENT " + "Projects"
_ACCOUNT = "Kry" + "pt"

STRONG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("lab-unit-mac", re.compile(re.escape(_MAC), re.IGNORECASE)),
    ("xil-home-unit", re.compile("xil" + "25", re.IGNORECASE)),
    ("workspace-path", re.compile(re.escape(_WORKSPACE))),
    ("wsl-workspace-mount", re.compile(r"/mnt/d/")),
    ("windows-user-path", re.compile(r"C:[\\/]+Users", re.IGNORECASE)),
    # Word-bounded so pool names such as "Kryptex" are not flagged.
    ("operator-account", re.compile(r"\b" + _ACCOUNT + r"(?:ykHex)?\b")),
)

# Memory-rule slugs: every ``feedback_*`` identifier, plus ``reference_*`` /
# ``project_*`` identifiers that are either ``.md`` file names or have at least
# three further words ( is an API field, not a slug).
_SLUG_PREFIX = r"(?<![A-Za-z0-9_])"
_SLUG = re.compile(
    _SLUG_PREFIX + "feed" + r"back_[a-z0-9_]{6,}"
    + "|" + _SLUG_PREFIX + r"(?:refer" + r"ence|pro" + r"ject)_[a-z0-9_]{4,}\.md\b"
    + "|" + _SLUG_PREFIX + r"(?:refer" + r"ence|pro" + r"ject)(?:_[a-z0-9]+){3,}"
)

OWNED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("lab-ip-192.168.101", re.compile(r"(?<![0-9.])192\.168\.101\.[0-9]")),
    ("lab-ip-10.0.1", re.compile(r"(?<![0-9.])10\.0\.1\.[0-9]")),
    ("memory-rule-slug", _SLUG),
    ("internal-doc-path", re.compile(r"docs/(?:dev|reviews)/")),
    ("knowledge-base-path", re.compile("knowledge" "-base/")),
    ("claude-md", re.compile("CLAUDE" r"\.md")),
)

# Exact, content-pinned exceptions: (rootfs path, rule, sha256 of the stripped
# line). Each entry tolerates ONE known line whose source file is SHA-pinned by
# a sealed campaign manifest and therefore cannot be scrubbed in place; any
# other line (or any edit of these lines) is still reported.
#   etc/init.d/S82dcentrald (Amlogic shared overlay): pinned by the S19k office
#   gauntlet campaign source manifest; scrub at the next campaign re-pin.
PINNED_LINE_EXCEPTIONS: frozenset[tuple[str, str, str]] = frozenset(
    {
        (
            "etc/init.d/S82dcentrald",
            "memory-rule-slug",
            "b565e92675868c991dc5ef028fea0226ebb63a222af53f8ca8eeeee9828c9aa7",
        ),
        (
            "etc/init.d/S82dcentrald",
            "memory-rule-slug",
            "417f489645c2404c83bd034d6bbdd440438a11d5335be23e5a5de7a6550e7d90",
        ),
        (
            "etc/init.d/S82dcentrald",
            "memory-rule-slug",
            "8a43bf112f225fecc707df1361cd157c49723896fd30dbe01706f8dd894c2b26",
        ),
    }
)

VENDOR_PREFIXES =("usr/lib/", "lib/", "usr/include/", "usr/share/")
OWNED_EXCEPTIONS = ("lib/functions/", "usr/share/dcentos", "usr/share/dcent")


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    rule: str
    excerpt: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: [{self.rule}] {self.excerpt}"


def _is_owned(rel: str) -> bool:
    if rel.startswith(OWNED_EXCEPTIONS):
        return True
    return not rel.startswith(VENDOR_PREFIXES)


def _looks_binary(head: bytes) -> bool:
    return b"\0" in head[:8192] or head.startswith(BINARY_MAGICS)


def _read_text(path: Path) -> str | None:
    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_TEXT_BYTES:
        return None
    data = path.read_bytes()
    if path.name.endswith(".gz") and data[:2] == b"\x1f\x8b":
        try:
            with gzip.open(path, "rb") as handle:
                data = handle.read(MAX_GZIP_BYTES + 1)
        except (OSError, EOFError):
            return None
        if len(data) > MAX_GZIP_BYTES:
            return None
    if _looks_binary(data):
        return None
    return data.decode("utf-8", errors="replace")


def scan_text(rel: str, text: str) -> list[Finding]:
    patterns = STRONG_PATTERNS + (OWNED_PATTERNS if _is_owned(rel) else ())
    findings: list[Finding] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in patterns:
            match = pattern.search(line)
            if match:
                digest = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
                if (rel, rule, digest) in PINNED_LINE_EXCEPTIONS:
                    continue
                start = max(0, match.start() - 40)
                excerpt = line[start : match.end() + 40].strip()
                findings.append(Finding(rel, lineno, rule, excerpt[:160]))
    return findings


def scan_tree(root: Path) -> list[Finding]:
    root = root.resolve()
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            text = _read_text(path)
            if text is None:
                continue
            findings.extend(scan_text(rel, text))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("rootfs", type=Path, help="staged rootfs directory (Buildroot TARGET_DIR)")
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = parser.parse_args(argv)
    if not args.rootfs.is_dir():
        print(f"image-content-leak-scan: not a directory: {args.rootfs}", file=sys.stderr)
        return 2
    findings = scan_tree(args.rootfs)
    if args.json:
        print(json.dumps([f.__dict__ for f in findings], indent=2))
    else:
        for finding in findings:
            print(finding.render(), file=sys.stderr)
    if findings:
        print(
            f"image-content-leak-scan: FAIL: {len(findings)} internal/lab detail(s) in {args.rootfs}",
            file=sys.stderr,
        )
        return 1
    print(f"image-content-leak-scan: OK: no internal/lab details in {args.rootfs}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
