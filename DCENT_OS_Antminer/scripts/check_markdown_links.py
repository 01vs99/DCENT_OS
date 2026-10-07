#!/usr/bin/env python3
"""Check local Markdown links in explicitly selected documentation.

No network access, source execution, or implicit full-corpus crawl. External URLs
and same-document anchors are excluded; local file targets must exist within the
repository. Supports inline links, angle-wrapped paths, and reference links.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[3]
INLINE = re.compile(r"!?\[[^\]\n]*\]\(\s*(<[^>]+>|[^\s)]+)(?:\s+[^)]*)?\)")
DEFINITION = re.compile(r"^\s{0,3}\[([^\]]+)\]:\s*(<[^>]+>|\S+)", re.MULTILINE)
REFERENCE = re.compile(r"!?\[([^\]\n]+)\]\[([^\]\n]*)\]")


def check_file(path: Path, root: Path = ROOT) -> list[str]:
    text = path.read_text(encoding="utf-8")
    # Examples inside fenced code blocks are not navigable document links.
    text = re.sub(r"(?ms)^\s*(`{3,}|~{3,})[^\n]*\n.*?^\s*\1\s*$", "", text)
    definitions = {label.strip().casefold(): target for label, target in DEFINITION.findall(text)}
    targets = [match.group(1) for match in INLINE.finditer(text)] + list(definitions.values())
    errors = []
    for label, reference in REFERENCE.findall(text):
        key = (reference or label).strip().casefold()
        if key not in definitions:
            errors.append(f"{path}: undefined reference [{reference or label}]")
    for target in targets:
        target = target.removeprefix("<").removesuffix(">")
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or not parsed.path:
            continue
        local = unquote(parsed.path)
        resolved = ((root / local.lstrip("/")) if local.startswith("/") else path.parent / local).resolve()
        if not resolved.is_relative_to(root.resolve()):
            errors.append(f"{path}: local link escapes repository: {target}")
        elif not resolved.exists():
            errors.append(f"{path}: missing local target: {target}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path, help="Markdown files or scoped directories")
    args = parser.parse_args()
    files: set[Path] = set()
    for path in args.paths:
        if not path.exists():
            parser.error(f"path does not exist: {path}")
        files.update(path.rglob("*.md") if path.is_dir() else [path])
    errors = [error for path in sorted(files) for error in check_file(path)]
    for error in errors:
        print(error)
    print(f"Local Markdown links: {len(files)} files, {len(errors)} errors")
    return bool(errors)


if __name__ == "__main__":
    raise SystemExit(main())
