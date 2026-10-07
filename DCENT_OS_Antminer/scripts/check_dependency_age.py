#!/usr/bin/env python3
"""Enforce seven full days since crates.io publication for changed locked packages.

Python 3.11+ uses the standard library; Python 3.9/3.10 need tomli (see
requirements-supply-chain.txt). No Cargo nightly flags or build scripts.
The base revision is resolved to a commit before reading its lock. Network or
metadata ambiguity fails closed. Emergency exceptions waive age only, never a
checksum mismatch, yanked version, unknown source, or failed registry lookup.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.9/3.10 developer hosts.
    import tomli as tomllib
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MINIMUM_AGE = timedelta(days=7)
CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9_-]+\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.+-]+)?\Z")
CHECKSUM = re.compile(r"[0-9a-f]{64}\Z")
GIT_SOURCE = re.compile(r"git\+https://[^\s#]+#[0-9a-f]{40}\Z")


class GateError(ValueError):
    """Invalid evidence or a policy violation."""


@dataclass(frozen=True, order=True)
class Package:
    name: str
    version: str
    source: str
    checksum: str


def utc_timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise GateError("timestamp must be a string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GateError(f"invalid timestamp: {value!r}") from exc
    if result.tzinfo is None:
        raise GateError("timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def read_packages(text: str, allowed_git: set[str]) -> set[Package]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise GateError(f"invalid Cargo.lock: {exc}") from exc
    if data.get("version") not in (3, 4) or not isinstance(data.get("package"), list):
        raise GateError("expected Cargo.lock v3/v4 with a package array")
    result: set[Package] = set()
    identities: set[tuple[str, str, str]] = set()
    for raw in data["package"]:
        name, version, source = raw.get("name", ""), raw.get("version", ""), raw.get("source", "")
        if not isinstance(name, str) or not NAME.fullmatch(name):
            raise GateError("invalid package name")
        if not isinstance(version, str) or not VERSION.fullmatch(version):
            raise GateError(f"invalid package version for {name}")
        if not isinstance(source, str):
            raise GateError(f"invalid source for {name}")
        identity = (name, version, source)
        if identity in identities:
            raise GateError(f"duplicate locked package: {name} {version}")
        identities.add(identity)
        if not source:
            if "checksum" in raw:
                raise GateError(f"local package unexpectedly has a checksum: {name}")
            continue
        if source in allowed_git and GIT_SOURCE.fullmatch(source):
            continue  # An explicit immutable Git pin is a separate source-review policy.
        if source != CRATES_IO:
            raise GateError(f"unapproved source for {name} {version}: {source}")
        checksum = raw.get("checksum", "")
        if not isinstance(checksum, str) or not CHECKSUM.fullmatch(checksum):
            raise GateError(f"missing/invalid crates.io checksum: {name} {version}")
        result.add(Package(name, version, source, checksum))
    return result


def load_exceptions(path: Path, now: datetime) -> dict[tuple[str, str, str], dict]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if set(data) != {"schema_version", "exceptions"} or data["schema_version"] != 1:
        raise GateError("invalid emergency exception schema")
    if not isinstance(data["exceptions"], list):
        raise GateError("exceptions must be an array")
    exceptions = {}
    fields = {"name", "version", "checksum", "issued_at", "expires_at", "reason", "reference"}
    for entry in data["exceptions"]:
        if not isinstance(entry, dict) or set(entry) != fields:
            raise GateError("an emergency exception has missing or unknown fields")
        if not all(isinstance(entry[key], str) for key in fields):
            raise GateError("emergency exception fields must be strings")
        if not NAME.fullmatch(entry["name"]) or not VERSION.fullmatch(entry["version"]):
            raise GateError("invalid exception package identity")
        if not CHECKSUM.fullmatch(entry["checksum"]):
            raise GateError("exception requires the exact crate checksum")
        issued, expires = utc_timestamp(entry["issued_at"]), utc_timestamp(entry["expires_at"])
        if not (issued <= now < expires <= issued + MINIMUM_AGE):
            raise GateError(f"exception is future-dated, expired, or longer than seven days: {entry['name']}")
        if len(entry["reason"].strip()) < 20 or not entry["reference"].startswith("https://"):
            raise GateError("exception needs a substantive reason and HTTPS review/advisory reference")
        key = (entry["name"], entry["version"], entry["checksum"])
        if key in exceptions:
            raise GateError("duplicate emergency exception")
        exceptions[key] = entry
    return exceptions


def registry_version(package: Package) -> dict:
    """Bounded HTTPS request to crates.io; never consume PR-provided metadata."""
    url = f"https://crates.io/api/v1/crates/{package.name}/{package.version}"
    request = Request(url, headers={"User-Agent": "DCENT_OS dependency-age gate (https://d-central.tech/)"})
    for attempt in range(3):
        try:
            with urlopen(request, timeout=20) as response:
                if not response.url.startswith("https://crates.io/"):
                    raise GateError("unexpected registry response origin")
                body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise GateError("registry response exceeds size limit")
            return json.loads(body)
        except (HTTPError, URLError, TimeoutError) as exc:
            if isinstance(exc, HTTPError) and exc.code not in (429, 500, 502, 503, 504):
                raise GateError(f"registry request failed for {package.name}: HTTP {exc.code}") from exc
            if attempt == 2:
                raise GateError(f"registry request failed for {package.name}: {exc}") from exc
            time.sleep(attempt + 1)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise GateError("registry returned invalid JSON") from exc
    raise AssertionError("unreachable")


def evaluate(package: Package, payload: dict, now: datetime, exceptions: dict) -> dict:
    version = payload.get("version") if isinstance(payload, dict) else None
    if not isinstance(version, dict):
        raise GateError(f"missing version metadata: {package.name}")
    if version.get("crate") != package.name or version.get("num") != package.version:
        raise GateError(f"registry identity mismatch: {package.name} {package.version}")
    if version.get("checksum") != package.checksum:
        raise GateError(f"registry checksum mismatch: {package.name} {package.version}")
    if version.get("yanked") is not False:
        raise GateError(f"yanked or ambiguous registry version: {package.name} {package.version}")
    published = utc_timestamp(version.get("created_at"))
    if published > now:
        raise GateError(f"future publication timestamp: {package.name} {package.version}")
    exception = exceptions.get((package.name, package.version, package.checksum))
    mature = now - published >= MINIMUM_AGE
    if not mature and exception is None:
        raise GateError(f"{package.name} {package.version} is younger than seven days; eligible at {(published + MINIMUM_AGE).isoformat()}")
    result = {"name": package.name, "version": package.version, "checksum": package.checksum,
              "published_at": published.isoformat(), "status": "mature" if mature else "emergency-exception"}
    if not mature:
        result["exception"] = exception
    return result


def git(root: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, encoding="utf-8")
    if proc.returncode:
        raise GateError(proc.stderr.strip() or "git command failed")
    return proc.stdout


def base_lock(root: Path, relative: str, reference: str) -> tuple[str, str | None]:
    if re.fullmatch(r"0{40}", reference):
        return reference, None  # GitHub's before SHA on an initial push.
    commit = git(root, "rev-parse", "--verify", "--end-of-options", f"{reference}^{{commit}}").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise GateError("base did not resolve to a commit")
    if not git(root, "ls-tree", commit, "--", relative).strip():
        return commit, None  # Newly introduced workspace: check every registry package.
    return commit, git(root, "show", f"{commit}:{relative}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, default=Path(__file__).resolve().parents[1] / "dcentrald/Cargo.lock")
    parser.add_argument("--base-ref", required=True, help="PR base SHA; HEAD compares local uncommitted lock changes")
    parser.add_argument("--exceptions", type=Path, default=Path(__file__).with_name("dependency_age_exceptions.json"))
    parser.add_argument("--allow-git-source", action="append", default=[], help="Exact reviewed HTTPS Git source ending in #<40-hex commit>; no age assertion for Git")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        now = datetime.now(timezone.utc)
        allowed_git = set(args.allow_git_source)
        if any(not GIT_SOURCE.fullmatch(source) for source in allowed_git):
            raise GateError("Git source exceptions require immutable HTTPS commit pins")
        lock = args.lock.resolve(strict=True)
        root = Path(git(lock.parent, "rev-parse", "--show-toplevel").strip()).resolve()
        relative = lock.relative_to(root).as_posix()
        head_bytes = lock.read_bytes()
        head = read_packages(head_bytes.decode("utf-8"), allowed_git)
        base_sha, previous = base_lock(root, relative, args.base_ref)
        base = read_packages(previous, allowed_git) if previous is not None else set()
        exceptions = load_exceptions(args.exceptions, now)
        changed = sorted(head - base)
        rows = [evaluate(package, registry_version(package), now, exceptions) for package in changed]
        report = {"schema_version": 1, "lock": relative, "lock_sha256": hashlib.sha256(head_bytes).hexdigest(),
                  "base_commit": base_sha, "checked_at": now.isoformat(), "minimum_age_days": 7,
                  "checked_packages": rows, "allowed_git_sources": sorted(allowed_git)}
        if args.report:
            args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        for row in rows:
            print(f"{row['status']}: {row['name']} {row['version']} published {row['published_at']}")
        print(f"PASS: dependency age; {len(rows)} changed crates.io package versions checked against {base_sha}")
        return 0
    except (GateError, OSError, ValueError) as exc:
        print(f"FAIL: dependency age: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
