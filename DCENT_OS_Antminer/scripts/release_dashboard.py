#!/usr/bin/env python3
"""Build and verify dashboard assets from an authenticated source copy.

The caller owns and verifies the source snapshot and live result stage. npm
runs only in a disposable writable copy. Its output and build observation are
then included in the result stage's exact seal, without changing source bytes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from binary_build_receipt import ReceiptError, assert_no_symlink_components, read_regular_snapshot

PROFILE = "dcentos-release-dashboard/v2"
LEGACY_PROFILES = ("dcentos-release-dashboard/v1",)
RECEIPT = "dashboard-build.json"
IGNORED_SOURCE_ROOTS = {"node_modules", "dist"}
MAX_ASSET_BYTES = 32 * 1024 * 1024


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def inventory(root: Path, *, source: bool = False) -> list[dict]:
    root = assert_no_symlink_components(root, "dashboard root")
    records = []
    for parent, directories, files in os.walk(root, followlinks=False):
        if Path(parent) == root and source:
            directories[:] = [name for name in directories if name not in IGNORED_SOURCE_ROOTS]
        for name in directories:
            assert_no_symlink_components(Path(parent) / name, "dashboard directory")
        for name in files:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if not source and relative == RECEIPT:
                continue
            if any(ord(char) < 32 or ord(char) == 127 for char in relative):
                raise ValueError("dashboard pathname contains a control character")
            assert_no_symlink_components(path, "dashboard file")
            if path.stat().st_size > MAX_ASSET_BYTES:
                raise ValueError("dashboard asset exceeds size bound")
            _, evidence = read_regular_snapshot(path, "dashboard input" if source else "dashboard asset")
            records.append({"path": relative, "size": evidence["size"], "sha256": evidence["sha256"]})
            if len(records) > 100000:
                raise ValueError("dashboard inventory exceeds entry bound")
    if not records:
        raise ValueError("empty dashboard tree")
    return sorted(records, key=lambda row: row["path"])


def verify_assets(root: Path) -> list[dict]:
    records = inventory(root)
    html, _ = read_regular_snapshot(root / "index.html", "dashboard HTML")
    compressed, _ = read_regular_snapshot(root / "index.html.gz", "dashboard gzip")
    digest, _ = read_regular_snapshot(root / "index.html.sha256", "dashboard digest")
    # Bounded streaming decompression also rejects concatenated trailing data.
    import zlib
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    unpacked = decompressor.decompress(compressed, MAX_ASSET_BYTES + 1)
    if (not decompressor.eof or decompressor.unused_data or decompressor.unconsumed_tail
            or unpacked != html or digest != (hashlib.sha256(html).hexdigest() + "\n").encode()):
        raise ValueError("dashboard HTML/gzip/digest disagree")
    if b"<html" not in html.lower() or b"/static/diagnostic-banner.js" not in html:
        raise ValueError("dashboard HTML is missing the application/diagnostic banner")
    return records


def verify(source: Path, output: Path) -> dict:
    raw, _ = read_regular_snapshot(output / RECEIPT, "dashboard build observation")
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("duplicate dashboard observation key")
            result[key] = value
        return result
    receipt = json.loads(raw, object_pairs_hook=pairs)
    allowed_sets = (
        {"manifest_profile", "source", "assets", "node", "npm"},
        {"manifest_profile", "source", "external_inputs", "assets", "node", "npm"},
    )
    if (not isinstance(receipt, dict)
            or set(receipt) not in allowed_sets
            or receipt["manifest_profile"] not in (PROFILE, *LEGACY_PROFILES)
            or canonical(receipt) != raw):
        raise ValueError("invalid dashboard build observation")
    for tool in ("node", "npm"):
        value = receipt[tool]
        if not isinstance(value, str) or not value or len(value) > 128 or any(ord(c) < 32 for c in value):
            raise ValueError("invalid dashboard tool version")
    if receipt["source"] != inventory(source, source=True) or receipt["assets"] != verify_assets(output):
        raise ValueError("dashboard source/output differs from its build observation")
    return receipt


def toolchain() -> tuple[list[str], dict[str, str]]:
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    node = shutil.which("node")
    if npm is None or node is None:
        raise ValueError("Node.js and npm are required before release compilation")
    # On Windows invoke npm's JS entry directly, avoiding cmd.exe interpolation.
    npm_cli = Path(npm).parent / "node_modules/npm/bin/npm-cli.js"
    command = [node, str(npm_cli)] if os.name == "nt" else [npm]
    if os.name == "nt" and not npm_cli.is_file():
        raise ValueError("npm-cli.js is missing beside the Node installation")
    versions = {"node": subprocess.check_output([node, "--version"], text=True, timeout=30).strip(),
                "npm": subprocess.check_output([*command, "--version"], text=True, timeout=30).strip()}
    return command, versions


def stage(source: Path, output: Path, destination: Path) -> dict:
    """Copy sealed assets into one fresh canonical container destination."""
    expected = verify(source, output)
    destination = Path(os.path.abspath(host_path_text(os.fspath(destination))))
    assert_no_symlink_components(destination.parent, "dashboard staging parent")
    if destination.exists() or destination.is_symlink():
        raise ValueError("dashboard staging destination must be absent")
    shutil.copytree(output, destination)
    actual = verify(source, destination)
    if actual != expected or verify(source, output) != expected:
        raise ValueError("dashboard changed during staging")
    return actual


def preflight(source: Path) -> list[dict]:
    inputs = inventory(source, source=True)
    if not {"package.json", "package-lock.json"}.issubset({row["path"] for row in inputs}):
        raise ValueError("authenticated npm package and lockfile are required")
    toolchain()
    return inputs


def scratch_parent(output: Path) -> Path:
    """Keep npm's Windows working directory short and on the output volume.

    Native process creation rejects long current directories even when Python
    can create and read them. Capsule result paths exceed that limit. Select
    an existing ancestor for the disposable copy, retaining the same-volume
    final rename and leaving the authenticated source untouched.
    """
    parent = output.parent
    if os.name == "nt":
        while len(str(parent)) > 80:
            if parent.parent == parent:
                raise ValueError("no short same-volume dashboard build parent")
            parent = parent.parent
    return assert_no_symlink_components(parent, "dashboard build parent")


def external_raw_imports(inputs: list[dict], source: Path) -> list[dict]:
    """Stage repo files that dashboard `?raw` imports reach for.

    HelpPage imports e.g. `../../../../docs/INSTALL/README.md?raw`, reaching
    above the dashboard root into the project tree. The disposable npm copy
    contains only the inventoried dashboard files, so those imports cannot
    resolve unless the referenced project files are staged at the same
    relative location. Every staged file is receipt-bound by content.
    """
    import re

    spec_re = re.compile(r"""(?:from\s+|import\s*\(\s*|require\s*\(\s*)['"]([^'"]+\?raw)['"]""")
    repo_root = source.parent
    staged: dict[str, dict] = {}
    for row in inputs:
        path = row["path"]
        if not path.endswith((".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte")):
            continue
        text = (source / path).read_text(encoding="utf-8", errors="strict")
        for match in spec_re.finditer(text):
            spec = match.group(1)
            if not spec.endswith("?raw"):
                continue
            spec = spec[: -len("?raw")]
            if not spec.startswith("../"):
                continue
            importer_dir = (source / path).parent
            resolved = (importer_dir / spec).resolve()
            try:
                relative = resolved.relative_to(repo_root.resolve()).as_posix()
            except ValueError:
                raise ValueError(
                    f"dashboard ?raw import escapes the project tree: {spec} in {path}"
                ) from None
            if relative in staged:
                continue
            _, evidence = read_regular_snapshot(resolved, "dashboard external ?raw input")
            staged[relative] = {"path": relative, "size": evidence["size"], "sha256": evidence["sha256"]}
    return sorted(staged.values(), key=lambda row: row["path"])


def build(source: Path, output: Path) -> dict:
    source = assert_no_symlink_components(source, "authenticated dashboard source")
    output = Path(os.path.abspath(host_path_text(os.fspath(output))))
    assert_no_symlink_components(output.parent, "dashboard result parent")
    if output.exists() or output.is_symlink():
        raise ValueError("dashboard result must be absent before building")
    inputs = preflight(source)
    externals = external_raw_imports(inputs, source)
    command, versions = toolchain()
    with tempfile.TemporaryDirectory(prefix="dashboard-build-", dir=scratch_parent(output)) as temporary:
        scratch = Path(temporary)
        working = scratch / "source"
        working.mkdir()
        for row in inputs:
            destination = working / row["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / row["path"], destination)
        # ?raw imports climb above the dashboard root. The private npm copy
        # drops the dashboard's own directory level, so each referenced file
        # stages one level above `working` (beside it, under the same scratch
        # root) and is re-verified by content after the build.
        for row in externals:
            destination = working.parent / row["path"]
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source.parent / row["path"], destination)
        if inventory(working, source=True) != inputs:
            raise ValueError("dashboard source changed during private copy")
        environment = dict(os.environ, CYPRESS_INSTALL_BINARY="0", CI="1")
        subprocess.run([*command, "ci", "--no-audit", "--no-fund"], cwd=working,
                       env=environment, check=True)
        subprocess.run([*command, "run", "build"], cwd=working, env=environment, check=True)
        if inventory(source, source=True) != inputs:
            raise ValueError("authenticated dashboard source changed during npm build")
        for row in externals:
            staged_path = working.parent / row["path"]
            _, evidence = read_regular_snapshot(staged_path, "dashboard external ?raw input")
            if (evidence["size"], evidence["sha256"]) != (row["size"], row["sha256"]):
                raise ValueError("dashboard external ?raw input changed during npm build")
        assets = verify_assets(working / "dist")
        receipt = {
            "manifest_profile": PROFILE,
            "source": inputs,
            "external_inputs": externals,
            "assets": assets,
            **versions,
        }
        (working / "dist" / RECEIPT).write_bytes(canonical(receipt))
        verify(source, working / "dist")
        # Single same-filesystem rename publishes only a complete verified set.
        if output.exists() or output.is_symlink():
            raise ValueError("dashboard result appeared during the build")
        os.rename(working / "dist", output)
    return receipt


def host_path_text(value: str) -> str:
    """Rewrite Git-Bash (MSYS) drive paths (/d/dir) and long-path prefixes.

    MSYS automatic argument conversion is per-argument and inconsistent on
    long release command lines (producer runs drop1-20260916-cyg3sjwi and
    drop1-20260917-gnscaudk; the same fix landed in rust_dependency_inventory
    commit b1ae659fa and source_closure commit 4fd3d8b0e). Dashboard paths
    feed strict component inspection and a final os.rename publication, so
    the type converter normalizes them at the parse layer before the
    spelling is consumed. POSIX and native inputs are returned unchanged;
    on non-Windows hosts this is the identity.
    """
    if os.name != "nt" or not isinstance(value, str):
        return value
    text = value
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("//?/UNC/"):
        text = "//" + text[8:]
    else:
        for prefix in ("\\\\?\\", "//?/"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
    if (
        len(text) >= 2
        and text[0] == "/"
        and text[1].isascii()
        and text[1].isalpha()
        and (len(text) == 2 or text[2] == "/")
    ):
        return text[1].upper() + ":/" + text[3:]
    return text



def host_path(value: str) -> Path:
    """argparse Path type normalized through host_path_text."""
    return Path(host_path_text(value))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("preflight", "build", "verify", "stage"))
    parser.add_argument("--source", type=host_path, required=True)
    parser.add_argument("--output", type=host_path)
    parser.add_argument("--destination", type=host_path)
    args = parser.parse_args()
    try:
        if args.action == "preflight":
            print(f"dashboard preflight: {len(preflight(args.source))} source files")
            return 0
        if args.output is None:
            parser.error("--output is required for build and verify")
        if args.action == "stage":
            if args.destination is None:
                parser.error("--destination is required for stage")
            result = stage(args.source, args.output, args.destination)
        else:
            result = build(args.source, args.output) if args.action == "build" else verify(args.source, args.output)
        print(f"verified dashboard: {len(result['assets'])} assets")
        return 0
    except (OSError, ValueError, ReceiptError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
