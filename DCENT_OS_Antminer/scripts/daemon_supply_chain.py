#!/usr/bin/env python3
"""One locked, pinned local/CI supply-chain gate for the daemon and MQTT TLS.

Python 3.9/3.10 require tomli; Python 3.11+ uses the standard library.
cargo-audit's complete lockfile report is retained. Only
the exact reviewed dormant upstream findings can be acknowledged, after their
source bytes and dependency callers have been checked. New advisories fail.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from check_dependency_age import GateError, utc_timestamp, tomllib

SCRIPT_DIR = Path(__file__).resolve().parent
WORKSPACE = SCRIPT_DIR.parent / "dcentrald"
REVIEWED_PACKAGES = {("rumqttc", "0.25.1"), ("rustls-webpki", "0.102.8"), ("rustls-pemfile", "2.2.0")}
REVIEWED_FINDINGS = {
    (advisory, "rustls-webpki", "0.102.8")
    for advisory in ("RUSTSEC-2026-0098", "RUSTSEC-2026-0099", "RUSTSEC-2026-0049", "RUSTSEC-2026-0104")
} | {("RUSTSEC-2025-0134", "rustls-pemfile", "2.2.0")}


def command(args: list[str], *, capture=False, timeout=900) -> subprocess.CompletedProcess:
    print("+ " + " ".join(args), flush=True)
    return subprocess.run(args, cwd=WORKSPACE, text=True, encoding="utf-8", errors="replace",
                          capture_output=capture, timeout=timeout)


def source_digest(source: Path) -> str:
    """Pin every upstream Rust source file, including file names and additions."""
    rows = []
    for path in sorted((source / "src").rglob("*.rs")):
        if path.is_symlink():
            raise GateError("unexpected symlink in reviewed MQTT source")
        rows.append(f"{path.relative_to(source).as_posix()}\0{hashlib.sha256(path.read_bytes()).hexdigest()}\n")
    if not rows:
        raise GateError("reviewed MQTT source is unavailable")
    return hashlib.sha256("".join(rows).encode()).hexdigest()


def mqtt_adapter_digest(path: Path) -> str:
    source = path.read_text(encoding="utf-8")
    start = source.index("/// Apply TLS transport when the broker URL requests it.")
    end = source.index("pub fn mqtt_command_token_is_present()", start)
    return hashlib.sha256(source[start:end].encode()).hexdigest()


def guard_dormant_findings(policy: dict, lock: dict, metadata: dict, now: datetime,
                           *, workspace: Path = WORKSPACE) -> set[tuple[str, str, str]]:
    if policy.get("schema_version") != 1 or now >= utc_timestamp(policy["expires_at"]):
        raise GateError("MQTT dormant-source review expired or has an invalid schema")
    if {(p["name"], p["version"]) for p in policy["packages"]} != REVIEWED_PACKAGES:
        raise GateError("MQTT dormant policy must pin every reviewed package")
    allowed = {(entry["advisory"], entry["package"], entry["version"]) for entry in policy["findings"]}
    if not allowed.issubset(REVIEWED_FINDINGS):
        raise GateError("policy added an advisory outside the reviewed dormant findings")
    packages = {(p["name"], p["version"]): p for p in lock["package"]}
    for expected in policy["packages"]:
        actual = packages.get((expected["name"], expected["version"]))
        if actual is None or any(actual.get(key) != expected[key] for key in ("source", "checksum")):
            raise GateError("MQTT dormant-source package pin changed; re-review required")
    meta_packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    mqtt = [p for p in meta_packages.values() if p["name"] == "rumqttc"]
    if len(mqtt) != 1 or mqtt[0]["version"] != "0.25.1":
        raise GateError("expected the reviewed rumqttc release")
    mqtt = mqtt[0]
    features = set(nodes[mqtt["id"]]["features"])
    if "use-rustls-no-provider" not in features or features.intersection({"use-rustls", "use-native-tls", "default"}):
        raise GateError("MQTT TLS feature/provider policy changed")
    if any("custom-build" in target["kind"] for target in mqtt["targets"]):
        raise GateError("reviewed MQTT package gained a build script")
    for name, version in [("rustls-webpki", "0.102.8"), ("rustls-pemfile", "2.2.0")]:
        candidates = [p["id"] for p in meta_packages.values() if p["name"] == name and p["version"] == version]
        if len(candidates) != 1:
            raise GateError("expected one reviewed dormant package")
        incoming = {n["id"] for n in nodes.values() if candidates[0] in n["dependencies"]}
        if incoming != {mqtt["id"]}:
            raise GateError(f"{name} gained a caller outside the reviewed MQTT path")
    for package in meta_packages.values():
        if package["name"] == "rustls" and not package["version"].startswith("0.23."):
            raise GateError("an older active rustls verifier entered the graph")
    source = Path(mqtt["manifest_path"]).parent
    if source_digest(source) != policy["rumqttc_source_sha256"]:
        raise GateError("MQTT Rust source changed; old webpki may have gained runtime callers")
    if hashlib.sha256((source / "Cargo.toml").read_bytes()).hexdigest() != policy["rumqttc_manifest_sha256"]:
        raise GateError("MQTT dependency manifest changed")
    adapter = workspace / "dcentrald-api/src/mqtt.rs"
    if mqtt_adapter_digest(adapter) != policy["dcent_mqtt_adapter_sha256"]:
        raise GateError("DCENT MQTT TLS adapter changed; re-review dormant PEM branch")
    return allowed


def classify_audit(audit: dict, allowed: set[tuple[str, str, str]]) -> tuple[list[dict], list[dict]]:
    if not isinstance(audit.get("database"), dict) or not isinstance(audit.get("warnings"), dict):
        raise GateError("cargo-audit did not return a complete advisory report")
    vulnerabilities = audit.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict) or not isinstance(vulnerabilities.get("list"), list):
        raise GateError("cargo-audit vulnerability report is missing")
    blocked, dormant = [], []
    rows = list(vulnerabilities["list"])
    for warnings in audit["warnings"].values():
        rows.extend(warnings)
    for row in rows:
        advisory = row.get("advisory") or {}
        package = row["package"]
        key = (advisory.get("id", row.get("kind", "unknown")), package["name"], package["version"])
        (dormant if key in allowed else blocked).append(row)
    return blocked, dormant


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install-tools", action="store_true", help="install exact reviewed versions, using their locked dependency graphs")
    parser.add_argument("--scope", choices=["all", "structural", "advisories"], default="all")
    parser.add_argument("--report", type=Path, help="retain raw cargo-audit findings plus scoped classification")
    args = parser.parse_args(argv)
    try:
        pins = json.loads((SCRIPT_DIR / "daemon_supply_chain_tools.json").read_text())
        cargo = ["cargo", "+" + pins["rust"]]
        for tool in ("cargo-deny", "cargo-audit"):
            version = command([*cargo, tool.removeprefix("cargo-"), "--version"], capture=True, timeout=30)
            if version.returncode or version.stdout.strip().split()[-1:] != [pins[tool]]:
                if not args.install_tools:
                    raise GateError(f"{tool} {pins[tool]} required; use --install-tools")
                command([*cargo, "install", tool, "--version", "=" + pins[tool], "--locked", "--force"], timeout=1200).check_returncode()
        if args.scope in ("all", "structural"):
            command([*cargo, "deny", "--locked", "--all-features", "check", "licenses", "bans", "sources"]).check_returncode()
        if args.scope in ("all", "advisories"):
            lock_bytes = (WORKSPACE / "Cargo.lock").read_bytes()
            resolved = command([*cargo, "metadata", "--locked", "--all-features", "--format-version", "1"], capture=True)
            resolved.check_returncode()
            policy = json.loads((SCRIPT_DIR / "mqtt_dormant_advisories.json").read_text())
            allowed = guard_dormant_findings(policy, tomllib.loads((WORKSPACE / "Cargo.lock").read_text()),
                                             json.loads(resolved.stdout), datetime.now(timezone.utc))
            audited = command([*cargo, "audit", "--json"], capture=True)
            if audited.returncode not in (0, 1):
                raise GateError(audited.stderr or "cargo-audit could not complete")
            audit = json.loads(audited.stdout)
            blocked, dormant = classify_audit(audit, allowed)
            if (WORKSPACE / "Cargo.lock").read_bytes() != lock_bytes:
                raise GateError("Cargo.lock changed while the advisory gate was running")
            if args.report:
                args.report.write_text(json.dumps({"raw_audit": audit, "blocked": blocked,
                    "reviewed_dormant": dormant, "policy_expires_at": policy["expires_at"],
                    "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(), "tool_versions": pins,
                    "checked_at": datetime.now(timezone.utc).isoformat()}, indent=2) + "\n", encoding="utf-8")
            for row in dormant:
                print(f"REVIEWED DORMANT: {row['advisory']['id']} {row['package']['name']} {row['package']['version']}")
            if blocked:
                for row in blocked:
                    print(f"BLOCKED: {(row.get('advisory') or {}).get('id', row.get('kind'))} {row['package']['name']} {row['package']['version']}", file=sys.stderr)
                raise GateError(f"{len(blocked)} unreviewed advisory/yank findings")
            print(f"PASS: advisory gate; {len(dormant)} explicitly reported dormant findings, no unreviewed findings")
        print("PASS: daemon supply-chain checks")
        return 0
    except (GateError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print(f"FAIL: daemon supply-chain: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
