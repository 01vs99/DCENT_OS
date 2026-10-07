#!/usr/bin/env python3
"""Generate the pure Rust and POSIX GPIO437 policy from one reviewed source.

This program never opens GPIO or vendor binaries. Citations describe software
evidence, not measurements. Run with --check to detect generated artifact drift.
"""

import argparse
import json
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts/hardware/amlogic-gpio437.json"
RUST = ROOT / "dcentrald/dcentrald-common/src/amlogic_gpio437_table.rs"
SHELL = ROOT / "br2_external_dcentos/board/amlogic/rootfs-overlay/usr/share/dcentos/amlogic-gpio437.sh"
SHELL_COMMON = ROOT / "br2_external_dcentos/board/common/rootfs-overlay/usr/share/dcentos/amlogic-gpio437.sh"
VENDORS = {"braiins": "Braiins", "vnish": "Vnish", "epic": "Epic", "bitmain": "Bitmain"}
KINDS = {
    "complete-model-trace": "CompleteModelTrace",
    "shared-backend-only": "SharedBackendOnly",
    "startup-only": "StartupOnly",
    "recorded-model-observation": "RecordedModelObservation",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def fields(value, names, label):
    require(isinstance(value, dict) and set(value) == set(names.split()), f"{label}: unexpected fields")


def load_policy(path=SOURCE):
    policy = json.loads(path.read_text(encoding="utf-8"))
    validate(policy)
    return policy


def validate(policy):
    fields(policy, "schema gpio sources profiles", "policy")
    require(policy["schema"] == "dcentos.amlogic-gpio437/v1", "unsupported schema")
    require(type(policy["gpio"]) is int and policy["gpio"] == 437, "GPIO437 policy only")
    sources = policy["sources"]
    require(isinstance(sources, dict), "sources must be an object")
    digest_vendors = {}
    for source_id, source in sources.items():
        require(re.fullmatch(r"[a-z0-9-]+", source_id) is not None, "invalid source ID")
        fields(source, "vendor artifact sha256", source_id)
        require(source["vendor"] in VENDORS, f"{source_id}: unknown vendor")
        require(isinstance(source["artifact"], str) and source["artifact"], f"{source_id}: missing artifact")
        require(re.fullmatch(r"[0-9a-f]{64}", source["sha256"]) is not None, f"{source_id}: invalid SHA256")
        previous_vendor = digest_vendors.setdefault(source["sha256"], source["vendor"])
        require(previous_vendor == source["vendor"], f"{source_id}: identical artifact relabeled as another vendor")
    require(isinstance(policy["profiles"], list) and policy["profiles"], "profiles must be nonempty")
    targets = set()
    for profile in policy["profiles"]:
        fields(profile, "board_target hashboard_names note evidence", "profile")
        target = profile["board_target"]
        require(isinstance(target, str) and re.fullmatch(r"am3-[a-z0-9-]+", target) is not None, "invalid exact target")
        require(target not in targets, f"duplicate target {target}")
        targets.add(target)
        names = profile["hashboard_names"]
        require(isinstance(names, list) and names and len(set(names)) == len(names), f"{target}: invalid hashboard names")
        require(all(isinstance(name, str) and re.fullmatch(r"[A-Z][A-Z0-9-]+", name) for name in names), f"{target}: invalid exact hashboard name")
        require(isinstance(profile["note"], str) and profile["note"], f"{target}: missing scope note")
        require(isinstance(profile["evidence"], list), f"{target}: evidence must be a list")
        for item in profile["evidence"]:
            fields(item, "board_target hashboard_names source kind on_raw off_raw model_join trace", target)
            require(item["board_target"] == target, f"{target}: evidence belongs to another target")
            require(item["source"] in sources, f"{target}: unknown source")
            require(item["kind"] in KINDS, f"{target}: unknown evidence kind")
            coverage = item["hashboard_names"]
            require(isinstance(coverage, list) and len(set(coverage)) == len(coverage) and set(coverage) <= set(names), f"{target}: invalid evidence hashboard coverage")
            require(isinstance(item["trace"], str) and item["trace"], f"{target}: missing trace or observation")
            require(isinstance(item["model_join"], str), f"{target}: invalid model join")
            for name in ("on_raw", "off_raw"):
                require(item[name] is None or (type(item[name]) is int and item[name] in (0, 1)), f"{target}: invalid raw level")
            if item["kind"] == "complete-model-trace":
                require(bool(coverage), f"{target}: complete trace lacks exact hashboard coverage")
                require(bool(item["model_join"]), f"{target}: complete trace lacks exact model join")
                require(item["on_raw"] is not None and item["off_raw"] is not None and item["on_raw"] != item["off_raw"], f"{target}: incomplete or invalid polarity pair")


def decision(profile, sources, hashboard_name=None):
    """Return status, distinct qualifying vendors, and optional (ON, OFF)."""
    if hashboard_name is None:
        results = [decision(profile, sources, name) for name in profile["hashboard_names"]]
        for result in results:
            if result[2] is None:
                return result
        if len({result[2] for result in results}) != 1:
            return "conflicting-complete-traces", min(result[1] for result in results), None
        return "qualified", min(result[1] for result in results), results[0][2]
    if hashboard_name not in profile["hashboard_names"]:
        return "unknown-hashboard", 0, None
    complete = [item for item in profile["evidence"] if item["kind"] == "complete-model-trace" and hashboard_name in item["hashboard_names"]]
    vendors = {sources[item["source"]]["vendor"] for item in complete}
    levels = {(item["on_raw"], item["off_raw"]) for item in complete}
    if len(levels) > 1:
        return "conflicting-complete-traces", len(vendors), None
    if len(vendors) < 2:
        return "insufficient-independent-vendors", len(vendors), None
    return "qualified", len(vendors), next(iter(levels))


def rust_text(policy):
    lines = [
        "// @generated by scripts/generate_amlogic_gpio437.py; do not edit.",
        "// Source: contracts/hardware/amlogic-gpio437.json. Software traces only.",
        "#[rustfmt::skip]",
        "const PROFILES: &[BoardPolarityProfile] = &[",
    ]
    for profile in policy["profiles"]:
        target = json.dumps(profile["board_target"])
        names = ", ".join(json.dumps(name) for name in profile["hashboard_names"])
        lines.extend(["    BoardPolarityProfile {", f"        board_target: {target},", f"        hashboard_names: &[{names}],", "        evidence: &["])
        for item in profile["evidence"]:
            vendor = VENDORS[policy["sources"][item["source"]]["vendor"]]
            coverage = ", ".join(json.dumps(name) for name in item["hashboard_names"])
            def raw(name):
                return "None" if item[name] is None else f"Some({item[name]})"
            lines.extend([
                f"            // Source: {item['source']} (see the JSON authority for exact joins).",
                "            Evidence {",
                f"                board_target: {target},",
                f"                hashboard_names: &[{coverage}],",
                f"                vendor: Vendor::{vendor},",
                f"                kind: EvidenceKind::{KINDS[item['kind']]},",
                f"                on_raw: {raw('on_raw')},",
                f"                off_raw: {raw('off_raw')},",
                "            },",
            ])
        lines.extend(["        ],", "    },"])
    lines.extend([
        "];",
        "",
        "#[cfg(test)]",
        "#[test]",
        "#[rustfmt::skip]",
        "fn generated_decisions_match_runtime_validation() {",
    ])
    for profile in policy["profiles"]:
        target = json.dumps(profile["board_target"])
        for name in [None, *profile["hashboard_names"]]:
            status, count, levels = decision(profile, policy["sources"], name)
            if levels is not None:
                result = f"Ok(Gpio437DriveRecipe {{ board_target: {target}, on_raw: {levels[0]}, off_raw: {levels[1]} }})"
            elif status == "conflicting-complete-traces":
                result = "Err(PolarityRefusal::ConflictingCompleteTraces)"
            else:
                result = f"Err(PolarityRefusal::InsufficientIndependentVendors {{ found: {count} }})"
            call = f"resolve_drive_recipe({target})" if name is None else f"resolve_identity_recipe({target}, {json.dumps(name)})"
            lines.append(f"    assert_eq!({call}, {result});")
    lines.extend(["}", ""])
    return "\n".join(lines)


def shell_text(policy):
    lines = [
        "#!/bin/sh",
        "# @generated by scripts/generate_amlogic_gpio437.py; do not edit.",
        "# Source: contracts/hardware/amlogic-gpio437.json. Software traces only.",
        "# Pure functions: no GPIO, marker or environment reads and no hardware writes.",
        "# drive_levels prints ON OFF OFF_DIRECTION only on success (status 0).",
        "# Status 1: known but unqualified; status 2: unknown target/invalid arguments.",
        "# A failure prints nothing. It never supplies a guessed OFF value.",
        "dcent_gpio437_drive_levels() {",
        "    [ \"$#\" -eq 1 ] || return 2",
        "    case \"$1\" in",
    ]
    for profile in policy["profiles"]:
        _, _, levels = decision(profile, policy["sources"])
        result = "return 1"
        if levels is not None:
            direction = "high" if levels[1] == 1 else "low"
            result = f"printf '%s\\n' '{levels[0]} {levels[1]} {direction}'"
        lines.append(f"        '{profile['board_target']}') {result} ;;")
    lines.extend(["        *) return 2 ;;", "    esac", "}", "", "# Report-only state; undriven is not a claim of electrical OFF.", "dcent_gpio437_policy_state() {", "    [ \"$#\" -eq 1 ] || return 2", "    case \"$1\" in"])
    for profile in policy["profiles"]:
        status, _, _ = decision(profile, policy["sources"])
        value = "qualified-software" if status == "qualified" else "undriven"
        lines.append(f"        '{profile['board_target']}') printf '%s\\n' '{value}' ;;")
    lines.extend(["        *) return 2 ;;", "    esac", "}", ""])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail on generated artifact drift")
    args = parser.parse_args(argv)
    try:
        policy = load_policy()
        for path, text in ((RUST, rust_text(policy)), (SHELL, shell_text(policy)), (SHELL_COMMON, shell_text(policy))):
            content = text.encode("utf-8")
            if args.check:
                require(path.is_file() and path.read_bytes() == content, f"generated artifact differs: {path}")
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
    except (OSError, ValueError, TypeError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
