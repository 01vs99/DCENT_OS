#!/usr/bin/env python3
"""Deterministic JSON and version admission for sysupgrade manifests.

Shell tools must not make mutation-authority decisions by grepping JSON.  This
helper first applies one semantic JSON parse that rejects decoded duplicate
keys and non-canonical (escaped or non-ASCII) member names.  The latter keeps
the existing small POSIX readers safe until every consumer uses typed queries.

The version comparator deliberately avoids awk/IEEE-754 numeric conversion.
It compares bounded digit strings and prerelease identifiers directly, so its
result is identical on hosts and BusyBox-class targets.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_MANIFEST_BYTES = 256 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 4096
MAX_VERSION_BYTES = 128
MAX_VERSION_PARTS = 16
MAX_VERSION_PART_BYTES = 32
PACKAGE_ONLY_DENIED_TARGETS = frozenset(
    {
        "am3-s19xp",
        "am3-s19jxp",
        "am3-s21xp",
        "am3-t21",
        # A126/bm1362-nopic and S19j Pro+ emit package_only_denied too
        # (post-image-family: MTD writer incompatibility; no persistent
        # writer authority) — reconciled with the emitters after producer
        # run drop1-20260918-xtleogkg. am3-s19jpro-aml emits the same
        # denied contract unconditionally (its post-image: boot selection
        # and restore remain unimplemented).
        "am3-s19jproa",
        "am3-s19jproplus",
        "am3-s19jpro-aml",
        # The nopic lane's manifest identity is am3-s19kpro (its overlay,
        # post-build and post-image all hard-pin that board_target) and
        # its post-image denies in EVERY mode; the installable am3-s19k
        # lane never consults this set (installable=true path).
        "am3-s19kpro",
    }
)

KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*\Z")
DECIMAL = r"(?:0|[1-9][0-9]*)"
IDENTIFIER = r"[0-9A-Za-z-]+"
VERSION_RE = re.compile(
    rf"v?({DECIMAL}\.{DECIMAL}(?:\.{DECIMAL})?)"
    rf"(?:-({IDENTIFIER}(?:\.{IDENTIFIER})*))?"
    rf"(?:\+({IDENTIFIER}(?:\.{IDENTIFIER})*))?\Z"
)

#: Admitted toolbox.install_mode values (the typed operator-route contract
#: shared with scripts/lib/sysupgrade_package_common.sh
#: dcent_require_toolbox_{install,update}_contract and the toolbox
#: PackageManifest.toolbox_install_mode reader).
INSTALL_MODES = frozenset(
    {
        "target_sysupgrade",
        "host_driven_rootfs_window_lab",
        "first_install_only",
        "package_only_denied",
    }
)


class AdmissionError(ValueError):
    """Manifest or version input is outside the admitted language."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AdmissionError(f"duplicate decoded JSON member name: {key!r}")
        result[key] = value
    return result


def _reject_constant(token: str) -> None:
    raise AdmissionError(f"non-standard JSON numeric constant: {token}")


def _raw_member_names(text: str) -> list[tuple[str, bool]]:
    """Return raw JSON string tokens followed by ':' and whether they escape.

    ``json.loads`` has already proved the document grammar.  Therefore a JSON
    string token followed by optional whitespace and ``:`` is an object member
    name.  Keeping this lexical check separate lets the semantic parser detect
    decoded duplicates while this pass rejects spelling aliases such as
    ``"versi\\u006fn"`` that byte-oriented shell readers cannot see.
    """

    names: list[tuple[str, bool]] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] != '"':
            index += 1
            continue
        index += 1
        start = index
        escaped = False
        while index < length:
            char = text[index]
            if char == "\\":
                escaped = True
                index += 2
                continue
            if char == '"':
                break
            index += 1
        if index >= length:
            raise AdmissionError("unterminated JSON string")
        raw = text[start:index]
        index += 1
        probe = index
        while probe < length and text[probe] in " \t\r\n":
            probe += 1
        if probe < length and text[probe] == ":":
            names.append((raw, escaped))
    return names


def _bounded_tree(value: Any, depth: int = 0) -> int:
    if depth > MAX_JSON_DEPTH:
        raise AdmissionError(f"JSON nesting exceeds {MAX_JSON_DEPTH}")
    nodes = 1
    if isinstance(value, dict):
        for child in value.values():
            nodes += _bounded_tree(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            nodes += _bounded_tree(child, depth + 1)
    if nodes > MAX_JSON_NODES:
        raise AdmissionError(f"JSON node count exceeds {MAX_JSON_NODES}")
    return nodes


def admit_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AdmissionError(f"cannot read manifest {path}: {exc}") from exc
    if not raw:
        raise AdmissionError("manifest is empty")
    if len(raw) > MAX_MANIFEST_BYTES:
        raise AdmissionError(
            f"manifest exceeds {MAX_MANIFEST_BYTES} bytes: {len(raw)}"
        )
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AdmissionError("manifest is not strict UTF-8") from exc
    if "\\" in text:
        raise AdmissionError(
            "manifest JSON must not contain escape sequences; authority fields "
            "require literal canonical spelling"
        )
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, RecursionError, AdmissionError) as exc:
        raise AdmissionError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AdmissionError("manifest root must be a JSON object")
    _bounded_tree(value)
    for raw_name, escaped in _raw_member_names(text):
        if escaped:
            raise AdmissionError(
                f"JSON member names must use literal canonical spelling: {raw_name!r}"
            )
        if not KEY_RE.fullmatch(raw_name):
            raise AdmissionError(
                f"JSON member name is outside the canonical ASCII grammar: {raw_name!r}"
            )
    return value


def require_payload_binding(
    manifest: dict[str, Any],
    payload_name: str,
    expected_path: str,
    expected_size: int,
    expected_sha256: str,
) -> None:
    """Require one payload object's path, size, and digest as a typed tuple.

    Mutation authority must never be inferred from matching strings elsewhere
    in the document: that would admit swapped kernel/rootfs hashes or decoy
    values in unrelated fields.
    """

    payloads = manifest.get("payloads")
    if not isinstance(payloads, dict):
        raise AdmissionError("payloads must be a JSON object")
    payload = payloads.get(payload_name)
    if not isinstance(payload, dict):
        raise AdmissionError(f"payloads.{payload_name} must be a JSON object")
    expected = {
        "path": expected_path,
        "size": expected_size,
        "sha256": expected_sha256,
    }
    for field, expected_value in expected.items():
        actual = payload.get(field)
        if type(actual) is not type(expected_value) or actual != expected_value:
            raise AdmissionError(
                f"payloads.{payload_name}.{field} does not match the exact payload"
            )


def _toolbox_install_mode(manifest: dict[str, Any]) -> str | None:
    """Return the typed toolbox.install_mode, or None when the field is absent.

    Raises AdmissionError for a non-string, empty, or unadmitted mode value.
    """

    toolbox = manifest.get("toolbox")
    if toolbox is None:
        return None
    if not isinstance(toolbox, dict):
        return None
    if "install_mode" not in toolbox:
        return None
    mode = toolbox.get("install_mode")
    if not isinstance(mode, str) or mode != mode.strip() or not mode:
        raise AdmissionError("toolbox.install_mode must be an exact non-empty string")
    if mode not in INSTALL_MODES:
        raise AdmissionError(
            f"toolbox.install_mode {mode!r} is not an admitted route contract"
        )
    return mode


def require_install_mode_contract(manifest: dict[str, Any]) -> str | None:
    """Validate the typed operator-route contract carried by a manifest.

    ``first_install_only`` (AM1-A Drop-1 route scoping; owner adjudication
    AM1_S9_ROOTFS_WINDOW_ADJUDICATION Option A, ratified 2026-09-15) is an
    INSTALLABLE package whose contract
    explicitly DENIES the live-sysupgrade (self-update) route. The denial is
    machine-checkable, not an omitted field: update_command must be JSON null
    and install_command must remain the target-bound ``dcent install`` rail.
    Returns the admitted mode string (or None when the toolbox block carries
    no install_mode, which keeps legacy manifests inspectable).
    """

    mode = _toolbox_install_mode(manifest)
    if mode != "first_install_only":
        return mode

    toolbox = manifest.get("toolbox")
    if not isinstance(toolbox, dict):
        raise AdmissionError("first_install_only contract requires a toolbox object")
    update_command = toolbox.get("update_command")
    if update_command is not None:
        raise AdmissionError(
            "first_install_only contract must not advertise an update_command "
            "(self-update is explicitly denied)"
        )
    install_command = toolbox.get("install_command")
    if not isinstance(install_command, str) or not install_command.startswith(
        "dcent install <ip> -f "
    ):
        raise AdmissionError(
            "first_install_only contract requires a target-bound "
            "'dcent install <ip> -f ' install_command"
        )
    return mode


def require_package_authority(
    manifest: dict[str, Any], expected_board: str
) -> None:
    """Admit either an installable package or an exact non-installable recipe.

    ``installable=false`` is not a weaker spelling of install authority.  It is
    accepted only for explicitly enumerated package-only targets whose Toolbox
    metadata is entirely non-dispatching.  This lets offline tooling verify the
    archive's hashes and structure without borrowing a sibling board's storage
    geometry or mutation route.
    """

    if manifest.get("board") != expected_board:
        raise AdmissionError("manifest board does not match the expected board")
    if manifest.get("board_target") != expected_board:
        raise AdmissionError("manifest board_target does not match the expected board")

    installable = manifest.get("installable")
    if type(installable) is not bool:
        raise AdmissionError("installable must be a JSON boolean")

    toolbox = manifest.get("toolbox")
    if installable:
        if isinstance(toolbox, dict) and toolbox.get("install_mode") == "package_only_denied":
            raise AdmissionError(
                "installable=true contradicts toolbox.install_mode=package_only_denied"
            )
        # Typed route contract (first_install_only carries an explicit
        # self-update denial that every update consumer must refuse).
        require_install_mode_contract(manifest)
        return

    if expected_board not in PACKAGE_ONLY_DENIED_TARGETS:
        raise AdmissionError(
            f"installable=false package-only validation is not admitted for {expected_board}"
        )
    if not isinstance(toolbox, dict):
        raise AdmissionError("non-installable package requires a toolbox object")

    expected_fields: dict[str, Any] = {
        "install_command": None,
        "update_command": None,
        "upload_endpoint": None,
        "board_target_header": None,
        "requires_inactive_slot": False,
        "install_mode": "package_only_denied",
        "target_side_sysupgrade": False,
    }
    for field, expected_value in expected_fields.items():
        if field not in toolbox:
            raise AdmissionError(
                f"non-installable package requires toolbox.{field}"
            )
        actual = toolbox.get(field)
        if type(actual) is not type(expected_value) or actual != expected_value:
            raise AdmissionError(
                f"non-installable package requires toolbox.{field}={expected_value!r}"
            )


def _bounded_parts(value: str, separator: str) -> list[str]:
    parts = re.split(separator, value)
    if len(parts) > MAX_VERSION_PARTS:
        raise AdmissionError(f"version contains more than {MAX_VERSION_PARTS} parts")
    if any(len(part.encode("ascii")) > MAX_VERSION_PART_BYTES for part in parts):
        raise AdmissionError(
            f"version part exceeds {MAX_VERSION_PART_BYTES} ASCII bytes"
        )
    return parts


def parse_version(value: str) -> tuple[list[str], list[str]]:
    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AdmissionError("version must be ASCII") from exc
    if not encoded or len(encoded) > MAX_VERSION_BYTES:
        raise AdmissionError(
            f"version length must be 1..{MAX_VERSION_BYTES} ASCII bytes"
        )
    match = VERSION_RE.fullmatch(value)
    if match is None:
        raise AdmissionError(f"version is outside the canonical grammar: {value!r}")
    # The complete value bound limits core-number size. Do not impose the
    # suffix identifier limit here: core numbers are arbitrary-precision
    # canonical decimals and may legitimately exceed 32 digits.
    release = match.group(1).split(".")
    prerelease = (
        _bounded_parts(match.group(2), r"\.") if match.group(2) is not None else []
    )
    if match.group(3) is not None:
        _bounded_parts(match.group(3), r"\.")
    for identifier in prerelease:
        if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
            raise AdmissionError(
                "numeric prerelease identifiers must not contain leading zeroes"
            )
    return release, prerelease


def _normalize_digits(value: str) -> str:
    normalized = value.lstrip("0")
    return normalized or "0"


def _compare_digits(left: str, right: str) -> int:
    left = _normalize_digits(left)
    right = _normalize_digits(right)
    if len(left) != len(right):
        return 1 if len(left) > len(right) else -1
    return (left > right) - (left < right)


def _compare_release(left: list[str], right: list[str]) -> int:
    width = max(len(left), len(right))
    for index in range(width):
        result = _compare_digits(
            left[index] if index < len(left) else "0",
            right[index] if index < len(right) else "0",
        )
        if result:
            return result
    return 0


def _compare_prerelease(left: list[str], right: list[str]) -> int:
    if not left and not right:
        return 0
    if not left:
        return 1
    if not right:
        return -1
    for left_part, right_part in zip(left, right):
        left_numeric = left_part.isdigit()
        right_numeric = right_part.isdigit()
        if left_numeric and right_numeric:
            result = _compare_digits(left_part, right_part)
        elif left_numeric != right_numeric:
            result = -1 if left_numeric else 1
        else:
            result = (left_part > right_part) - (left_part < right_part)
        if result:
            return result
    return (len(left) > len(right)) - (len(left) < len(right))


def compare_versions(candidate: str, current: str) -> int:
    candidate_release, candidate_pre = parse_version(candidate)
    current_release, current_pre = parse_version(current)
    release_result = _compare_release(candidate_release, current_release)
    if release_result:
        return release_result
    return _compare_prerelease(candidate_pre, current_pre)


def read_version_file(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise AdmissionError(f"cannot read version file {path}: {exc}") from exc
    if b"\r" in raw or b"\0" in raw:
        raise AdmissionError("version file contains CR or NUL bytes")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or b"\n" in raw:
        raise AdmissionError("version file must contain exactly one non-empty line")
    try:
        value = raw.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise AdmissionError("version file must contain ASCII") from exc
    parse_version(value)
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("manifest", type=Path)
    compare_parser = subparsers.add_parser("compare-version")
    compare_parser.add_argument("candidate")
    compare_parser.add_argument("current")
    read_parser = subparsers.add_parser("read-version-file")
    read_parser.add_argument("path", type=Path)
    payload_parser = subparsers.add_parser("verify-payload")
    payload_parser.add_argument("manifest", type=Path)
    payload_parser.add_argument("payload_name")
    payload_parser.add_argument("expected_path")
    payload_parser.add_argument("expected_size", type=int)
    payload_parser.add_argument("expected_sha256")
    authority_parser = subparsers.add_parser("verify-package-authority")
    authority_parser.add_argument("manifest", type=Path)
    authority_parser.add_argument("expected_board")
    mode_parser = subparsers.add_parser("query-install-mode")
    mode_parser.add_argument("manifest", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            admit_manifest(args.manifest)
        elif args.command == "compare-version":
            print(compare_versions(args.candidate, args.current))
        elif args.command == "read-version-file":
            print(read_version_file(args.path))
        elif args.command == "verify-payload":
            require_payload_binding(
                admit_manifest(args.manifest),
                args.payload_name,
                args.expected_path,
                args.expected_size,
                args.expected_sha256,
            )
        elif args.command == "query-install-mode":
            # Typed route-contract query for shell gates (host pre-flash and
            # packagers). Prints the admitted install_mode, or "absent" when
            # the toolbox block carries none (legacy manifests).
            mode = require_install_mode_contract(admit_manifest(args.manifest))
            print(mode if mode is not None else "absent")
        else:
            require_package_authority(
                admit_manifest(args.manifest),
                args.expected_board,
            )
    except AdmissionError as exc:
        print(f"sysupgrade manifest admission: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
