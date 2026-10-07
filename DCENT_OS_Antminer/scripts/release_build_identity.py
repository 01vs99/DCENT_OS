#!/usr/bin/env python3
"""Bind current release compilation to its independently trusted OTA key.

This supplements current producer builds. Historical receipt schemas and the
separate stock-firmware manifest key keep their original meanings.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path
import sys

import runtime_image_manifest as runtime

OTA_KEY = "DCENT_OTA_PUBLIC_KEY_HEX"


def key_hex(pubkey: Path, expected: str | None = None) -> str:
    value = runtime.public_key_bytes(pubkey).hex()
    if expected is not None and (re.fullmatch(r"[0-9a-f]{64}", expected) is None or expected != value):
        raise runtime.ManifestError("compiled OTA key must equal the independently trusted release public key")
    return value


def verify(binary: Path, compile_environment: Path, pubkey: Path, version: str) -> None:
    expected = key_hex(pubkey)
    entries: dict[str, str] = {}
    for line in runtime.regular_bytes(compile_environment, 1024 * 1024).decode("utf-8").splitlines():
        if "=" not in line:
            raise runtime.ManifestError("malformed compile environment")
        name, value = line.split("=", 1)
        if not name or name in entries:
            raise runtime.ManifestError("duplicate or empty compile environment key")
        entries[name] = value
    if entries.get(OTA_KEY) != expected:
        raise runtime.ManifestError("compile observation is missing the exact trusted OTA public key")
    identity = runtime.build_identity(runtime.regular_bytes(binary, runtime.MAX_DAEMON))
    if identity["public_key"].hex() != expected or identity["version"] != version:
        raise runtime.ManifestError("actual daemon ELF does not contain the expected release key/version")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    key = commands.add_parser("key")
    key.add_argument("--pubkey", required=True, type=Path)
    key.add_argument("--expected")
    check = commands.add_parser("verify")
    check.add_argument("--pubkey", required=True, type=Path)
    check.add_argument("--binary", required=True, type=Path)
    check.add_argument("--compile-environment", required=True, type=Path)
    check.add_argument("--version", required=True)
    args = parser.parse_args()
    try:
        if args.action == "key":
            print(key_hex(args.pubkey, args.expected))
        else:
            verify(args.binary, args.compile_environment, args.pubkey, args.version)
            print("verified compiled release OTA identity")
        return 0
    except (OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
