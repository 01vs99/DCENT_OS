#!/usr/bin/env python3
"""Install exact S9i/j beta identity into a private, extracted S9 rootfs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import sys

TARGETS = ("am1-s9i", "am1-s9j")
CONFIGS = Path(__file__).resolve().parents[1] / "dcentrald/configs/beta"


def checked_path(root: Path, relative: str) -> Path:
    current = root
    for part in Path(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"rootfs path must not be a symlink: {relative}")
    return current


def prepare(root: Path, target: str, binaries: Path | None = None) -> None:
    if target not in TARGETS:
        raise ValueError(f"unsupported exact target: {target}")
    if root.is_symlink() or not root.is_dir():
        raise ValueError("rootfs must be a real staging directory")
    root = root.resolve()
    marker = checked_path(root, "etc/dcentos/board_target")
    if not marker.is_file() or marker.read_text().strip() != "am1-s9":
        raise ValueError("input rootfs must identify am1-s9")
    for name in ("data/dcentrald.toml", "data/dcentrald", "data/dcentrald-experimental.toml"):
        if checked_path(root, name).exists():
            raise ValueError(f"rootfs contains a persistent runtime override: {name}")
    daemon = checked_path(root, "usr/bin/dcentrald")
    if not daemon.is_file() or (os.name != "nt" and not daemon.stat().st_mode & stat.S_IXUSR):
        raise ValueError("rootfs must contain the executable current daemon")
    outputs = [
        (CONFIGS / f"{target}-baked-default.toml", checked_path(root, "etc/dcentrald.toml")),
    ]
    # Validate every source and destination before the first identity write.
    for source, destination in outputs:
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"missing regular config source: {source}")
        if destination.exists() and not destination.is_file():
            raise ValueError(f"configuration destination is not a regular file: {destination}")
    runtime_inputs = {}
    binary_outputs = []
    if binaries is not None:
        for name in ("dcentrald", "dcentos-discovery", "dcentos-init"):
            source = binaries / name
            if source.is_symlink() or not source.is_file():
                raise ValueError(f"current regular ARM binary required: {name}")
            data = source.read_bytes()
            if len(data) < 64 or data[:6] != b"\x7fELF\x01\x01" or struct.unpack_from("<H", data, 18)[0] != 40:
                raise ValueError(f"current ARMv7 ELF required: {name}")
            destination = checked_path(root, "sbin/init" if name == "dcentos-init" else "usr/bin/" + name)
            binary_outputs.append((source, destination))
            runtime_inputs[name] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    for source, destination in outputs:
        shutil.copyfile(source, destination)
        destination.chmod(0o644)
    for source, destination in binary_outputs:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
    if runtime_inputs:
        for name in ("dcentrald", "dcentos-init"):
            checked_path(root, f"etc/dcentos/{name}.sha256").write_text(runtime_inputs[name]["sha256"] + "\n")
        checked_path(root, "etc/dcentos/dcentrald.md5").write_text(
            hashlib.md5((binaries / "dcentrald").read_bytes(), usedforsecurity=False).hexdigest() + "\n")
        checked_path(root, "etc/dcentos/native-runtime-inputs.json").write_text(json.dumps(runtime_inputs, indent=2) + "\n")
    marker.write_text(target + "\n")
    marker.chmod(0o644)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--board-target", choices=TARGETS, required=True)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--binaries", type=Path, help="Install all three current ARMv7 executables before producing the variant")
    args = parser.parse_args()
    try:
        prepare(args.rootfs, args.board_target, args.binaries)
    except (OSError, ValueError) as error:
        print(f"S9 variant staging refused: {error}", file=sys.stderr)
        return 2
    print(f"Prepared {args.board_target}: native BM1387 beta, mining initially disabled")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
