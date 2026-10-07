#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Compile an exact NoPIC descriptor specialization of immutable reviewed leaves."""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[4]
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("nopic_entry_prepare", HERE / "prepare.py")
data = importlib.util.module_from_spec(spec)
spec.loader.exec_module(data)


def pin(path):
    return data.reader.pin(path.read_bytes())


def validate_inputs(directory, candidate, boot_source, target):
    directory, candidate, boot_source = (path.absolute() for path in (directory, candidate, boot_source))
    report = data.inspect(directory, data.reader.regular_bytes(candidate),
                          data.reader.regular_bytes(boot_source, data.reader.MAX_SOURCE), target)
    receipt = ROOT / ""
    data.require(pin(receipt) == {"bytes": 9686, "sha256": "608d1a5b4b576c77f7bddbc67c531b6cd8ed228c753bf837fdf5d0be6b8de478"}, "accepted runtime build receipt differs")
    accepted = json.loads(receipt.read_text())
    sources = {}
    for name, row in accepted["sources"].items():
        path = ROOT / name
        data.require(pin(path) == row, "immutable accepted runtime input changed: " + name)
        sources[path.relative_to(ROOT).as_posix()] = row
    for path in (Path(__file__), HERE / "prepare.py", candidate, boot_source, directory / "ENTRY_DATA.json", directory / "entry-profile.h"):
        sources[path.relative_to(ROOT).as_posix()] = pin(path)
    return report, sources


def build(directory, candidate, boot_source, target, output, receipt, zig):
    directory, candidate, boot_source, output, receipt = (path.absolute() for path in (directory, candidate, boot_source, output, receipt))
    report, sources = validate_inputs(directory, candidate, boot_source, target)
    output = data.reader._plain_path(output)
    data.require(not output.exists() and not receipt.exists(), "new build directory and receipt required")
    output.mkdir(mode=0o700)
    profile = output / "entry-profile.h"
    data.reader._write_new(profile, data.reader.regular_bytes(directory / "entry-profile.h", 4096))
    source = ROOT / "DCENT_OS_Antminer/scripts/classic_aml_entry"
    inputs = [source / name for name in ("runtime_bootstrap.S", "runtime.c", "mmio.S", "cache.S", "handoff.S", "finish.S")]
    elf, binary = output / "nopic-entry.elf", output / "nopic-entry.bin"
    commands = [[str(zig), "cc", "-target", "aarch64-freestanding-none",
        "-mcpu=generic+el3+reserve_x18-neon-fp_armv8", "-O2", "-ffreestanding", "-nostdlib",
        "-fno-builtin", "-fno-stack-protector", "-fno-pic", "-ffixed-x18", "-mgeneral-regs-only",
        "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-I", str(source), "-I", str(output),
        "-Wl,-T," + str(source / "entry.ld"), "-Wl,--build-id=none", *[str(path) for path in inputs], "-o", str(elf)],
        [str(zig), "objcopy", "-O", "binary", str(elf), str(binary)],
        ["readelf", "-h", "-l", "-s", str(elf)]]
    rows = []
    for index, command in enumerate(commands):
        process = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        log = output / (str(index) + ".log")
        log.open("xb").write(process.stdout)
        rows.append({"command": command, "exit_code": process.returncode, "log": {"path": log.relative_to(ROOT).as_posix(), **pin(log)}})
        if process.returncode:
            break
    unchanged = all(pin(ROOT / name) == row for name, row in sources.items())
    passed = len(rows) == 3 and all(row["exit_code"] == 0 for row in rows) and unchanged
    result = {"status": "PASS" if passed else "FAIL", "board_target": target, "data_inspection": report,
              "sources": sources, "sources_unchanged": unchanged, "commands": rows,
              "artifacts": {path.relative_to(ROOT).as_posix(): pin(path) for path in (elf, binary) if path.exists()},
              "generated_profile": pin(profile), "zig_binary": {"path": str(zig), **pin(zig)},
              "prerequisites": data.PREREQUISITES, "compiled_validation_complete": False,
              "hardware_contact": False, "physical_entry_authorized": False,
              "persistent_install_authorized": False, "signing": False, "publication": False}
    receipt.open("x", encoding="utf-8").write(json.dumps(result, indent=2) + "\n")
    data.require(passed, "NoPIC compilation failed; retained exact receipt and logs")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=tuple(data.BOOT_SOURCES), required=True)
    parser.add_argument("--data-directory", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--boot-source-tar", type=Path, required=True)
    parser.add_argument("--check-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--zig", type=Path, default=Path("/opt/zig-0.13.0/zig"))
    args = parser.parse_args()
    try:
        if args.check_only:
            data.require(args.output is None and args.receipt is None, "check-only does not create build outputs")
            report, sources = validate_inputs(args.data_directory, args.candidate, args.boot_source_tar, args.target)
            result = {"status": "source_ready_compile_pending", "data": report, "sources": sources, "compiler_executed": False}
        else:
            data.require(args.output is not None and args.receipt is not None, "build output and receipt required")
            result = build(args.data_directory, args.candidate, args.boot_source_tar, args.target, args.output, args.receipt, args.zig)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
