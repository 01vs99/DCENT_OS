#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare exact compact native17 candidate local loader review files.

Compact-candidate counterpart of prepare_loader_review.py. It stages the same
guarded five-file chain with the compact candidate's own prepared data and the
compact-compiled runtime, and never executes a command. The accepted native20
producer is unchanged; this file pins only the compact native17 profile.
Support this project: https://d-central.tech/fund/
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import zlib

import prepare
from prepare_loader_review import CHECK_ADDRESS, NAMES, OUTER_CONTRACTS, command_text

ENTRY_ADDRESS = 0x07800000
ENTRY_PIN = {"bytes": 24760, "sha256": "0107a972722bff1d28f96d7da522b68a7ca1dbb3496c207031b8e264aeb95a05"}
DESCRIPTOR_PIN = {"bytes": 256, "sha256": "14dd97d3d67531832c629a2a50dd3803c65ddf80599316270f79e185e1e88d1e"}
DATA_MANIFEST_PIN = {"bytes": 1695, "sha256": "5c269451235f4987d93bb40413d0a1aa764c2c01619cd0b2e1e5ec6d5e5e2ca7"}
CANDIDATE_BYTES = 37724160


def compose(candidate_raw, entry_raw):
    prepare.require(prepare.pin(candidate_raw) == {"bytes": CANDIDATE_BYTES,
        "sha256": "627fe3c9e9aacd753df9fd0c70217e44df3416631f81f12dcb6338a0c61d5285"},
        "candidate is not the compact native17 Classic candidate")
    prepare.require(prepare.pin(entry_raw) == ENTRY_PIN, "unrecognized compiled runtime; exact compact build required")
    prepared, data_manifest = prepare.compose(candidate_raw)
    prepare.require(prepare.pin(prepared["descriptor.bin"]) == DESCRIPTOR_PIN,
                    "candidate does not match this runtime's compiled compact descriptor profile")
    files = {name: prepared[name] for name in NAMES if name != "classic-entry.bin"}
    files["classic-entry.bin"] = entry_raw
    addresses = dict(data_manifest["addresses"], **{"classic-entry.bin": ENTRY_ADDRESS})
    command = command_text(files, addresses)
    manifest = {
        "schema": "dcentos.classic_aml_loader_review.v1",
        "board_target": prepare.reader.TARGET,
        "status": "local_loader_review_files",
        "candidate": prepare.pin(candidate_raw),
        "compiled_runtime": ENTRY_PIN,
        "compiled_descriptor": DESCRIPTOR_PIN,
        "members": {name: prepare.pin(body) for name, body in files.items()},
        "addresses": addresses,
        "command_text": {"name": "LOAD_REVIEW.txt", **prepare.pin(command)},
        "transport": {"interface": "usb", "device": "0", "physical_device_identity_proven": False},
        "CRC_result_address": CHECK_ADDRESS,
        "CRC_is_authentication": False,
        "executable_runtime_artifact": True,
        "automatic_boot_script": False,
        "install_admission": False,
        "physical_readiness": False,
        "signature": None,
        "publication": False,
        "commands_executed": False,
        "runtime_data": data_manifest,
        "outer_contracts": list(OUTER_CONTRACTS),
    }
    files["LOAD_REVIEW.txt"] = command
    files["LOADER_REVIEW.json"] = prepare.canonical(manifest)
    return files, manifest


def stage(candidate, entry, expected_candidate_sha256, output, *, fault=None):
    candidate_raw = prepare.reader.regular_bytes(candidate)
    entry_raw = prepare.reader.regular_bytes(entry, 65536)
    prepare.require(prepare.pin(candidate_raw)["sha256"] == expected_candidate_sha256, "candidate digest differs")
    files, manifest = compose(candidate_raw, entry_raw)
    output = prepare.reader._plain_path(output)
    output.mkdir(mode=0o700)
    # Commit manifest last; an interrupted directory is preserved for inspection.
    for name in (*NAMES, "LOAD_REVIEW.txt"):
        prepare.reader._write_new(output / name, files[name])
        prepare.require(prepare.reader.regular_bytes(output / name) == files[name], "staged member changed: " + name)
        if fault:
            fault(name)
    prepare.reader._write_new(output / "LOADER_REVIEW.json", files["LOADER_REVIEW.json"])
    prepare.require(prepare.reader.regular_bytes(output / "LOADER_REVIEW.json", 65536) == files["LOADER_REVIEW.json"],
                    "staged commit changed")
    prepare.reader._sync_directory(output)
    prepare.reader._sync_directory(output.parent)
    return manifest


def inspect(output):
    """Read committed regular review files and check their descriptor/commands.

    Mirrors the accepted native20 reader with the compact native17 pins. This
    reader parses the command operands independently of command_text(). It
    accepts only this exact compiled profile and never promotes install
    authority.
    """
    directory = prepare.reader._plain_path(output)
    prepare.require(directory.is_dir(), "loader review directory required")
    prepare.require({item.name for item in directory.iterdir()} ==
                    {*NAMES, "LOAD_REVIEW.txt", "LOADER_REVIEW.json"}, "complete loader review directory required")
    manifest = prepare.reader.object_json(prepare.reader.regular_bytes(directory / "LOADER_REVIEW.json", 65536))
    prepare.require(set(manifest) == set((
        "schema board_target status candidate compiled_runtime compiled_descriptor members addresses command_text transport "
        "CRC_result_address CRC_is_authentication executable_runtime_artifact automatic_boot_script install_admission "
        "physical_readiness signature publication commands_executed runtime_data outer_contracts").split()),
        "loader manifest field set differs")
    prepare.require(manifest["schema"] == "dcentos.classic_aml_loader_review.v1"
                    and manifest["board_target"] == prepare.reader.TARGET
                    and manifest["status"] == "local_loader_review_files", "loader review identity differs")
    for name in ("automatic_boot_script", "install_admission", "physical_readiness", "publication", "commands_executed"):
        prepare.require(manifest[name] is False, "unrecognized authority field: " + name)
    prepare.require(manifest["signature"] is None and manifest["CRC_is_authentication"] is False
                    and manifest["executable_runtime_artifact"] is True, "loader authentication/status differs")
    prepare.require(prepare.pin(prepare.canonical(manifest["runtime_data"])) == DATA_MANIFEST_PIN
                    and manifest["outer_contracts"] == list(OUTER_CONTRACTS), "data provenance or remaining contracts differ")
    limits = {"Image": 32 * 1024 * 1024, "initrd.gz": 32 * 1024 * 1024,
              "final.dtb": 65536, "descriptor.bin": 256, "classic-entry.bin": 65536}
    files = {name: prepare.reader.regular_bytes(directory / name, limits[name]) for name in NAMES}
    prepare.require(prepare.pin(files["classic-entry.bin"]) == ENTRY_PIN and manifest["compiled_runtime"] == ENTRY_PIN,
                    "compiled runtime changed")
    descriptor = files["descriptor.bin"]
    prepare.require(prepare.pin(descriptor) == DESCRIPTOR_PIN and manifest["compiled_descriptor"] == DESCRIPTOR_PIN,
                    "compiled descriptor changed")
    kernel, kernel_bytes, _, initrd, initrd_bytes, fdt, fdt_bytes, _ = struct.unpack_from("<8Q", descriptor, 16)
    addresses = {"Image": kernel, "initrd.gz": initrd, "final.dtb": fdt,
                 "descriptor.bin": prepare.DESCRIPTOR_ADDRESS, "classic-entry.bin": ENTRY_ADDRESS}
    for name, size, offset in (("Image", kernel_bytes, 80), ("initrd.gz", initrd_bytes, 112), ("final.dtb", fdt_bytes, 144)):
        prepare.require(prepare.pin(files[name]) == {"bytes": size, "sha256": descriptor[offset:offset + 32].hex()},
                        "descriptor member differs: " + name)
    prepare.require(manifest["members"] == {name: prepare.pin(body) for name, body in files.items()}
                    and manifest["addresses"] == addresses and manifest["CRC_result_address"] == CHECK_ADDRESS,
                    "manifest member/placement differs")
    prepare.require(manifest["candidate"] == {"bytes": CANDIDATE_BYTES, "sha256": descriptor[208:240].hex()},
                    "source candidate differs")
    prepare.require(manifest["transport"] == {"interface": "usb", "device": "0", "physical_device_identity_proven": False},
                    "transport review scope differs")
    command = prepare.reader.regular_bytes(directory / "LOAD_REVIEW.txt", 4096)
    prepare.require(manifest["command_text"] == {"name": "LOAD_REVIEW.txt", **prepare.pin(command)}, "command digest differs")
    prepare.require(command.endswith(b"\n") and b"\r" not in command, "command text framing differs")
    commands = command[:-1].decode("ascii").split(" && ")
    prepare.require(len(commands) == 32 and commands[0] == "icache off"
                    and commands[-1] == "go 7800000", "command sequence differs")
    for index, name in enumerate(NAMES):
        block = [line.split(" ") for line in commands[1 + index * 6:7 + index * 6]]
        prepare.require(block[0] == ["setenv", "filesize", "0"] and block[1] == ["itest.l", "${filesize}", "==", "0"],
                        "filesize reset/readback missing")
        prepare.require(block[2] == ["fatload", "usb", "0", format(addresses[name], "x"), name, format(len(files[name]), "x")],
                        "file load bound differs")
        prepare.require(block[3] == ["itest.l", "${filesize}", "==", format(len(files[name]), "x")], "actual byte count check differs")
        prepare.require(block[4] == ["crc32", format(addresses[name], "x"), format(len(files[name]), "x"), format(CHECK_ADDRESS, "x")],
                        "CRC calculation differs")
        compared = int.from_bytes(zlib.crc32(files[name]).to_bytes(4, "big"), "little")
        prepare.require(block[5] == ["itest.l", "*7810200", "==", format(compared, "x")], "CRC comparison differs")
    return {"status": "local_loader_review_verified", "members": manifest["members"],
            "candidate": manifest["candidate"], "command_text": manifest["command_text"],
            "install_admission": False, "physical_readiness": False, "publication": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path, nargs="?")
    parser.add_argument("--entry", type=Path)
    parser.add_argument("--expected-candidate-sha256")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inspect", type=Path, metavar="DIRECTORY", help="inspect committed regular review files")
    args = parser.parse_args()
    if args.inspect is not None:
        if any(value is not None for value in (args.candidate, args.entry, args.expected_candidate_sha256, args.output)):
            parser.error("--inspect cannot be combined with preparation arguments")
    elif any(value is None for value in (args.candidate, args.entry, args.expected_candidate_sha256, args.output)):
        parser.error("preparation requires candidate, --entry, --expected-candidate-sha256 and --output")
    try:
        report = inspect(args.inspect) if args.inspect is not None else stage(
            args.candidate, args.entry, args.expected_candidate_sha256, args.output)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
