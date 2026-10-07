#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare or inspect exact native21 NoPIC local loader review files.

Only regular host files are consumed or created. Commands are textual artifacts.
Support this project: https://d-central.tech/fund/
"""
from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct
import zlib

spec = importlib.util.spec_from_file_location("nopic_loader_data", Path(__file__).with_name("prepare.py"))
data = importlib.util.module_from_spec(spec)
spec.loader.exec_module(data)
reader, require = data.reader, data.require
ENTRY_ADDRESS, DESCRIPTOR_ADDRESS, CHECK_ADDRESS = 0x07800000, 0x07810000, 0x07810200
NAMES = ("Image", "initrd.gz", "final.dtb", "descriptor.bin", "nopic-entry.bin")
PROFILES = {
    "am3-s19jproa": {
        "entry": {"bytes": 24760, "sha256": "8150b77d77b40a62b46802c94205fa4161f4cc315284decc239c26f508d55a41"},
        "descriptor": {"bytes": 256, "sha256": "9abbb67e4854719ff7a1a01ab9a92c9b573658435d4c6d11fbd3fde6f726b138"},
        "data": {"bytes": 1969, "sha256": "a71b2a19b92ebfb74f50f813aecf501b76575e84baf1f3cf489fb4c8234e21f9"},
    },
    "am3-s19jproplus": {
        "entry": {"bytes": 24760, "sha256": "737468c8f50dd96981b22ad22e1a246145fba59b0579c2fb104c398ab3c04a11"},
        "descriptor": {"bytes": 256, "sha256": "759e83a99e334138725e765caa5a7f17e46af9f2d84c7351e5b21e8533a5800e"},
        "data": {"bytes": 1975, "sha256": "21eb91ec63863454605ab30f8793841eed3a97c0fa4fdd90aa347123c6c26e7f"},
    },
}
OUTER_CONTRACTS = (
    "exact target source-bound resident relocation and cold BL2/BL31 lineage with empty BL32",
    "prior secondary private-cache retirement and initialized writable EL2 architectural state",
    "no intervening secure crypto transaction and complete remaining actor/memory custody",
    "accepted Device writes and source-derived controller clock/mux profile",
    "regular-file source authentication before transport; CRC is corruption detection only",
    "real FAT/environment and data-cache clean completion before uncached first instruction fetch",
    "independent loader review, physical validation, signing and publication boundaries",
)


def command_text(files, addresses):
    require(set(files) == set(NAMES) == set(addresses), "loader member set differs")
    commands = ["icache off"]
    for name in NAMES:
        raw, address = files[name], addresses[name]
        require(raw and isinstance(address, int), "empty or unplaced member")
        # Held crc32 writes big-endian bytes; held itest.l reads a little-endian word.
        compared = struct.unpack("<I", struct.pack(">I", zlib.crc32(raw)))[0]
        commands.extend(["setenv filesize 0", "itest.l ${filesize} == 0",
            f"fatload usb 0 {address:x} {name} {len(raw):x}",
            f"itest.l ${{filesize}} == {len(raw):x}",
            f"crc32 {address:x} {len(raw):x} {CHECK_ADDRESS:x}",
            f"itest.l *{CHECK_ADDRESS:x} == {compared:x}"])
    return (" && ".join(commands + [f"go {ENTRY_ADDRESS:x}"]) + "\n").encode("ascii")


def compose(candidate, boot_source, entry, target):
    require(target in PROFILES, "exact NoPIC target required")
    profile = PROFILES[target]
    require(reader.pin(entry) == profile["entry"], "exact target compiled entry differs")
    prepared, source = data.compose(candidate, boot_source, target)
    require(reader.pin(reader.canonical(source)) == profile["data"], "compiled target data differs")
    require(reader.pin(prepared["descriptor.bin"]) == profile["descriptor"], "compiled target descriptor differs")
    files = {name: prepared[name] for name in NAMES[:-1]}
    files["nopic-entry.bin"] = entry
    kernel, _, _, initrd, _, fdt, _, _ = struct.unpack_from("<8Q", files["descriptor.bin"], 16)
    addresses = dict(zip(NAMES, (kernel, initrd, fdt, DESCRIPTOR_ADDRESS, ENTRY_ADDRESS)))
    command = command_text(files, addresses)
    manifest = {"schema": "dcentos.nopic_aml_loader_review.v1", "board_target": target,
        "status": "local_loader_review_files", "candidate": source["candidate"],
        "boot_source_archive": source["boot_source_archive"], "compiled_runtime": profile["entry"],
        "compiled_descriptor": profile["descriptor"], "runtime_data": source,
        "members": {name: reader.pin(raw) for name, raw in files.items()}, "addresses": addresses,
        "command_text": {"name": "LOAD_REVIEW.txt", **reader.pin(command)}, "CRC_result_address": CHECK_ADDRESS,
        "transport": {"interface": "usb", "device": "0", "physical_device_identity_proven": False},
        "CRC_is_authentication": False, "executable_runtime_artifact": True, "automatic_boot_script": False,
        "install_admission": False, "physical_readiness": False, "signature": None,
        "publication": False, "commands_executed": False, "outer_contracts": list(OUTER_CONTRACTS)}
    files["LOAD_REVIEW.txt"], files["LOADER_REVIEW.json"] = command, reader.canonical(manifest)
    return files, manifest


def inspect(directory, target):
    """Independently parse all command operands against immutable target pins."""
    require(target in PROFILES, "exact NoPIC target required")
    profile = PROFILES[target]
    directory = reader._plain_path(directory)
    require(directory.is_dir() and {p.name for p in directory.iterdir()} ==
            {*NAMES, "LOAD_REVIEW.txt", "LOADER_REVIEW.json"}, "complete loader directory required")
    manifest = reader.object_json(reader.regular_bytes(directory / "LOADER_REVIEW.json", 65536))
    fields = ("schema board_target status candidate boot_source_archive compiled_runtime compiled_descriptor runtime_data "
              "members addresses command_text CRC_result_address transport CRC_is_authentication executable_runtime_artifact "
              "automatic_boot_script install_admission physical_readiness signature publication commands_executed outer_contracts").split()
    require(set(manifest) == set(fields), "loader manifest field set differs")
    require(manifest["schema"] == "dcentos.nopic_aml_loader_review.v1" and manifest["board_target"] == target
            and manifest["status"] == "local_loader_review_files", "loader identity differs")
    require(reader.pin(reader.canonical(manifest["runtime_data"])) == profile["data"], "target data provenance differs")
    require(manifest["outer_contracts"] == list(OUTER_CONTRACTS), "remaining contracts differ")
    for name in ("automatic_boot_script", "install_admission", "physical_readiness", "publication", "commands_executed", "CRC_is_authentication"):
        require(manifest[name] is False, "unrecognized authority field: " + name)
    require(manifest["signature"] is None and manifest["executable_runtime_artifact"] is True, "authentication/status differs")
    limits = dict(zip(NAMES, (32 * 1024 * 1024, 32 * 1024 * 1024, 65536, 256, 65536)))
    files = {name: reader.regular_bytes(directory / name, limits[name]) for name in NAMES}
    require(reader.pin(files["nopic-entry.bin"]) == profile["entry"] == manifest["compiled_runtime"], "compiled entry differs")
    descriptor = files["descriptor.bin"]
    require(reader.pin(descriptor) == profile["descriptor"] == manifest["compiled_descriptor"], "compiled descriptor differs")
    kernel, kernel_bytes, _, initrd, initrd_bytes, fdt, fdt_bytes, _ = struct.unpack_from("<8Q", descriptor, 16)
    for name, size, offset in (("Image", kernel_bytes, 80), ("initrd.gz", initrd_bytes, 112), ("final.dtb", fdt_bytes, 144)):
        require(reader.pin(files[name]) == {"bytes": size, "sha256": descriptor[offset:offset+32].hex()}, "descriptor payload differs: " + name)
    addresses = dict(zip(NAMES, (kernel, initrd, fdt, DESCRIPTOR_ADDRESS, ENTRY_ADDRESS)))
    require(manifest["members"] == {name: reader.pin(raw) for name, raw in files.items()}
            and manifest["addresses"] == addresses and manifest["CRC_result_address"] == CHECK_ADDRESS, "member/placement differs")
    require(manifest["candidate"] == manifest["runtime_data"]["candidate"] ==
            {"bytes": 36782080, "sha256": descriptor[208:240].hex()}, "source candidate differs")
    require(manifest["boot_source_archive"] == data.BOOT_SOURCES[target] == manifest["runtime_data"]["boot_source_archive"], "boot source differs")
    require(manifest["transport"] == {"interface": "usb", "device": "0", "physical_device_identity_proven": False}, "transport differs")
    command = reader.regular_bytes(directory / "LOAD_REVIEW.txt", 4096)
    require(manifest["command_text"] == {"name": "LOAD_REVIEW.txt", **reader.pin(command)}, "command digest differs")
    require(command.endswith(b"\n") and b"\r" not in command, "command framing differs")
    commands = command[:-1].decode("ascii").split(" && ")
    require(len(commands) == 32 and commands[0] == "icache off" and commands[-1] == "go 7800000", "command sequence differs")
    for index, name in enumerate(NAMES):
        block = [line.split(" ") for line in commands[1+index*6:7+index*6]]
        require(block[0] == ["setenv", "filesize", "0"] and block[1] == ["itest.l", "${filesize}", "==", "0"], "filesize reset differs")
        require(block[2] == ["fatload", "usb", "0", format(addresses[name], "x"), name, format(len(files[name]), "x")], "file load differs")
        require(block[3] == ["itest.l", "${filesize}", "==", format(len(files[name]), "x")], "file count differs")
        require(block[4] == ["crc32", format(addresses[name], "x"), format(len(files[name]), "x"), format(CHECK_ADDRESS, "x")], "CRC calculation differs")
        compared = int.from_bytes(zlib.crc32(files[name]).to_bytes(4, "big"), "little")
        require(block[5] == ["itest.l", "*7810200", "==", format(compared, "x")], "CRC comparison differs")
    return {"status": "local_nopic_loader_review_verified", "board_target": target, "members": manifest["members"],
            "candidate": manifest["candidate"], "boot_source_archive": manifest["boot_source_archive"],
            "command_text": manifest["command_text"], "install_admission": False, "physical_readiness": False, "publication": False}


def stage(candidate_path, boot_source_path, entry_path, target, output, *, fault=None):
    candidate = reader.regular_bytes(candidate_path)
    boot_source = reader.regular_bytes(boot_source_path, reader.MAX_SOURCE)
    entry = reader.regular_bytes(entry_path, 65536)
    files, manifest = compose(candidate, boot_source, entry, target)
    output = reader._plain_path(output)
    output.mkdir(mode=0o700)
    for name in (*NAMES, "LOAD_REVIEW.txt"):
        reader._write_new(output / name, files[name])
        require(reader.regular_bytes(output / name) == files[name], "staged member differs: " + name)
        if fault:
            fault(name)
    reader._write_new(output / "LOADER_REVIEW.json", files["LOADER_REVIEW.json"])
    if fault:
        fault("commit_written")
    inspect(output, target)
    require(reader.regular_bytes(candidate_path) == candidate and
            reader.regular_bytes(boot_source_path, reader.MAX_SOURCE) == boot_source and
            reader.regular_bytes(entry_path, 65536) == entry, "source changed during preparation")
    reader._sync_directory(output)
    reader._sync_directory(output.parent)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=tuple(PROFILES), required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--boot-source-tar", type=Path)
    parser.add_argument("--entry", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inspect", type=Path)
    args = parser.parse_args()
    preparation = (args.candidate, args.boot_source_tar, args.entry, args.output)
    if args.inspect is not None:
        if any(value is not None for value in preparation):
            parser.error("--inspect cannot be combined with preparation arguments")
    elif any(value is None for value in preparation):
        parser.error("preparation requires --candidate, --boot-source-tar, --entry and --output")
    try:
        report = inspect(args.inspect, args.target) if args.inspect is not None else stage(
            args.candidate, args.boot_source_tar, args.entry, args.target, args.output)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
