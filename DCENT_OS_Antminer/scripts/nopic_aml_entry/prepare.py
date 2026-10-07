#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare distinct NoPIC direct-entry data and a compiled-profile input locally."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "projects/dcent-toolbox/src"))
from dcent_toolbox.core import nopic_aml_candidate as reader

SCHEMA = "dcentos.nopic_aml_direct_entry_data.v1"
ABI = "DCE2CL01_256_v1"
BOOT_SOURCES = {
    "am3-s19jproa": {"bytes": 41823184, "sha256": "152edc734bcc71af5530c78f39f9e4473606ab263545d795d6809f4830c41d61"},
    "am3-s19jproplus": {"bytes": 41823293, "sha256": "8dce899c56de509e65eff96fcbb66dbbe06af0f4eccdab59d4c9c834074f3ecd"},
}
PREREQUISITES = [
    "exact held resident BL33 and cold BL2/BL31 source lineage",
    "empty BL32 cold route with no intervening secure crypto operation",
    "prior secondary private-cache retirement and no subsequent CPU_ON",
    "complete remaining actor and payload memory custody",
    "architecturally ordered accepted Device writes with admitted clocks and muxes",
    "initialized remaining writable EL2 architectural state",
]
AUTHORITY = {"hardware_contact": False, "executable_entry_built": False,
             "physical_entry_authorized": False, "persistent_install_authorized": False,
             "release_signature_verified": False, "publication": False}
FILES = {"Image", "initrd.gz", "final.dtb", "descriptor.bin", "entry-profile.h"}
KERNEL_ADDRESS = 0x01080000
FDT_ADDRESS = 0x056a2000
BOOTARGS = b"console=ttyAML0,115200n8 rdinit=/init\0"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def _dependencies():
    # Existing accepted code stays immutable. The shared ABI labels its byte
    # layout, while each NoPIC target is bound by its complete descriptor hash.
    helper = ROOT / "DCENT_OS_Antminer/scripts/classic_aml_entry/prepare.py"
    require(reader.pin(helper.read_bytes()) == {"bytes": 7721, "sha256": "1ed89237a69789ac0117670e0da90d4758cac8a9ec3086cc71b874bb49fa45dd"}, "reviewed FDT helper changed")
    spec = importlib.util.spec_from_file_location("nopic_held_fdt_helper", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    evidence = ROOT / ""
    source_receipt = evidence / "nopic-entry-source-v2.json"
    require(reader.pin(source_receipt.read_bytes()) == {"bytes": 42750, "sha256": "675201a89a869bef42f5539438f60eb149a435ac8908b542d4b8c33a80f1fd9f"}, "NoPIC boot source proof changed")
    previous = evidence / "classic-entry-runtime-build-v2.json"
    require(reader.pin(previous.read_bytes()) == {"bytes": 9686, "sha256": "608d1a5b4b576c77f7bddbc67c531b6cd8ed228c753bf837fdf5d0be6b8de478"}, "reviewed runtime receipt changed")
    record = reader.object_json(previous.read_bytes())
    require(record["status"] == "PASS", "reviewed runtime build missing")
    profile = ROOT / "DCENT_OS_Antminer/output/i02-classic-entry-runtime-v2/entry-profile.h"
    require(reader.pin(profile.read_bytes()) == {"bytes": 674, "sha256": "07e9f58171c829e80975ee17a0d44ef712a27e6e7a0e8f98861ba8d6231d01f5"}, "held resident profile identity differs")
    source_key = next(key for key in record["sources"] if Path(key).name == "entry-profile.h")
    require(reader.pin(profile.read_bytes()) == record["sources"][source_key], "reviewed resident profile changed")
    return module.final_dtb, profile.read_bytes(), {
        "fdt_helper": reader.pin(helper.read_bytes()), "boot_source_proof": reader.pin(source_receipt.read_bytes()),
        "resident_profile": reader.pin(profile.read_bytes()), "runtime_build_receipt": reader.pin(previous.read_bytes()),
    }


def _inputs(candidate, boot_source, target):
    require(target in BOOT_SOURCES and reader.pin(boot_source) == BOOT_SOURCES[target], "exact NoPIC boot source differs")
    report = reader.inspect_bytes(candidate, expected_target=target)
    blobs = reader.archive_members(candidate)
    kernel = reader.gunzip(blobs["payloads/kernel.gz"], reader.MAX_KERNEL)
    initrd = blobs["payloads/uImage_rootfs.bin"][64:]
    source_dtb = blobs["payloads/devicetree.dtb"]
    require(reader.sha(kernel) == "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6", "held kernel differs")
    require(reader.sha(source_dtb) == "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257", "held DTB differs")
    final_dtb, profile, dependencies = _dependencies()
    initrd_start = (0x07400000 - len(initrd)) & ~4095
    require(len(initrd) <= 32 * 1024 * 1024 and FDT_ADDRESS + 0x9000 <= initrd_start, "NoPIC payload placement differs")
    return kernel, initrd, final_dtb(source_dtb, initrd_start, initrd_start + len(initrd)), initrd_start, profile, dependencies, report


def _profile(template, descriptor, target):
    start = template.index(b"profile={\n") + len(b"profile={\n")
    stop = template.index(b"},\n", start) + 1
    require(template[start:stop].startswith(b"{0x44,0xf1,0xe6,0x3f,"), "previous descriptor initializer differs")
    initializer = ("{" + ",".join("0x%02x" % byte for byte in hashlib.sha256(descriptor).digest()) + "}").encode()
    result = template[:start] + initializer + template[stop:]
    first_line = result.index(b"\n")
    return ("/* Exact " + target + " native21 descriptor and source-identical held resident; unsigned. */\n").encode() + result[first_line + 1:]


def compose(candidate, boot_source, target):
    kernel, initrd, dtb, initrd_start, template, dependencies, report = _inputs(candidate, boot_source, target)
    descriptor = struct.pack("<8sII8Q", b"DCE2CL01", 1, 256, KERNEL_ADDRESS, len(kernel), 0x00f2b000,
                             initrd_start, len(initrd), FDT_ADDRESS, len(dtb), 0x10000000)
    descriptor += b"".join(hashlib.sha256(value).digest() for value in (kernel, initrd, dtb, BOOTARGS, candidate)) + bytes(16)
    require(len(descriptor) == 256, "descriptor size differs")
    files = {"Image": kernel, "initrd.gz": initrd, "final.dtb": dtb, "descriptor.bin": descriptor,
             "entry-profile.h": _profile(template, descriptor, target)}
    manifest = {"schema": SCHEMA, "board_target": target, "platform": report["platform"],
                "candidate": reader.pin(candidate), "boot_source_archive": reader.pin(boot_source),
                "descriptor_abi": ABI, "files": {name: reader.pin(raw) for name, raw in files.items()},
                "dependencies": dependencies, "prerequisites": PREREQUISITES, "authority": AUTHORITY}
    return files, manifest


def inspect(directory, candidate, boot_source, target):
    directory = reader._plain_path(directory)
    require(directory.is_dir() and {path.name for path in directory.iterdir()} == FILES | {"ENTRY_DATA.json"}, "complete NoPIC entry data directory required")
    manifest = reader.object_json(reader.regular_bytes(directory / "ENTRY_DATA.json", 65536))
    require(set(manifest) == {"schema", "board_target", "platform", "candidate", "boot_source_archive", "descriptor_abi",
                              "files", "dependencies", "prerequisites", "authority"}, "entry manifest fields differ")
    require(manifest["schema"] == SCHEMA and manifest["board_target"] == target and manifest["descriptor_abi"] == ABI,
            "NoPIC data identity differs")
    require(manifest["authority"] == AUTHORITY and manifest["prerequisites"] == PREREQUISITES, "entry authority/prerequisites differ")
    kernel, initrd, dtb, start, template, dependencies, report = _inputs(candidate, boot_source, target)
    require(manifest["candidate"] == reader.pin(candidate) and manifest["boot_source_archive"] == reader.pin(boot_source)
            and manifest["platform"] == report["platform"] and manifest["dependencies"] == dependencies, "entry source binding differs")
    files = {name: reader.regular_bytes(directory / name) for name in FILES}
    require(manifest["files"] == {name: reader.pin(raw) for name, raw in files.items()}, "entry file digest differs")
    require(files["Image"] == kernel and files["initrd.gz"] == initrd and files["final.dtb"] == dtb, "actual source payload differs")
    descriptor = files["descriptor.bin"]
    require(len(descriptor) == 256 and struct.unpack_from("<8sII8Q", descriptor) ==
            (b"DCE2CL01", 1, 256, KERNEL_ADDRESS, len(kernel), 0x00f2b000, start, len(initrd), FDT_ADDRESS, len(dtb), 0x10000000),
            "descriptor geometry differs")
    for offset, raw in ((80, kernel), (112, initrd), (144, dtb), (176, BOOTARGS), (208, candidate)):
        require(descriptor[offset:offset + 32] == hashlib.sha256(raw).digest(), "descriptor content/candidate hash differs")
    require(descriptor[240:] == bytes(16), "descriptor reserved bytes differ")
    require(files["entry-profile.h"] == _profile(template, descriptor, target), "compiled target descriptor profile differs")
    return {"status": "local_nopic_entry_data_verified", "board_target": target, "candidate": reader.pin(candidate),
            "descriptor": reader.pin(descriptor), "files": manifest["files"], "initrd_address": start,
            "descriptor_abi": ABI, "prerequisites": PREREQUISITES, **AUTHORITY}


def prepare(candidate_path, boot_source_path, target, output):
    candidate = reader.regular_bytes(candidate_path)
    boot_source = reader.regular_bytes(boot_source_path, reader.MAX_SOURCE)
    files, manifest = compose(candidate, boot_source, target)
    output = reader._plain_path(output)
    try:
        output.mkdir(mode=0o700)
    except OSError as error:
        raise ValueError("new NoPIC entry output directory required") from error
    for name, raw in files.items():
        reader._write_new(output / name, raw)
        require(reader.regular_bytes(output / name) == raw, "entry file readback differs")
    reader._write_new(output / "ENTRY_DATA.json", reader.canonical(manifest))
    result = inspect(output, candidate, boot_source, target)
    require(reader.regular_bytes(candidate_path) == candidate and reader.regular_bytes(boot_source_path, reader.MAX_SOURCE) == boot_source,
            "entry source inputs changed")
    reader._sync_directory(output)
    reader._sync_directory(output.parent)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", choices=tuple(BOOT_SOURCES), required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--boot-source-tar", type=Path, required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output", type=Path)
    action.add_argument("--inspect", type=Path)
    args = parser.parse_args()
    try:
        if args.inspect:
            result = inspect(args.inspect, reader.regular_bytes(args.candidate),
                             reader.regular_bytes(args.boot_source_tar, reader.MAX_SOURCE), args.target)
        else:
            result = prepare(args.candidate, args.boot_source_tar, args.target, args.output)
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
