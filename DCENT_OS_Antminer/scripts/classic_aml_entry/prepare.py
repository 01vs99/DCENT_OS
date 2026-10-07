#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 D-Central Technologies <dev@d-central.tech>
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare source-bound Classic direct-entry data for local implementation review.

This emits regular data files, not a device command or an executable entry.
Support this project: https://d-central.tech/fund/
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "projects/dcent-toolbox/src"))
from dcent_toolbox.core import classic_aml_candidate as reader  # noqa: E402

BOOTARGS = b"console=ttyAML0,115200n8 rdinit=/init\0"
KERNEL_ADDRESS = 0x01080000
FDT_ADDRESS = 0x056A2000
INITRD_HIGH = 0x07400000
DESCRIPTOR_ADDRESS = 0x07810000
KERNEL_SHA = "d5013ac9f545df3b0792ea2cd8902b51e323bbb6f73ff0fea17bbee9f6157fe6"
FDT_SHA = "540c1770543d9620e106ea4287c2a534f5efd85c912e97d6be6295930506b257"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def final_dtb(source, ram_start, ram_end):
    require(pin(source)["sha256"] == FDT_SHA, "kernel DTB source differs")
    nodes, _ = reader.parse_fdt(source)
    nodes = {path: dict(properties) for path, properties in nodes.items()}
    require("/chosen" not in nodes, "unexpected chosen source")
    require(nodes["/"]["#address-cells"] == struct.pack(">I", 2), "root address width differs")
    require(nodes["/"]["#size-cells"] == struct.pack(">I", 2), "root size width differs")
    nodes["/memory"]["reg"] = struct.pack(">QQ", 0, 0x10000000)
    nodes["/chosen"] = {"bootargs": BOOTARGS, "linux,initrd-start": struct.pack(">Q", ram_start),
                        "linux,initrd-end": struct.pack(">Q", ram_end)}
    strings = bytearray()
    offsets = {}
    for properties in nodes.values():
        for name in properties:
            if name not in offsets:
                offsets[name] = len(strings)
                strings.extend(name.encode("ascii") + b"\0")
    structure = bytearray()
    def emit(path):
        name = "" if path == "/" else path.rsplit("/", 1)[1]
        structure.extend(struct.pack(">I", 1) + name.encode("ascii") + b"\0")
        structure.extend(bytes(-len(structure) % 4))
        for name, value in nodes[path].items():
            structure.extend(struct.pack(">III", 3, len(value), offsets[name]) + value)
            structure.extend(bytes(-len(structure) % 4))
        for child in nodes:
            if child != "/" and (child.rsplit("/", 1)[0] or "/") == path:
                emit(child)
        structure.extend(struct.pack(">I", 2))
    emit("/")
    structure.extend(struct.pack(">I", 9))
    # Original OSprep reserves its own final DTB allocation as well as initrd.
    # The compact serialization needs exactly six pages for this pinned DTB.
    struct_offset = 40 + 48
    string_offset = struct_offset + len(structure)
    total = string_offset + len(strings)
    allocated = (total + 4095) & ~4095
    require(FDT_ADDRESS + allocated <= ram_start, "DTB allocation overlaps initrd")
    reservations = struct.pack(">6Q", FDT_ADDRESS, allocated, ram_start, ram_end - ram_start, 0, 0)
    boot_cpuid = struct.unpack_from(">I", source, 28)[0]
    header = struct.pack(">10I", 0xD00DFEED, total, struct_offset, string_offset, 40, 17, 16,
                         boot_cpuid, len(strings), len(structure))
    return header + reservations + structure + strings


def compose(raw):
    inspected = reader.inspect_bytes(raw)
    blobs = reader.archive_members(raw)
    container = reader.decode_container(blobs["aml_boot_package.enc"])
    nodes, _ = reader.parse_fdt(container[reader.FIT_OFFSET:])
    kernel = reader.gunzip(nodes["/images/kernel"]["data"], 32 * 1024 * 1024)
    source_fdt = nodes["/images/fdt"]["data"]
    initrd = nodes["/images/ramdisk"]["data"]
    require(pin(kernel)["sha256"] == KERNEL_SHA, "Image source differs")
    text_offset, image_size, flags = struct.unpack_from("<QQQ", kernel, 8)
    require((text_offset, image_size, flags, kernel[56:60]) ==
            (KERNEL_ADDRESS, 0xF2B000, 0xA, b"ARM\x64"), "Image effective extent/header differs")
    require(len(kernel) <= image_size and KERNEL_ADDRESS + image_size <= 0x02200000,
            "effective kernel extent overlaps loader")
    ram_start = (INITRD_HIGH - len(initrd)) & ~4095
    ram_end = ram_start + len(initrd)
    dtb = final_dtb(source_fdt, ram_start, ram_end)
    require(FDT_ADDRESS + len(dtb) <= ram_start and FDT_ADDRESS >= 0x05400000,
            "final DTB overlaps initrd or secure memory")
    require(len(dtb) <= 0x9000 and ram_end <= INITRD_HIGH, "final payload bound")
    descriptor = struct.pack("<8sII8Q", b"DCE2CL01", 1, 256,
        KERNEL_ADDRESS, len(kernel), image_size, ram_start, len(initrd), FDT_ADDRESS, len(dtb), 0x10000000)
    descriptor += b"".join(hashlib.sha256(item).digest() for item in (kernel, initrd, dtb, BOOTARGS, raw)) + bytes(16)
    require(len(descriptor) == 256, "descriptor layout differs")
    files = {"Image": kernel, "initrd.gz": initrd, "final.dtb": dtb, "descriptor.bin": descriptor}
    manifest = {"schema": "dcentos.classic_aml_direct_entry_data.v1", "board_target": reader.TARGET,
        "status": "local_entry_data_prepared_dma_and_executable_review_pending", "candidate": pin(raw),
        "candidate_runtime": inspected["runtime"], "source_kernel_dtb": pin(source_fdt),
        "members": {name: pin(data) for name, data in files.items()},
        "addresses": {"Image": KERNEL_ADDRESS, "initrd.gz": ram_start, "final.dtb": FDT_ADDRESS,
                      "descriptor.bin": DESCRIPTOR_ADDRESS},
        "kernel_file_span": [KERNEL_ADDRESS, KERNEL_ADDRESS + len(kernel)],
        "kernel_effective_span": [KERNEL_ADDRESS, KERNEL_ADDRESS + image_size],
        "reserved_spans": {"secmon": [0x05000000, 0x05400000], "ramoops": [0x07400000, 0x07500000],
                           "entry_descriptor_stack": [0x07800000, 0x07822000]},
        "bootargs": BOOTARGS[:-1].decode(), "resident_environment_dependency": False,
        "descriptor_authenticated_by_release_signature": False, "signature": None,
        "dma_quiescence_proven": False, "executable_entry": False, "physical_readiness": False,
        "hardware_contact": False, "persistent_install_authorized": False, "publication": False}
    files["ENTRY_DATA.json"] = canonical(manifest)
    return files, manifest


def prepare(candidate, expected_sha256, output):
    raw = reader.regular_bytes(candidate)
    require(pin(raw)["sha256"] == expected_sha256, "candidate archive digest differs")
    files, manifest = compose(raw)
    output = reader._plain_path(output)
    output.mkdir()  # Create-only; an incomplete existing directory is evidence.
    for name, content in files.items():
        reader._write_new(output / name, content)
        require(reader.regular_bytes(output / name) == content, "written data differs: " + name)
    reader._sync_directory(output)
    reader._sync_directory(output.parent)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    result = prepare(arguments.candidate, arguments.expected_sha256, arguments.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
