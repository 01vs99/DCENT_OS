#!/usr/bin/env python3
"""Admit the exact held AM2 S17 Braiins donor and its UBI boot FIT.

This is an offline, no-device helper.  It deliberately distinguishes the
stock Bitmain raw-MTD update kernel from the kernel contract used by the
Braiins/DCENT AM2 A/B UBI boot chain:

* the exact held Braiins SD image supplies the model-bound S17 kernel + DTB;
* its U-Boot environment proves 95 MiB ``firmware1``/``firmware2`` slots,
  mtd7/mtd8 selection, ``ubi read ... kernel``, and ``bootm``;
* the extracted kernel is the exact UBI/ubiblock/SquashFS/generic-UIO kernel
  used by that donor; and
* a caller-built kernel+DTB/no-ramdisk FIT must fit the canonical 23-LEB
  inactive ``kernel`` volume before it can be packaged.

The helper never contacts a miner and never authorizes a flash.  Manufacturer
or hardware boot provenance is not inferred beyond the exact pinned donor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
from typing import Dict, NoReturn, Optional, Tuple
import zlib


SCHEMA = "org.dcentral.dcentos.am2-s17-ubi-boot-admission.v1"

DONOR_SIZE = 112_197_632
DONOR_SHA256 = "b0444ad2a5e9b9e2b021ec756a40cb1448128545a42c77bdabb4363617d03579"
MAX_DONOR_BYTES = 128 * 1024 * 1024

SOURCE_FIT_SIZE = 27_387_008
SOURCE_FIT_SHA256 = "e3e0f8ae80175235aef1d9b210f4345da3723a6fe472e491f91ffc561aaf4d67"
SOURCE_FIT_TIMESTAMP = 1_740_171_698

OUTPUT_FIT_DESCRIPTION = "DCENT_OS S17 model-bound UBI kernel FIT"
OUTPUT_KERNEL_DESCRIPTION = "DCENT_OS S17 UBI kernel"
OUTPUT_DTB_DESCRIPTION = "Antminer S17 model-bound device tree"
OUTPUT_CONFIG_DESCRIPTION = "DCENT_OS S17 kernel plus exact S17 DTB"
OUTPUT_FIT_SIZE = 2_845_580
OUTPUT_FIT_SHA256 = "3e0cebd3f0461722b3f9e21b84e0700d215e9a928459a951660849547aff5749"

KERNEL_SIZE = 2_827_744
KERNEL_SHA256 = "205b9fb13cae3152e2d8ac94f34fd6105aa0260cf9229abe2bc14f86512a24c1"
KERNEL_XZ_OFFSET = 0x3720
VMLINUX_SIZE = 8_073_888
VMLINUX_SHA256 = "170bc5cfeb170ef4837f5f67e0ffea4330033c4cb7984528dc1637af8da39b04"

DTB_SIZE = 16_454
DTB_SHA256 = "51f4d224271b0e2bd4c1bf4f62f88373f50caaa5f184571817f32fa30841ff3b"
DTB_MODEL = "Antminer S17 Miner Control Board"

UBOOT_IMAGE_SIZE = 572_780
UBOOT_IMAGE_SHA256 = "af8a04e7b108f545eb029f97fb810296e05257425dae93657e5c9d6fa5868f6d"
UENV_SIZE = 1_113
UENV_SHA256 = "6b6a77d88525bec3872436357ffa840e8e371ce2d3f63a85281a8f2b17a22435"

UBI_LEB_SIZE = 126_976
UBI_KERNEL_LEBS = 23
UBI_KERNEL_CAPACITY = UBI_LEB_SIZE * UBI_KERNEL_LEBS

_MBR_PARTITIONS = (
    (0x80, 0x0C, 2_048, 81_920),
    (0x00, 0x83, 83_968, 131_072),
    (0x00, 0xBB, 215_040, 4_096),
    (0x00, 0x00, 0, 0),
)

_FAT_FILES = {
    "BOOT.BIN": (
        78_039,
        "60a60746f4c92d5493bfb6af36c02e3ac9574c46d5718bcb70106563b8e6c654",
    ),
    "FIT.ITB": (SOURCE_FIT_SIZE, SOURCE_FIT_SHA256),
    "MINER.BTM": (
        2_048,
        "a5443fbfebd548332e31e23576bdd62e5c6607724ed344d9b36d76a0e0a017ce",
    ),
    "MINER.BTM.SIG": (
        256,
        "4e81c666b82a0096fff729b32e0bb93a47efc3d21cbc3bf6e3162ecd313d0533",
    ),
    "SYSTEM.BIT.GZ": (
        259_234,
        "7102a9f204a4be3edfbf2096f68e6a9b24b1a2845c8257e29563ce459a597c8b",
    ),
    "SYSTEM_BM.BIT.GZ": (
        365_657,
        "e2454a146c196b15bd59b59a1321a289109afefc80f7e7e587ef0e6c96ff5897",
    ),
    "U-BOOT.IMG": (UBOOT_IMAGE_SIZE, UBOOT_IMAGE_SHA256),
    "UENV.TXT": (UENV_SIZE, UENV_SHA256),
}

_REQUIRED_UBOOT_ENV_FRAGMENTS = (
    b"firmware_select=if test x${firmware} = x1; then setenv bitstream fpga1 && setenv firmware_name firmware1 && setenv firmware_mtd 7; else setenv bitstream fpga2 && setenv firmware_name firmware2 && setenv firmware_mtd 8; fi",
    b"auto_recovery=if test x${upgrade_stage} = x0; then echo Trying to boot system after upgrade...",
    b"ubi part ${firmware_name} && ubi read ${load_addr} kernel",
    b"bootm ${load_addr}",
    b"mtdparts=pl35x-nand:512k(boot),2560k(uboot),2m(fpga1),2m(fpga2),512k(uboot_env),512k(miner_cfg),22m(recovery),95m(firmware1),95m(firmware2),36m(factory)",
)

_REQUIRED_VMLINUX_EVIDENCE = (
    b"Linux version 4.4.0-xilinx",
    b"ubiblock",
    b"Squashfs",
    b"UBIFS",
    b"generic-uio",
    b"pl35x-nand",
)

_REQUIRED_DTB_UIO_NODES = (
    "/amba_pl/chain1-common",
    "/amba_pl/chain1-cmd-rx",
    "/amba_pl/chain1-work-rx",
    "/amba_pl/chain1-work-tx",
    "/amba_pl/fan-control",
    "/amba_pl/board-control",
)


class AdmissionError(ValueError):
    """The input does not satisfy the exact held-donor contract."""


def fail(message: str) -> NoReturn:
    raise AdmissionError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"{label} must be a regular non-symlink file")
    if metadata.st_nlink != 1:
        fail(f"{label} must not have hard-link aliases")
    if metadata.st_size > maximum:
        fail(f"{label} exceeds {maximum} bytes")
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    if len(value) != metadata.st_size or len(value) > maximum:
        fail(f"{label} changed while being read or exceeded its limit")
    return value


def _validate_mbr(raw: bytes) -> None:
    if raw[510:512] != b"\x55\xaa":
        fail("S17 donor MBR signature is invalid")
    for index, expected in enumerate(_MBR_PARTITIONS):
        offset = 446 + index * 16
        status, _chs1, kind, _chs2, lba, sectors = struct.unpack_from(
            "<B3sB3sII", raw, offset
        )
        if (status, kind, lba, sectors) != expected:
            fail(f"S17 donor MBR partition {index + 1} does not match its pin")


def _fat16_files(raw: bytes) -> Dict[str, bytes]:
    partition_offset = _MBR_PARTITIONS[0][2] * 512
    partition_bytes = _MBR_PARTITIONS[0][3] * 512
    boot = raw[partition_offset : partition_offset + partition_bytes]
    if len(boot) != partition_bytes:
        fail("S17 donor FAT partition is truncated")

    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    sectors_per_cluster = boot[13]
    reserved = struct.unpack_from("<H", boot, 14)[0]
    fats = boot[16]
    root_entries = struct.unpack_from("<H", boot, 17)[0]
    total_sectors = struct.unpack_from("<I", boot, 32)[0]
    fat_sectors = struct.unpack_from("<H", boot, 22)[0]
    if (
        bytes_per_sector,
        sectors_per_cluster,
        reserved,
        fats,
        root_entries,
        total_sectors,
        fat_sectors,
        boot[54:62],
    ) != (512, 4, 4, 2, 512, 81_920, 80, b"FAT16   "):
        fail("S17 donor FAT16 geometry does not match its exact pin")

    fat_offset = reserved * bytes_per_sector
    fat = boot[fat_offset : fat_offset + fat_sectors * bytes_per_sector]
    root_offset = (reserved + fats * fat_sectors) * bytes_per_sector
    root_size = root_entries * 32
    data_offset = root_offset + root_size
    cluster_bytes = sectors_per_cluster * bytes_per_sector

    def cluster_chain(first: int) -> Tuple[int, ...]:
        result = []
        seen = set()
        cluster = first
        while 2 <= cluster < 0xFFF8:
            if cluster in seen or len(result) > 65_536:
                fail("S17 donor FAT16 cluster chain is cyclic or excessive")
            seen.add(cluster)
            result.append(cluster)
            entry = cluster * 2
            if entry + 2 > len(fat):
                fail("S17 donor FAT16 cluster index is out of range")
            cluster = struct.unpack_from("<H", fat, entry)[0]
        if cluster not in range(0xFFF8, 0x10000):
            fail("S17 donor FAT16 cluster chain has an invalid terminator")
        return tuple(result)

    values: Dict[str, bytes] = {}
    long_parts = []
    for offset in range(root_offset, root_offset + root_size, 32):
        entry = boot[offset : offset + 32]
        if len(entry) != 32 or entry[0] == 0:
            break
        if entry[0] == 0xE5:
            long_parts = []
            continue
        attributes = entry[11]
        if attributes == 0x0F:
            long_parts.append(entry[1:11] + entry[14:26] + entry[28:32])
            continue
        if attributes & 0x08:  # volume label
            long_parts = []
            continue
        short_stem = entry[:8].decode("ascii", "strict").rstrip()
        short_ext = entry[8:11].decode("ascii", "strict").rstrip()
        if long_parts:
            encoded = b"".join(reversed(long_parts))
            name = (
                encoded.decode("utf-16le", "strict").split("\0", 1)[0].rstrip("\uffff")
            )
            long_parts = []
        else:
            name = short_stem + (f".{short_ext}" if short_ext else "")
        pure = PurePosixPath(name)
        if pure.is_absolute() or len(pure.parts) != 1 or pure.name != name:
            fail(f"S17 donor FAT16 contains a non-canonical name: {name}")
        first_cluster = struct.unpack_from("<H", entry, 26)[0]
        size = struct.unpack_from("<I", entry, 28)[0]
        chunks = []
        for cluster in cluster_chain(first_cluster):
            start = data_offset + (cluster - 2) * cluster_bytes
            end = start + cluster_bytes
            if end > len(boot):
                fail(f"S17 donor FAT16 file exceeds its partition: {name}")
            chunks.append(boot[start:end])
        value = b"".join(chunks)[:size]
        if len(value) != size:
            fail(f"S17 donor FAT16 file is truncated: {name}")
        upper = name.upper()
        if upper in values:
            fail(f"S17 donor FAT16 contains a duplicate file: {name}")
        values[upper] = value

    if set(values) != set(_FAT_FILES):
        fail("S17 donor FAT16 file set does not match its exact pin")
    for name, (size, digest) in _FAT_FILES.items():
        value = values[name]
        if len(value) != size or sha256_bytes(value) != digest:
            fail(f"S17 donor FAT16 file hash/size mismatch: {name}")
    return values


def _fdt_properties(raw: bytes, label: str) -> Dict[str, Dict[str, bytes]]:
    if len(raw) < 40:
        fail(f"{label} is shorter than an FDT header")
    (
        magic,
        total_size,
        struct_offset,
        strings_offset,
        reserve_offset,
        version,
        last_compatible,
        _boot_cpu,
        strings_size,
        struct_size,
    ) = struct.unpack_from(">10I", raw, 0)
    if magic != 0xD00DFEED:
        fail(f"{label} does not carry FDT/FIT magic")
    if total_size != len(raw):
        fail(f"{label} has trailing or truncated bytes")
    if version != 17 or last_compatible > 16:
        fail(f"{label} uses an unsupported FDT version")
    if reserve_offset < 40:
        fail(f"{label} reserve map overlaps its header")
    if (
        struct_offset + struct_size > total_size
        or strings_offset + strings_size > total_size
    ):
        fail(f"{label} tables exceed the container")

    position = struct_offset
    strings = raw[strings_offset : strings_offset + strings_size]
    stack = []
    values: Dict[str, Dict[str, bytes]] = {}
    saw_end = False
    while position + 4 <= struct_offset + struct_size:
        token = struct.unpack_from(">I", raw, position)[0]
        position += 4
        if token == 1:  # FDT_BEGIN_NODE
            try:
                end = raw.index(0, position, struct_offset + struct_size)
            except ValueError:
                fail(f"{label} has an unterminated node name")
            name = raw[position:end].decode("ascii", "strict")
            if "/" in name:
                fail(f"{label} has a non-canonical node name")
            stack.append(name)
            position = (end + 4) & ~3
        elif token == 2:  # FDT_END_NODE
            if not stack:
                fail(f"{label} has an unmatched end-node token")
            stack.pop()
        elif token == 3:  # FDT_PROP
            if position + 8 > struct_offset + struct_size or not stack:
                fail(f"{label} has a malformed property")
            length, name_offset = struct.unpack_from(">II", raw, position)
            position += 8
            if position + length > struct_offset + struct_size or name_offset >= len(
                strings
            ):
                fail(f"{label} property exceeds its table")
            try:
                name_end = strings.index(0, name_offset)
            except ValueError:
                fail(f"{label} property name is unterminated")
            prop_name = strings[name_offset:name_end].decode("ascii", "strict")
            value = raw[position : position + length]
            position = (position + length + 3) & ~3
            path = "/" + "/".join(part for part in stack if part)
            node = values.setdefault(path or "/", {})
            if prop_name in node:
                fail(f"{label} has a duplicate property: {path}/{prop_name}")
            node[prop_name] = value
        elif token == 4:  # FDT_NOP
            continue
        elif token == 9:  # FDT_END
            if stack:
                fail(f"{label} ended with open nodes")
            saw_end = True
            break
        else:
            fail(f"{label} has an unknown structure token: {token}")
    if not saw_end:
        fail(f"{label} has no terminal FDT_END token")
    return values


def _cstring(value: bytes, label: str) -> str:
    if not value.endswith(b"\0") or b"\0" in value[:-1]:
        fail(f"{label} is not one canonical FDT string")
    try:
        return value[:-1].decode("ascii", "strict")
    except UnicodeDecodeError:
        fail(f"{label} is not ASCII")


def _be32(value: bytes, label: str) -> int:
    if len(value) != 4:
        fail(f"{label} is not one FDT cell")
    return struct.unpack(">I", value)[0]


def _require_prop(
    nodes: Dict[str, Dict[str, bytes]], path: str, name: str, label: str
) -> bytes:
    try:
        return nodes[path][name]
    except KeyError:
        fail(f"{label} is missing {path}/{name}")


def _validate_uboot(image: bytes) -> dict:
    if len(image) != UBOOT_IMAGE_SIZE or sha256_bytes(image) != UBOOT_IMAGE_SHA256:
        fail("S17 donor U-Boot image does not match its pin")
    if len(image) < 64:
        fail("S17 donor U-Boot image is truncated")
    fields = struct.unpack(">7I4B32s", image[:64])
    magic, header_crc, timestamp, data_size, load, entry, data_crc = fields[:7]
    os_id, arch, image_type, compression, raw_name = fields[7:]
    header = bytearray(image[:64])
    header[4:8] = b"\0\0\0\0"
    payload = image[64:]
    if (
        magic != 0x27051956
        or zlib.crc32(header) & 0xFFFFFFFF != header_crc
        or data_size != len(payload)
        or zlib.crc32(payload) & 0xFFFFFFFF != data_crc
    ):
        fail("S17 donor U-Boot legacy-image CRC/size is invalid")
    if (os_id, arch, image_type, compression, load, entry) != (
        17,
        2,
        5,
        0,
        0x04000000,
        0x04000000,
    ):
        fail("S17 donor U-Boot legacy-image metadata is unexpected")
    name = raw_name.rstrip(b"\0").decode("ascii", "strict")
    if name != "U-Boot 2016.03 for zynq board":
        fail("S17 donor U-Boot image name is unexpected")
    for fragment in _REQUIRED_UBOOT_ENV_FRAGMENTS:
        if fragment not in payload:
            fail("S17 donor U-Boot is missing its pinned AM2 A/B boot contract")
    return {
        "sha256": UBOOT_IMAGE_SHA256,
        "size": UBOOT_IMAGE_SIZE,
        "name": name,
        "load": load,
        "entry": entry,
        "firmware_slots": {"1": "mtd7/firmware1", "2": "mtd8/firmware2"},
        "firmware_slot_bytes": 95 * 1024 * 1024,
        "kernel_boot": "ubi part <firmware>; ubi read <addr> kernel; bootm <addr>",
        "automatic_revert": "firmware+upgrade_stage",
    }


def _validate_kernel(kernel: bytes) -> dict:
    if len(kernel) != KERNEL_SIZE or sha256_bytes(kernel) != KERNEL_SHA256:
        fail("S17 donor kernel does not match its exact pin")
    if len(kernel) < 0x30 or struct.unpack_from("<I", kernel, 0x24)[0] != 0x016F2818:
        fail("S17 donor kernel is not an ARM zImage")
    if struct.unpack_from("<I", kernel, 0x28)[0] != 0:
        fail("S17 donor zImage start field is unexpected")
    if struct.unpack_from("<I", kernel, 0x2C)[0] != len(kernel):
        fail("S17 donor zImage end/size field is invalid")
    if kernel[KERNEL_XZ_OFFSET : KERNEL_XZ_OFFSET + 6] != b"\xfd7zXZ\x00":
        fail("S17 donor kernel XZ payload is not at its pinned offset")
    try:
        vmlinux = lzma.decompress(kernel[KERNEL_XZ_OFFSET:], format=lzma.FORMAT_XZ)
    except lzma.LZMAError as error:
        fail(f"S17 donor kernel XZ payload is invalid: {error}")
    if len(vmlinux) != VMLINUX_SIZE or sha256_bytes(vmlinux) != VMLINUX_SHA256:
        fail("S17 donor decompressed kernel does not match its exact pin")
    missing = [
        item.decode("ascii")
        for item in _REQUIRED_VMLINUX_EVIDENCE
        if item not in vmlinux
    ]
    if missing:
        fail(
            f"S17 donor kernel lacks required UBI runtime evidence: {', '.join(missing)}"
        )
    return {
        "sha256": KERNEL_SHA256,
        "size": KERNEL_SIZE,
        "format": "arm-zimage-xz",
        "load": 0x8000,
        "entry": 0x8000,
        "vmlinux_sha256": VMLINUX_SHA256,
        "vmlinux_size": VMLINUX_SIZE,
        "runtime_evidence": [
            item.decode("ascii") for item in _REQUIRED_VMLINUX_EVIDENCE
        ],
    }


def _validate_dtb(dtb: bytes) -> dict:
    if len(dtb) != DTB_SIZE or sha256_bytes(dtb) != DTB_SHA256:
        fail("S17 donor DTB does not match its exact pin")
    nodes = _fdt_properties(dtb, "S17 donor DTB")
    model = _cstring(_require_prop(nodes, "/", "model", "S17 donor DTB"), "DTB model")
    if model != DTB_MODEL:
        fail(f"S17 donor DTB model mismatch: {model}")
    compatible = (
        _require_prop(nodes, "/", "compatible", "S17 donor DTB")
        .rstrip(b"\0")
        .split(b"\0")
    )
    if b"xlnx,zynq-7000" not in compatible:
        fail("S17 donor DTB is not bound to Xilinx Zynq-7000")
    for path in _REQUIRED_DTB_UIO_NODES:
        value = _require_prop(nodes, path, "compatible", "S17 donor DTB")
        if value != b"generic-uio\0":
            fail(f"S17 donor DTB UIO binding mismatch: {path}")
    return {
        "sha256": DTB_SHA256,
        "size": DTB_SIZE,
        "model": model,
        "compatible": [item.decode("ascii") for item in compatible],
        "required_uio_nodes": list(_REQUIRED_DTB_UIO_NODES),
    }


def _validate_source_fit(source_fit: bytes) -> Tuple[bytes, bytes, dict]:
    if (
        len(source_fit) != SOURCE_FIT_SIZE
        or sha256_bytes(source_fit) != SOURCE_FIT_SHA256
    ):
        fail("S17 donor source FIT does not match its exact pin")
    nodes = _fdt_properties(source_fit, "S17 donor source FIT")
    if (
        _be32(_require_prop(nodes, "/", "timestamp", "source FIT"), "FIT timestamp")
        != SOURCE_FIT_TIMESTAMP
    ):
        fail("S17 donor source FIT timestamp is unexpected")
    if (
        _cstring(
            _require_prop(nodes, "/configurations", "default", "source FIT"),
            "source FIT default configuration",
        )
        != "config@1"
    ):
        fail("S17 donor source FIT default configuration is unexpected")
    config = nodes.get("/configurations/config@1", {})
    expected_config = {"kernel": "kernel@1", "ramdisk": "ramdisk@1", "fdt": "fdt@1"}
    for name, expected in expected_config.items():
        if _cstring(config.get(name, b""), f"source FIT config {name}") != expected:
            fail(f"S17 donor source FIT config does not bind {name} to {expected}")

    kernel_node = "/images/kernel@1"
    dtb_node = "/images/fdt@1"
    kernel = _require_prop(nodes, kernel_node, "data", "source FIT")
    dtb = _require_prop(nodes, dtb_node, "data", "source FIT")
    for path, kind in ((kernel_node, "kernel"), (dtb_node, "flat_dt")):
        if (
            _cstring(_require_prop(nodes, path, "type", "source FIT"), "FIT image type")
            != kind
        ):
            fail(f"S17 donor source FIT {path} type mismatch")
        if (
            _cstring(_require_prop(nodes, path, "arch", "source FIT"), "FIT image arch")
            != "arm"
        ):
            fail(f"S17 donor source FIT {path} architecture mismatch")
        if (
            _cstring(
                _require_prop(nodes, path, "compression", "source FIT"),
                "FIT compression",
            )
            != "none"
        ):
            fail(f"S17 donor source FIT {path} compression mismatch")
    if (
        _cstring(_require_prop(nodes, kernel_node, "os", "source FIT"), "FIT kernel OS")
        != "linux"
    ):
        fail("S17 donor source FIT kernel OS mismatch")
    if (
        _be32(
            _require_prop(nodes, kernel_node, "load", "source FIT"), "FIT kernel load"
        ),
        _be32(
            _require_prop(nodes, kernel_node, "entry", "source FIT"), "FIT kernel entry"
        ),
    ) != (0x8000, 0x8000):
        fail("S17 donor source FIT kernel load/entry mismatch")

    kernel_receipt = _validate_kernel(kernel)
    dtb_receipt = _validate_dtb(dtb)
    return (
        kernel,
        dtb,
        {
            "sha256": SOURCE_FIT_SHA256,
            "size": SOURCE_FIT_SIZE,
            "timestamp": SOURCE_FIT_TIMESTAMP,
            "source_configuration": expected_config,
            "kernel": kernel_receipt,
            "dtb": dtb_receipt,
        },
    )


def admit_donor(path: Path) -> Tuple[bytes, bytes, dict]:
    raw = _read_regular(path, MAX_DONOR_BYTES, "S17 Braiins SD donor")
    if len(raw) != DONOR_SIZE or sha256_bytes(raw) != DONOR_SHA256:
        fail("S17 Braiins SD donor size/SHA256 does not match its exact pin")
    _validate_mbr(raw)
    files = _fat16_files(raw)
    uboot = _validate_uboot(files["U-BOOT.IMG"])
    if sha256_bytes(files["UENV.TXT"]) != UENV_SHA256:
        fail("S17 donor uEnv.txt does not match its pin")
    kernel, dtb, source_fit = _validate_source_fit(files["FIT.ITB"])
    receipt = {
        "schema": SCHEMA,
        "donor": {
            "path": path.name,
            "size": DONOR_SIZE,
            "sha256": DONOR_SHA256,
            "identity": "exact-held-braiins-am2-s17-sd-image",
        },
        "mbr": {
            "sector_size": 512,
            "partitions": [
                {
                    "boot": item[0],
                    "type": item[1],
                    "start_lba": item[2],
                    "sectors": item[3],
                }
                for item in _MBR_PARTITIONS
            ],
        },
        "uboot": uboot,
        "uenv": {"size": UENV_SIZE, "sha256": UENV_SHA256},
        "source_fit": source_fit,
        "geometry": {
            "kernel_volume_lebs": UBI_KERNEL_LEBS,
            "usable_leb_size": UBI_LEB_SIZE,
            "kernel_capacity_bytes": UBI_KERNEL_CAPACITY,
            "source_kind": "canonical-am2-inactive-volume-contract",
        },
        "authorization": {
            "host_artifact_extract": True,
            "experimental_fit_build": True,
            "device_contact": False,
            "stock_first_install": False,
            "flash": False,
            "cold_boot_proof": False,
            "mining_proof": False,
        },
    }
    return kernel, dtb, receipt


def verify_ubi_fit(path: Path) -> dict:
    raw = _read_regular(path, UBI_KERNEL_CAPACITY, "S17 UBI kernel FIT")
    if len(raw) != OUTPUT_FIT_SIZE or sha256_bytes(raw) != OUTPUT_FIT_SHA256:
        fail("S17 UBI kernel FIT size/SHA256 does not match its reproducible pin")
    nodes = _fdt_properties(raw, "S17 UBI kernel FIT")
    if len(raw) > UBI_KERNEL_CAPACITY:
        fail(
            f"S17 UBI kernel FIT exceeds {UBI_KERNEL_LEBS} LEBs: "
            f"{len(raw)} > {UBI_KERNEL_CAPACITY}"
        )
    if any(path.startswith("/images/ramdisk") for path in nodes):
        fail("S17 UBI kernel FIT must not contain a ramdisk")
    expected_fields = {
        "/": {"description", "#address-cells", "timestamp"},
        "/images/kernel@1": {
            "description",
            "data",
            "type",
            "arch",
            "os",
            "compression",
            "load",
            "entry",
        },
        "/images/kernel@1/hash@1": {"algo", "value"},
        "/images/kernel@1/hash@2": {"algo", "value"},
        "/images/fdt@1": {"description", "data", "type", "arch", "compression"},
        "/images/fdt@1/hash@1": {"algo", "value"},
        "/images/fdt@1/hash@2": {"algo", "value"},
        "/configurations": {"default"},
        "/configurations/config@1": {"description", "kernel", "fdt"},
    }
    if set(nodes) != set(expected_fields):
        fail("S17 UBI kernel FIT contains unexpected or missing property-bearing nodes")
    for node_path, fields in expected_fields.items():
        if set(nodes[node_path]) != fields:
            fail(f"S17 UBI kernel FIT property set mismatch: {node_path}")
    if (
        _cstring(nodes["/"]["description"], "S17 UBI FIT description")
        != OUTPUT_FIT_DESCRIPTION
    ):
        fail("S17 UBI kernel FIT top-level description mismatch")
    if _be32(nodes["/"]["#address-cells"], "S17 UBI FIT address cells") != 1:
        fail("S17 UBI kernel FIT address-cell contract mismatch")
    if _be32(nodes["/"]["timestamp"], "S17 UBI FIT timestamp") != SOURCE_FIT_TIMESTAMP:
        fail("S17 UBI kernel FIT timestamp is not bound to the exact donor FIT")
    if (
        _cstring(
            _require_prop(nodes, "/configurations", "default", "S17 UBI kernel FIT"),
            "S17 UBI FIT default",
        )
        != "config@1"
    ):
        fail("S17 UBI kernel FIT default configuration must be config@1")
    config = nodes.get("/configurations/config@1", {})
    if set(config) != {"description", "kernel", "fdt"}:
        fail("S17 UBI kernel FIT configuration contains unexpected or missing fields")
    if (
        _cstring(config["description"], "S17 UBI FIT config description")
        != OUTPUT_CONFIG_DESCRIPTION
    ):
        fail("S17 UBI kernel FIT configuration description mismatch")
    if _cstring(config["kernel"], "S17 UBI FIT kernel reference") != "kernel@1":
        fail("S17 UBI kernel FIT configuration selects the wrong kernel")
    if _cstring(config["fdt"], "S17 UBI FIT DTB reference") != "fdt@1":
        fail("S17 UBI kernel FIT configuration selects the wrong DTB")

    kernel_path = "/images/kernel@1"
    dtb_path = "/images/fdt@1"
    kernel = _require_prop(nodes, kernel_path, "data", "S17 UBI kernel FIT")
    dtb = _require_prop(nodes, dtb_path, "data", "S17 UBI kernel FIT")
    _validate_kernel(kernel)
    dtb_receipt = _validate_dtb(dtb)
    for image_path, expected_type, expected_description in (
        (kernel_path, "kernel", OUTPUT_KERNEL_DESCRIPTION),
        (dtb_path, "flat_dt", OUTPUT_DTB_DESCRIPTION),
    ):
        node = nodes.get(image_path, {})
        if (
            _cstring(node.get("description", b""), "S17 UBI FIT description")
            != expected_description
        ):
            fail(f"S17 UBI kernel FIT description mismatch: {image_path}")
        if _cstring(node.get("type", b""), "S17 UBI FIT type") != expected_type:
            fail(f"S17 UBI kernel FIT type mismatch: {image_path}")
        if _cstring(node.get("arch", b""), "S17 UBI FIT arch") != "arm":
            fail(f"S17 UBI kernel FIT architecture mismatch: {image_path}")
        if _cstring(node.get("compression", b""), "S17 UBI FIT compression") != "none":
            fail(f"S17 UBI kernel FIT compression mismatch: {image_path}")
    kernel_node = nodes[kernel_path]
    if _cstring(kernel_node.get("os", b""), "S17 UBI FIT OS") != "linux":
        fail("S17 UBI kernel FIT OS mismatch")
    if (
        _be32(kernel_node.get("load", b""), "S17 UBI FIT load"),
        _be32(kernel_node.get("entry", b""), "S17 UBI FIT entry"),
    ) != (0x8000, 0x8000):
        fail("S17 UBI kernel FIT load/entry mismatch")

    for image_path, payload in ((kernel_path, kernel), (dtb_path, dtb)):
        crc = _require_prop(
            nodes, f"{image_path}/hash@1", "value", "S17 UBI kernel FIT"
        )
        sha1 = _require_prop(
            nodes, f"{image_path}/hash@2", "value", "S17 UBI kernel FIT"
        )
        if _cstring(
            _require_prop(nodes, f"{image_path}/hash@1", "algo", "S17 UBI kernel FIT"),
            "FIT CRC algorithm",
        ) != "crc32" or crc != struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF):
            fail(f"S17 UBI kernel FIT CRC32 mismatch: {image_path}")
        if (
            _cstring(
                _require_prop(
                    nodes, f"{image_path}/hash@2", "algo", "S17 UBI kernel FIT"
                ),
                "FIT SHA-1 algorithm",
            )
            != "sha1"
            or sha1 != hashlib.sha1(payload).digest()
        ):
            fail(f"S17 UBI kernel FIT SHA-1 mismatch: {image_path}")

    return {
        "schema": SCHEMA,
        "fit": {
            "size": len(raw),
            "sha256": sha256_bytes(raw),
            "format": "fit-kernel-plus-model-bound-dtb-no-ramdisk",
            "kernel_sha256": KERNEL_SHA256,
            "dtb_sha256": DTB_SHA256,
            "dtb_model": dtb_receipt["model"],
        },
        "geometry": {
            "kernel_volume_lebs": UBI_KERNEL_LEBS,
            "usable_leb_size": UBI_LEB_SIZE,
            "kernel_capacity_bytes": UBI_KERNEL_CAPACITY,
            "fit_bytes": len(raw),
            "margin_bytes": UBI_KERNEL_CAPACITY - len(raw),
            "fits": True,
        },
        "authorization": {
            "experimental_package_payload": True,
            "device_contact": False,
            "stock_first_install": False,
            "flash": False,
            "cold_boot_proof": False,
        },
    }


def _write_exclusive(path: Path, value: bytes) -> None:
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        fail(f"output parent must be an existing real directory: {parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    try:
        descriptor = os.open(str(path), flags, 0o600)
    except OSError as error:
        fail(f"refusing output path: {path}: {error}")
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def extract(donor: Path, kernel_path: Path, dtb_path: Path, receipt_path: Path) -> dict:
    outputs = (kernel_path, dtb_path, receipt_path)
    if len({str(path.resolve(strict=False)) for path in outputs}) != len(outputs):
        fail("kernel, DTB, and receipt outputs must differ")
    if any(path.exists() or path.is_symlink() for path in outputs):
        fail("kernel, DTB, and receipt outputs must all be absent")
    kernel, dtb, receipt = admit_donor(donor)
    written = []
    try:
        for path, value in (
            (kernel_path, kernel),
            (dtb_path, dtb),
            (receipt_path, canonical_json(receipt)),
        ):
            _write_exclusive(path, value)
            written.append(path)
    except BaseException:
        for path in written:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return receipt


def _canonical_ubi_fit(kernel: bytes, dtb: bytes) -> bytes:
    """Encode only the existing, exact-pinned S17 FIT; never repair host output.

    The property-string order and 384 zero trailer bytes are part of the
    historical OUTPUT_FIT_SHA256 contract. Keeping those bytes avoids changing
    the admitted U-Boot tuple when host mkimage fails to finalize this layout.
    """
    _validate_kernel(kernel)
    _validate_dtb(dtb)
    names = (
        "description", "#address-cells", "data", "type", "arch", "os",
        "compression", "load", "entry", "algo", "default", "kernel", "fdt",
        "timestamp", "value",
    )
    strings = bytearray()
    offsets = {}
    for name in names:
        offsets[name] = len(strings)
        strings.extend(name.encode("ascii") + b"\0")
    structure = bytearray()

    def word(value: int) -> None:
        structure.extend(struct.pack(">I", value))

    def aligned(value: bytes) -> None:
        structure.extend(value)
        structure.extend(bytes(-len(value) % 4))

    def begin(name: str) -> None:
        word(1)
        aligned(name.encode("ascii") + b"\0")

    def prop(name: str, value: bytes) -> None:
        word(3)
        word(len(value))
        word(offsets[name])
        aligned(value)

    def text(name: str, value: str) -> None:
        prop(name, value.encode("ascii") + b"\0")

    def hashes(payload: bytes) -> None:
        for name, algorithm, value in (
            ("hash@1", "crc32", struct.pack(">I", zlib.crc32(payload) & 0xFFFFFFFF)),
            ("hash@2", "sha1", hashlib.sha1(payload).digest()),
        ):
            begin(name)
            prop("value", value)
            text("algo", algorithm)
            word(2)

    begin("")
    prop("timestamp", struct.pack(">I", SOURCE_FIT_TIMESTAMP))
    text("description", OUTPUT_FIT_DESCRIPTION)
    prop("#address-cells", struct.pack(">I", 1))
    begin("images")
    begin("kernel@1")
    text("description", OUTPUT_KERNEL_DESCRIPTION)
    prop("data", kernel)
    text("type", "kernel")
    text("arch", "arm")
    text("os", "linux")
    text("compression", "none")
    prop("load", struct.pack(">I", 0x8000))
    prop("entry", struct.pack(">I", 0x8000))
    hashes(kernel)
    word(2)
    begin("fdt@1")
    text("description", OUTPUT_DTB_DESCRIPTION)
    prop("data", dtb)
    text("type", "flat_dt")
    text("arch", "arm")
    text("compression", "none")
    hashes(dtb)
    word(2)
    word(2)
    begin("configurations")
    text("default", "config@1")
    begin("config@1")
    text("description", OUTPUT_CONFIG_DESCRIPTION)
    text("kernel", "kernel@1")
    text("fdt", "fdt@1")
    word(2)
    word(2)
    word(2)
    word(9)
    start = 56
    header = struct.pack(
        ">10I", 0xD00DFEED, start + len(structure) + len(strings) + 384,
        start, start + len(structure), 40, 17, 16, 0,
        len(strings), len(structure),
    )
    result = header + bytes(16) + structure + strings + bytes(384)
    if len(result) != OUTPUT_FIT_SIZE or sha256_bytes(result) != OUTPUT_FIT_SHA256:
        fail("canonical S17 FIT builder did not reproduce the existing output pin")
    return result


def build_ubi_fit(kernel_path: Path, dtb_path: Path, output: Path) -> dict:
    """Build from exact-admitted regular payloads and recheck the actual output."""
    if output.exists() or output.is_symlink():
        fail("S17 FIT output must be absent")
    kernel = _read_regular(kernel_path, KERNEL_SIZE, "S17 kernel")
    dtb = _read_regular(dtb_path, DTB_SIZE, "S17 DTB")
    value = _canonical_ubi_fit(kernel, dtb)
    _write_exclusive(output, value)
    return verify_ubi_fit(output)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    extract_parser = commands.add_parser(
        "extract", help="admit donor and extract kernel+DTB"
    )
    extract_parser.add_argument("--donor", type=Path, required=True)
    extract_parser.add_argument("--kernel-output", type=Path, required=True)
    extract_parser.add_argument("--dtb-output", type=Path, required=True)
    extract_parser.add_argument("--receipt", type=Path, required=True)
    build = commands.add_parser("build-fit", help="build the exact canonical S17 FIT")
    build.add_argument("--kernel", type=Path, required=True)
    build.add_argument("--dtb", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    fit_parser = commands.add_parser(
        "verify-fit", help="verify the rebuilt UBI boot FIT"
    )
    fit_parser.add_argument("--fit", type=Path, required=True)
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "extract":
            result = extract(
                args.donor, args.kernel_output, args.dtb_output, args.receipt
            )
        elif args.command == "build-fit":
            result = build_ubi_fit(args.kernel, args.dtb, args.output)
        else:
            result = verify_ubi_fit(args.fit)
    except AdmissionError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(canonical_json(result).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
