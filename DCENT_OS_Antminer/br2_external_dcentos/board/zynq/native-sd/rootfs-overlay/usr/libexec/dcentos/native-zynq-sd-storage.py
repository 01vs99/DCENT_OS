#!/usr/bin/python3
"""Admit only the selected native Zynq card's data partition; never format it.

The immutable root carries the exact profile produced for this card. This
helper checks kernel-provided boot, SD, root-mount and ext4 identities before
issuing a mount. It has no NAND, UBI, discovery, repair or fallback path.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import uuid

TARGETS = frozenset(
    (
        "am1-s9i",
        "am1-s9j",
        "am2-s17p",
        "am2-s17plus",
        "am2-t17",
        "am2-t17plus",
        "am2-s19pro",
        "am2-s19",
        "am2-t19",
        "am2-s19a",
        "am2-s19plus",
    )
)
PROFILE = Path("/etc/dcentos/native-zynq-sd.json")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate profile key")
        result[key] = value
    return result


def expected_profile(target):
    if target not in TARGETS:
        raise ValueError("exact native Zynq SD target required")
    am1 = target.startswith("am1-")
    return {
        "schema": "dcentos.native_zynq_sd_storage.v1",
        "board_target": target,
        "board_family": "am1" if am1 else "am2",
        "platform": "zynq-am1" if am1 else "zynq-bm3-am2",
        "root_source": "/dev/ram0" if am1 else "/dev/mmcblk0p2",
        "root_fstype": "squashfs",
        "data_device": "/dev/mmcblk0p2" if am1 else "/dev/mmcblk0p3",
        "data_start_sector": 198656 if am1 else 296960,
        "data_uuid": str(
            uuid.uuid5(
                uuid.NAMESPACE_URL, "https://d-cent.local/native-sd/v1/" + target
            )
        ),
        "data_bytes": 67108864,
        "data_label": "DCENT_SD_DATA",
    }


def profile_from_bytes(raw):
    if len(raw) > 16384:
        raise ValueError("bounded storage profile required")
    value = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(value, dict) or not isinstance(value.get("board_target"), str):
        raise ValueError("storage profile object required")
    expected = expected_profile(value["board_target"])
    if value != expected or any(
        type(value[k]) is not type(v) for k, v in expected.items()
    ):
        raise ValueError("exact storage profile required")
    return expected


def mount_rows(raw):
    rows = []
    for line in raw.splitlines():
        fields = line.split()
        if "-" not in fields or len(fields) < 10:
            raise ValueError("malformed kernel mountinfo")
        separator = fields.index("-")
        if separator < 6 or len(fields) != separator + 4:
            raise ValueError("malformed kernel mountinfo fields")
        rows.append(
            {
                "device": fields[2],
                "root": fields[3],
                "path": fields[4],
                "options": set(fields[5].split(",")),
                "fstype": fields[separator + 1],
                "source": fields[separator + 2],
                "super_options": set(fields[separator + 3].split(",")),
            }
        )
    return rows


def one_mount(rows, path):
    selected = [row for row in rows if row["path"] == path]
    if len(selected) != 1:
        raise ValueError("exactly one mount required at " + path)
    return selected[0]


def validate_boot(
    profile,
    *,
    identities,
    cmdline,
    mounts,
    sd_type,
    removable,
    root_dev,
    data_dev,
    data_node_dev,
    data_sectors,
    data_start,
    superblock,
):
    """Pure admission before any mount request; all arguments are actual reads."""
    if identities != {
        k: profile[k] for k in ("board_target", "board_family", "platform")
    }:
        raise ValueError("immutable board identity differs")
    if sd_type.strip() != "SD" or removable.strip() != "1":
        raise ValueError("removable SD controller required")
    for name, expected in (
        ("root", profile["root_source"]),
        ("rootfstype", "squashfs"),
    ):
        values = [
            part.split("=", 1)[1]
            for part in cmdline.split()
            if part.startswith(name + "=")
        ]
        if values != [expected]:
            raise ValueError("exact kernel root arguments required")
    flags = [part for part in cmdline.split() if part in ("ro", "rw")]
    if flags != ["ro"]:
        raise ValueError("explicit read-only kernel root required")
    rows = mount_rows(mounts)
    root = one_mount(rows, "/")
    if (
        root["device"] != root_dev.strip()
        or root["root"] != "/"
        or root["fstype"] != "squashfs"
        or "ro" not in root["options"]
        or "rw" in root["options"]
        or "ro" not in root["super_options"]
        or "rw" in root["super_options"]
    ):
        raise ValueError("actual root mount differs")
    if any(row["path"] == "/data" for row in rows):
        raise ValueError("data must be unmounted before admission")
    if data_dev.strip() != data_node_dev or data_dev.strip() == root_dev.strip():
        raise ValueError("separate exact SD data block device required")
    if data_sectors.strip() != "131072":
        raise ValueError("exact 64 MiB data partition required")
    if data_start.strip() != str(profile["data_start_sector"]):
        raise ValueError("exact target data partition placement required")
    if len(superblock) != 1024 or struct.unpack_from("<H", superblock, 56)[0] != 0xEF53:
        raise ValueError("ext4 data superblock required")
    if (
        struct.unpack_from("<I", superblock, 4)[0] != 16384
        or struct.unpack_from("<I", superblock, 24)[0] != 2
        or struct.unpack_from("<I", superblock, 336)[0] != 0
    ):
        raise ValueError("exact 64 MiB / 4096-byte ext4 geometry required")
    if str(uuid.UUID(bytes=superblock[104:120])) != profile["data_uuid"]:
        raise ValueError("foreign data UUID")
    if superblock[120:136] != b"DCENT_SD_DATA\0\0\0":
        raise ValueError("foreign data label")
    # Unsupported on-disk features are refused before the kernel sees them.
    compat, incompat, ro_compat = struct.unpack_from("<III", superblock, 92)
    if (
        compat & ~0x3C
        or incompat & ~0x242
        or ro_compat & ~0x7B
        or not incompat & 0x40
        or incompat & 0x80
    ):
        raise ValueError("unsupported ext4 data features")
    return data_dev.strip()


def validate_mounted(mounts, data_dev, device):
    row = one_mount(mount_rows(mounts), "/data")
    if (
        row["device"] != data_dev
        or row["root"] != "/"
        or row["source"] != device
        or row["fstype"] != "ext4"
        or not {"rw", "nodev", "nosuid"} <= row["options"]
        or "ro" in row["options"]
        or "rw" not in row["super_options"]
    ):
        raise ValueError("mounted SD data readback differs")


def read_regular(path, limit):
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > limit
    ):
        raise ValueError("bounded unique regular identity file required")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not os.path.samestat(before, opened):
            raise ValueError("identity file replaced")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    if (
        len(raw) > limit
        or not os.path.samestat(after, path.lstat())
        or (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns)
        != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
    ):
        raise ValueError("identity file changed")
    return raw


def prepare(*, verification_only=False):
    profile = profile_from_bytes(read_regular(PROFILE, 16384))
    identity = {
        name: read_regular(Path("/etc/dcentos") / name, 128).decode().strip()
        for name in ("board_target", "board_family", "platform")
    }
    data = Path(profile["data_device"])

    def read(name):
        return Path(name).read_text(encoding="ascii")

    sd_type = read("/sys/class/block/mmcblk0/device/type")
    removable = read("/sys/class/block/mmcblk0/removable")
    data_dev = read("/sys/class/block/" + data.name + "/dev")
    # Device nodes are created from this same kernel sysfs table by early-init.
    node = data.lstat()
    if not stat.S_ISBLK(node.st_mode):
        raise ValueError("direct SD data block node required")
    node_dev = str(os.major(node.st_rdev)) + ":" + str(os.minor(node.st_rdev))
    # Establish the node's kernel SD identity before the first block read.
    if (
        sd_type.strip() != "SD"
        or removable.strip() != "1"
        or node_dev != data_dev.strip()
    ):
        raise ValueError(
            "actual removable SD node required before reading its superblock"
        )
    descriptor = os.open(data, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not os.path.samestat(node, opened) or opened.st_rdev != node.st_rdev:
            raise ValueError("SD node changed")
        stream.seek(1024)
        superblock = stream.read(1024)
    root_name = Path(profile["root_source"]).name
    mounts = read("/proc/self/mountinfo")
    if verification_only:
        validate_mounted(mounts, data_dev.strip(), str(data))
        # Validate the same complete pre-mount root/card identity after removing
        # only the already-validated /data row; all duplicate mounts were refused.
        mounts = "\n".join(
            line for line in mounts.splitlines() if line.split()[4] != "/data"
        )
    data_dev = validate_boot(
        profile,
        identities=identity,
        cmdline=read("/proc/cmdline"),
        mounts=mounts,
        sd_type=sd_type,
        removable=removable,
        root_dev=read("/sys/class/block/" + root_name + "/dev"),
        data_dev=data_dev,
        data_node_dev=node_dev,
        data_sectors=read("/sys/class/block/" + data.name + "/size"),
        data_start=read("/sys/class/block/" + data.name + "/start"),
        superblock=superblock,
    )
    if not stat.S_ISDIR(Path("/data").lstat().st_mode):
        raise ValueError("direct immutable-root data directory required")
    if not os.path.samestat(node, data.lstat()):
        raise ValueError("SD node replaced before mount")
    if not verification_only:
        subprocess.run(
            ["/bin/mount", "-t", "ext4", "-o", "rw,nodev,nosuid", str(data), "/data"],
            check=True,
            timeout=20,
        )
    validate_mounted(read("/proc/self/mountinfo"), data_dev, str(data))
    # The caller publishes readiness only after writable /etc and /root bind
    # mounts have also succeeded. No receipt is published by this component.
    return profile


if __name__ == "__main__":
    if sys.argv[1:] not in ([], ["--verify"]):
        raise ValueError("only preparation or read-only --verify is supported")
    prepare(verification_only=bool(sys.argv[1:]))
