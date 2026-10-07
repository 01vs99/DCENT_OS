"""Host-only storage identity/refusal tests; no block device is opened."""

import importlib.util
import json
import os
from pathlib import Path
import struct
import stat
from types import SimpleNamespace
import uuid

import pytest

PROJECT = Path(__file__).resolve().parents[2]
SOURCE = (
    PROJECT
    / "br2_external_dcentos/board/zynq/native-sd/rootfs-overlay/usr/libexec/dcentos/native-zynq-sd-storage.py"
)
SPEC = importlib.util.spec_from_file_location("native_zynq_sd_storage", SOURCE)
storage = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(storage)
TARGETS = sorted(storage.TARGETS)


def fixture(target):
    profile = storage.expected_profile(target)
    am1 = target.startswith("am1-")
    root_dev, data_dev = ("1:0", "179:2") if am1 else ("179:2", "179:3")
    superblock = bytearray(1024)
    struct.pack_into("<I", superblock, 4, 16384)
    struct.pack_into("<I", superblock, 24, 2)
    struct.pack_into("<H", superblock, 56, 0xEF53)
    struct.pack_into("<III", superblock, 92, 0x3C, 0x242, 0x7B)
    superblock[104:120] = uuid.UUID(profile["data_uuid"]).bytes
    superblock[120:136] = b"DCENT_SD_DATA\0\0\0"
    return profile, {
        "identities": {
            k: profile[k] for k in ("board_target", "board_family", "platform")
        },
        "cmdline": "console=ttyPS0,115200 root="
        + profile["root_source"]
        + " rootfstype=squashfs ro rootwait",
        "mounts": "20 0 " + root_dev + " / / ro,relatime - squashfs /dev/root ro\n",
        "sd_type": "SD\n",
        "removable": "1\n",
        "root_dev": root_dev + "\n",
        "data_dev": data_dev + "\n",
        "data_node_dev": data_dev,
        "data_sectors": "131072\n",
        "data_start": str(profile["data_start_sector"]) + "\n",
        "superblock": bytes(superblock),
    }


@pytest.mark.parametrize("target", TARGETS)
def test_exact_boot_and_target_data_identity(target):
    profile, args = fixture(target)
    assert storage.profile_from_bytes(json.dumps(profile).encode()) == profile
    assert storage.validate_boot(profile, **args) == args["data_dev"].strip()


@pytest.mark.parametrize("target", TARGETS)
def test_every_other_target_is_refused(target):
    profile, args = fixture(target)
    for other in TARGETS:
        if target == other:
            continue
        other_profile, other_args = fixture(other)
        with pytest.raises(ValueError):
            storage.validate_boot(profile, **other_args)
        args["superblock"] = other_args["superblock"]
        with pytest.raises(ValueError, match="UUID"):
            storage.validate_boot(profile, **args)
        assert other_profile["data_uuid"] != profile["data_uuid"]


@pytest.mark.parametrize("target", ["am1-s9i", "am2-s19pro"])
@pytest.mark.parametrize(
    "fault",
    [
        "sd_type",
        "removable",
        "root_argument",
        "duplicate_root",
        "duplicate_fstype",
        "writable_argument",
        "missing_readonly",
        "duplicate_root_mount",
        "wrong_root_device",
        "root_rw",
        "root_super_rw",
        "root_bind",
        "root_filesystem",
        "already_mounted",
        "data_node_alias",
        "data_root_alias",
        "data_size",
        "data_start",
        "superblock_size",
        "magic",
        "blocks",
        "blocksize",
        "high_blocks",
        "uuid",
        "label",
        "unsupported_feature",
        "no_extents",
        "identity",
        "malformed_mount",
        "missing_root_mount",
    ],
)
def test_pre_mount_refusal_matrix(target, fault):
    profile, args = fixture(target)
    if fault == "sd_type":
        args["sd_type"] = "MMC\n"
    elif fault == "removable":
        args["removable"] = "0\n"
    elif fault == "root_argument":
        args["cmdline"] = args["cmdline"].replace(
            profile["root_source"], "/dev/mtdblock7"
        )
    elif fault == "duplicate_root":
        args["cmdline"] += " root=" + profile["root_source"]
    elif fault == "duplicate_fstype":
        args["cmdline"] += " rootfstype=squashfs"
    elif fault == "writable_argument":
        args["cmdline"] += " rw"
    elif fault == "missing_readonly":
        args["cmdline"] = args["cmdline"].replace(" ro ", " ")
    elif fault == "duplicate_root_mount":
        args["mounts"] *= 2
    elif fault == "wrong_root_device":
        args["root_dev"] = "31:7\n"
    elif fault == "root_rw":
        args["mounts"] = args["mounts"].replace("ro,relatime", "rw,relatime")
    elif fault == "root_super_rw":
        args["mounts"] = args["mounts"].replace("/dev/root ro", "/dev/root rw")
    elif fault == "root_bind":
        args["mounts"] = args["mounts"].replace(" / / ", " /subdir / ")
    elif fault == "root_filesystem":
        args["mounts"] = args["mounts"].replace("squashfs", "ubifs")
    elif fault == "already_mounted":
        args["mounts"] += "21 20 0:55 / /data rw - ubifs ubi0:rootfs_data rw\n"
    elif fault == "data_node_alias":
        args["data_node_dev"] = "179:8"
    elif fault == "data_root_alias":
        args["data_dev"] = args["root_dev"]
        args["data_node_dev"] = args["root_dev"].strip()
    elif fault == "data_size":
        args["data_sectors"] = "131071"
    elif fault == "data_start":
        args["data_start"] = str(profile["data_start_sector"] + 2048)
    elif fault == "identity":
        args["identities"]["board_target"] = "am1-s9se"
    elif fault == "malformed_mount":
        args["mounts"] = "20 0 broken\n"
    elif fault == "missing_root_mount":
        args["mounts"] = ""
    else:
        superblock = bytearray(args["superblock"])
        if fault == "superblock_size":
            superblock.pop()
        elif fault == "magic":
            superblock[56] ^= 1
        elif fault == "blocks":
            superblock[4] ^= 1
        elif fault == "blocksize":
            superblock[24] ^= 1
        elif fault == "high_blocks":
            superblock[336] = 1
        elif fault == "uuid":
            superblock[104] ^= 1
        elif fault == "label":
            superblock[120] ^= 1
        elif fault == "unsupported_feature":
            superblock[101] |= 4
        elif fault == "no_extents":
            superblock[96] &= ~0x40
        args["superblock"] = bytes(superblock)
    with pytest.raises(ValueError):
        storage.validate_boot(profile, **args)


@pytest.mark.parametrize(
    "fault", ["duplicate", "foreign", "extra", "bool_size", "device", "uuid"]
)
def test_immutable_profile_is_exact(fault):
    profile = storage.expected_profile("am1-s9j")
    if fault == "duplicate":
        raw = (
            json.dumps(profile)
            .replace('"schema":', '"schema": "bad", "schema":')
            .encode()
        )
    else:
        if fault == "foreign":
            profile["board_target"] = "am1-s9se"
        elif fault == "extra":
            profile["fallback"] = "/dev/mtdblock7"
        elif fault == "bool_size":
            profile["data_bytes"] = True
        elif fault == "device":
            profile["data_device"] = "/dev/mmcblk0p3"
        elif fault == "uuid":
            profile["data_uuid"] = storage.expected_profile("am1-s9i")["data_uuid"]
        raw = json.dumps(profile).encode()
    with pytest.raises(ValueError):
        storage.profile_from_bytes(raw)


@pytest.mark.parametrize("target", TARGETS)
def test_complete_mounted_readback(target):
    profile, args = fixture(target)
    mounted = (
        "30 20 "
        + args["data_node_dev"]
        + " / /data rw,nodev,nosuid,relatime - ext4 "
        + profile["data_device"]
        + " rw,data=ordered\n"
    )
    storage.validate_mounted(
        args["mounts"] + mounted, args["data_node_dev"], profile["data_device"]
    )
    for bad in (
        mounted * 2,
        mounted.replace("rw,nodev,nosuid", "rw,nodev"),
        mounted.replace("rw,nodev,nosuid", "ro,nodev,nosuid"),
        mounted.replace(profile["data_device"], "/dev/mmcblk1p3"),
        mounted.replace(args["data_node_dev"], "31:7"),
        mounted.replace(" / /data ", " /subdir /data "),
        mounted.replace("ext4", "ubifs"),
    ):
        with pytest.raises(ValueError):
            storage.validate_mounted(
                args["mounts"] + bad, args["data_node_dev"], profile["data_device"]
            )


@pytest.mark.parametrize("target", ["am1-s9j", "am2-t17plus"])
@pytest.mark.parametrize(
    "fault",
    [
        "none",
        "foreign_sd",
        "fixed_media",
        "foreign_node",
        "regular_node",
        "wrong_superblock",
        "wrong_root",
        "lost_mount",
        "wrong_mount_device",
    ],
)
def test_actual_prepare_order_and_mount_readback(tmp_path, monkeypatch, target, fault):
    """Execute the production function with real file I/O and a modeled kernel.

    Only the block read is redirected to a regular fixture. There is no device
    or mount operation; the complete command is observed by an explicit model.
    """
    profile, args = fixture(target)
    block = tmp_path / "superblock.bin"
    raw = bytearray(args["superblock"])
    if fault == "wrong_superblock":
        raw[104] ^= 1
    block.write_bytes(bytes(1024) + raw)
    events = []
    device_numbers = tuple(int(x) for x in args["data_node_dev"].split(":"))
    node = SimpleNamespace(
        st_mode=stat.S_IFBLK | 0o600,
        st_dev=1,
        st_ino=2,
        st_rdev=os.makedev(*device_numbers)
        if hasattr(os, "makedev")
        else device_numbers[0] * 256 + device_numbers[1],
    )
    if fault == "foreign_node":
        node.st_rdev += 1
    if fault == "regular_node":
        node.st_mode = stat.S_IFREG | 0o600
    reads = {
        "/sys/class/block/mmcblk0/device/type": "MMC"
        if fault == "foreign_sd"
        else args["sd_type"],
        "/sys/class/block/mmcblk0/removable": "0"
        if fault == "fixed_media"
        else args["removable"],
        "/sys/class/block/" + Path(profile["data_device"]).name + "/dev": args[
            "data_dev"
        ],
        "/sys/class/block/" + Path(profile["data_device"]).name + "/size": args[
            "data_sectors"
        ],
        "/sys/class/block/" + Path(profile["data_device"]).name + "/start": args[
            "data_start"
        ],
        "/sys/class/block/" + Path(profile["root_source"]).name + "/dev": args[
            "root_dev"
        ],
        "/proc/cmdline": args["cmdline"],
        "/proc/self/mountinfo": args["mounts"].replace("squashfs", "ubifs")
        if fault == "wrong_root"
        else args["mounts"],
    }

    class KernelPath:
        def __init__(self, value):
            self.value = str(value)

        @property
        def name(self):
            return self.value.rsplit("/", 1)[-1]

        def __str__(self):
            return self.value

        def __truediv__(self, other):
            return KernelPath(self.value + "/" + other)

        def lstat(self):
            if self.value == profile["data_device"]:
                return node
            assert self.value == "/data"
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755)

        def read_text(self, encoding):
            events.append(("kernel_read", self.value))
            return reads[self.value]

    real_open = os.open

    def open_block(path, flags):
        assert str(path) == profile["data_device"]
        assert ("kernel_read", "/sys/class/block/mmcblk0/device/type") in events
        assert (
            "kernel_read",
            "/sys/class/block/" + Path(profile["data_device"]).name + "/dev",
        ) in events
        events.append(("block_read", str(path)))
        return real_open(block, os.O_RDONLY | getattr(os, "O_BINARY", 0))

    def mount(command, check, timeout):
        assert command == [
            "/bin/mount",
            "-t",
            "ext4",
            "-o",
            "rw,nodev,nosuid",
            profile["data_device"],
            "/data",
        ]
        assert check and timeout == 20
        events.append(("mount", command))
        if fault != "lost_mount":
            source = (
                "/dev/mmcblk1p3"
                if fault == "wrong_mount_device"
                else profile["data_device"]
            )
            reads["/proc/self/mountinfo"] += (
                "30 20 "
                + args["data_node_dev"]
                + " / /data rw,nodev,nosuid - ext4 "
                + source
                + " rw\n"
            )

    def identity(path, limit):
        if str(path).endswith("native-zynq-sd.json"):
            return json.dumps(profile).encode()
        return (args["identities"][path.name] + "\n").encode()

    monkeypatch.setattr(storage, "Path", KernelPath)
    monkeypatch.setattr(storage, "read_regular", identity)
    monkeypatch.setattr(storage.os, "open", open_block)
    monkeypatch.setattr(storage.os, "fstat", lambda fd: node)
    monkeypatch.setattr(storage.subprocess, "run", mount)
    if not hasattr(os, "major"):
        monkeypatch.setattr(storage.os, "major", lambda n: n // 256, raising=False)
        monkeypatch.setattr(storage.os, "minor", lambda n: n % 256, raising=False)
    for flag in ("O_NOFOLLOW", "O_NONBLOCK"):
        if not hasattr(os, flag):
            monkeypatch.setattr(storage.os, flag, 0, raising=False)
    if fault == "none":
        assert storage.prepare() == profile
        assert storage.prepare(verification_only=True) == profile
        # Verification does another actual regular-file superblock read and
        # complete boot/data identity check, with no second mount request.
    else:
        with pytest.raises(ValueError):
            storage.prepare()
    opened = [event for event in events if event[0] == "block_read"]
    mounted = [event for event in events if event[0] == "mount"]
    assert len(opened) == (
        2
        if fault == "none"
        else 0
        if fault in {"foreign_sd", "fixed_media", "foreign_node", "regular_node"}
        else 1
    )
    assert len(mounted) == (
        1 if fault in {"none", "lost_mount", "wrong_mount_device"} else 0
    )
