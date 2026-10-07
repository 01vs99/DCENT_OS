"""Assemble and read back a new private regular-file native30 SD card.

Only private host files are created. Every selected root must already have a
complete successor plan; boot inputs and pristine data are independently read.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import zlib

from dcent_toolbox.core.flat_fat32 import read_flat_fat32
from dcent_toolbox.core.pristine_ext4 import inspect_pristine_ext4
from dcent_toolbox.core.uboot_legacy_image import parse_uboot_legacy_image

from .boot_assets import EPOCH, am2_boot_assets, s9_ramdisk, s9_static_assets
from .inspect_successor import inspect_successor
from .prepare_data import prepare_data
from .profiles import BOOT_BYTES, MIB, ROOT_BYTES, profile


def pin(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _write(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def mbr(target: str) -> bytes:
    result = bytearray(512)
    for index, (start, count, kind) in enumerate(profile(target)["partitions"]):
        struct.pack_into("<B3sB3sII", result, 446 + index * 16,
                         0x80 if index == 0 else 0, b"\xfe\xff\xff", kind,
                         b"\xfe\xff\xff", start, count)
    result[510:] = b"\x55\xaa"
    return bytes(result)


def inspect_card(raw: bytes, target: str, *, boot_files: dict, root_plan: dict,
                 root_inventory: dict, expected_root: bytes) -> dict:
    selected = profile(target)
    if type(raw) is not bytes or len(raw) != selected["image_bytes"]:
        raise ValueError("complete exact-target private card bytes required")
    if raw[:512] != mbr(target) or any(raw[512:MIB]):
        raise ValueError("card partition table or unallocated prefix differs")
    parts = [raw[start * 512:(start + count) * 512]
             for start, count, _kind in selected["partitions"]]
    boot = read_flat_fat32(parts[0], label="DCENTOS",
                           limits={name: len(value) for name, value in boot_files.items()})
    if boot != boot_files:
        raise ValueError("complete card boot bytes differ from selected source assets")
    if selected["board_family"] == "am1":
        legacy = parse_uboot_legacy_image(boot["uramdisk.image.gz"])
        if (legacy.os_id, legacy.architecture_id, legacy.image_type_id,
            legacy.compression_id, legacy.load_address, legacy.entry_address,
            legacy.timestamp) != (5, 2, 3, 1, 0, 0, EPOCH):
            raise ValueError("AM1 root ramdisk wrapper differs")
        decoder = zlib.decompressobj(31)
        root = decoder.decompress(legacy.payload, ROOT_BYTES + 1)
        if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail or len(root) > ROOT_BYTES:
            raise ValueError("bounded complete single AM1 ramdisk member required")
    else:
        root = parts[1][:len(expected_root)]
        if any(parts[1][len(expected_root):]):
            raise ValueError("AM2 root partition has a nonzero tail")
    if root != expected_root or root_plan.get("board_target") != target:
        raise ValueError("card root differs from exact selected successor")
    root_check = inspect_successor(root, root_plan, root_inventory)
    data_check = inspect_pristine_ext4(parts[-1], expected_uuid=selected["data_uuid"])
    return {"image": pin(raw), "board_target": target, "native_checkpoint": 30,
            "partitions": [pin(part) for part in parts], "root": root_check,
            "data": data_check, "boot_files": {name: pin(value) for name, value in boot.items()},
            "complete_card_readback": True, "physical_qualification": "pending",
            "release_authentication_verified": False}


def prepare_card(job: Path, target: str, *, root: bytes, root_plan: dict,
                 root_inventory: dict, boot_inputs: dict[str, bytes]) -> dict:
    selected = profile(target)
    if root_plan.get("board_target") != target:
        raise ValueError("root plan target differs")
    root_check = inspect_successor(root, root_plan, root_inventory)
    boot = (s9_static_assets(target, boot_inputs) if selected["board_family"] == "am1"
            else am2_boot_assets(target, boot_inputs))
    if selected["board_family"] == "am1":
        boot["uramdisk.image.gz"] = s9_ramdisk(root)
    if os.name != "posix" or not job.is_absolute() or job.parent.resolve() != job.parent:
        raise ValueError("direct absolute Linux private card job required")
    parent = job.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
        raise ValueError("private caller-owned parent required")
    if job.exists() or job.is_symlink():
        raise ValueError("preserve prior card job; choose a new directory")
    tools = {}
    for name in ("mkfs.fat", "mcopy"):
        path = shutil.which(name)
        if path is None:
            raise ValueError("required private filesystem tool absent: " + name)
        tools[name] = {"path": path, "resolved": str(Path(path).resolve()),
                       **pin(Path(path).read_bytes())}
    job.mkdir(mode=0o700)
    result = {"status": "RUNNING", "board_target": target, "commands": [], "tools": tools,
              "hardware_contact": False, "device_io": False, "mount_performed": False,
              "release_signing": False, "publication": False}
    try:
        data_result = prepare_data(job / "data", target)
        data = (job / "data/data.ext4").read_bytes()
        assert data_result["image"]["sha256"] == pin(data)["sha256"]
        inspect_pristine_ext4(data, expected_uuid=selected["data_uuid"])
        directory = job / "boot-files"
        directory.mkdir(mode=0o700)
        for name, content in boot.items():
            _write(directory / name, content)
            os.utime(directory / name, (EPOCH, EPOCH))
        fat = job / "boot.vfat"
        with fat.open("xb") as stream:
            stream.truncate(BOOT_BYTES)
            stream.flush()
            os.fsync(stream.fileno())
        commands = [[tools["mkfs.fat"]["path"], "--invariant", "-F", "32", "-s", "1",
                     "-S", "512", "-R", "32", "-f", "2", "-h", "2048", "-n", "DCENTOS", str(fat)]]
        commands += [[tools["mcopy"]["path"], "-m", "-i", str(fat), str(directory / name), "::" + name]
                     for name in sorted(boot)]
        environment = {**os.environ, "LC_ALL": "C", "TZ": "UTC", "MTOOLS_SKIP_CHECK": "1"}
        for index, command in enumerate(commands):
            log = job / ("boot-command-" + str(index) + ".log")
            with log.open("xb") as stream:
                completed = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT,
                                           env=environment, timeout=60)
            result["commands"].append({"command": command, "exit_code": completed.returncode,
                                       "log": pin(log.read_bytes())})
            if completed.returncode:
                raise ValueError("private FAT preparation failed; output and logs retained")
        fat_raw = fat.read_bytes()
        if read_flat_fat32(fat_raw, label="DCENTOS", limits={n:len(v) for n,v in boot.items()}) != boot:
            raise ValueError("FAT preparation readback differs")
        image = job / "dcentos-sd.img"
        with image.open("xb") as stream:
            stream.write(mbr(target))
            stream.write(bytes(MIB - 512))
            stream.write(fat_raw)
            if selected["board_family"] == "am2":
                stream.write(root)
                stream.write(bytes(ROOT_BYTES - len(root)))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        image.chmod(0o600)
        checked = inspect_card(image.read_bytes(), target, boot_files=boot, root_plan=root_plan,
                               root_inventory=root_inventory, expected_root=root)
        manifest = {"schema": "dcentos.native_zynq_sd_card.v1", "board_target": target,
                    "image": image.name, "image_size_bytes": checked["image"]["bytes"],
                    "image_sha256": checked["image"]["sha256"], "native_checkpoint": 30,
                    "data_uuid": selected["data_uuid"], "partitions": checked["partitions"],
                    "artifacts": {**checked["boot_files"], "rootfs.squashfs": pin(root),
                                  "data.ext4": pin(data), "boot.vfat": pin(fat_raw)},
                    "root_plan": pin((json.dumps(root_plan, sort_keys=True) + "\n").encode()),
                    "native_evidence": root_plan["native"], "boot_artifacts_complete": True,
                    "allow_incomplete": False, "physical_qualification": "pending",
                    "release_authentication_verified": False, "persistent_install_authorized": False,
                    "nand_mutation_authorized": False, "requires_sd_present": True}
        _write(Path(str(image) + ".manifest.json"), (json.dumps(manifest, indent=2) + "\n").encode())
        for tool in tools.values():
            if pin(Path(tool["path"]).read_bytes()) != {k:tool[k] for k in ("bytes", "sha256")}:
                raise ValueError("private filesystem tool changed")
        result.update(status="PASS", inspection=checked, root_preflight=root_check,
                      image_path=str(image), manifest=pin(Path(str(image) + ".manifest.json").read_bytes()))
    except BaseException as error:
        result.update(status="FAIL", error=repr(error))
        raise
    finally:
        _write(job / "card-preparation.json", (json.dumps(result, indent=2) + "\n").encode())
    return result
