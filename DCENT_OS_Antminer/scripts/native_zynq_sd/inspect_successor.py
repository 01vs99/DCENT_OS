"""Decode every packed successor member and compare it with its sealed plan.

The immutable base remains native28; this separately binds the actual native30
root. No extraction, executable, mount, physical device or release grant.
"""

from __future__ import annotations

import hashlib
import json
import struct

from dcent_toolbox.core.squashfs_files import SquashfsFiles

from .boot_assets import EPOCH
from .inspect_base import runtime_dependencies
from .profiles import profile


def _pin(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _links(inventory: dict) -> list:
    groups = {}
    for name, row in inventory.items():
        if row["kind"] == 2:
            groups.setdefault(row["inode"], []).append(name)
    return sorted(sorted(names) for names in groups.values())


def inspect_successor(raw: bytes, plan: dict, wanted: dict) -> dict:
    selected = profile(plan.get("board_target"))
    if (
        plan.get("schema") != "dcentos.native_zynq_sd_successor_root_plan.v1"
        or plan.get("native_checkpoint") != 30
        or plan.get("base_native_checkpoint") != 28
        or plan.get("family") != selected["board_family"]
        or plan.get("inventory") != _pin((json.dumps(wanted, sort_keys=True) + "\n").encode())
    ):
        raise ValueError("complete exact-target native30 successor plan required")
    fs = SquashfsFiles(raw)
    if fs.read("etc/dcentos/board_target") != (selected["board_target"] + "\n").encode():
        raise ValueError("packed successor target marker differs from plan")
    native = plan.get("native", {})
    if (
        native.get("schema") != "dcentos.native_zynq_sd_successor_native.v1"
        or native.get("native_checkpoint") != 30
        or native.get("release_authentication_verified") is not False
        or set(native.get("executables", {})) != {"dcentrald", "dcentos-discovery", "dcentos-init"}
    ):
        raise ValueError("complete native30 executable evidence required")
    for name, path in (("dcentrald", "usr/local/bin/dcentrald"),
                       ("dcentos-discovery", "usr/bin/dcentos-discovery"),
                       ("dcentos-init", "sbin/init")):
        actual_native = _pin(fs.read(path))
        if actual_native != native["executables"][name] or fs.read("etc/dcentos/" + name + ".sha256") != (actual_native["sha256"] + "\n").encode():
            raise ValueError("packed successor native executable/marker differs: " + name)
    if fs.compressor != (1 if selected["board_family"] == "am1" else 4):
        raise ValueError("packed successor compressor differs from boot family")
    if len(raw) > 48 * 1024 * 1024:
        raise ValueError("packed successor exceeds root allocation")
    if struct.unpack_from("<I", raw, 8)[0] != EPOCH:
        raise ValueError("packed successor creation timestamp differs")
    actual = fs.inventory()
    if set(actual) != set(wanted):
        raise ValueError("packed successor member set differs")
    for name, row in actual.items():
        if row["kind"] not in (1, 2, 3):
            raise ValueError("packed successor contains a special node")
        if {k: v for k, v in row.items() if k != "inode"} != {
            k: v for k, v in wanted[name].items() if k != "inode"
        }:
            raise ValueError("packed successor metadata/content differs: " + name)
        # The retained generic decoder deliberately omits timestamps from its
        # inventory. Read the v4 inode header using its bounded metadata frames;
        # do not alter the predecessor reader or inventories in place.
        inode = fs.find(name) if name else fs.inode(fs.root_reference)
        header = fs._read_metadata(fs.inode_frames, inode.reference >> 16,
                                   inode.reference & 0xFFFF, 16)
        _kind, _mode, _uid, _gid, mtime, number = struct.unpack("<HHHHII", header)
        if mtime != EPOCH or number != inode.number:
            raise ValueError("packed successor inode timestamp differs: " + name)
    links = _links(actual)
    if links != _links(wanted):
        raise ValueError("packed successor hardlink relationships differ")
    graph = runtime_dependencies(fs, actual)
    if json.dumps(graph, sort_keys=True) != json.dumps(plan.get("elf_dependencies"), sort_keys=True):
        raise ValueError("packed successor executable dependency graph differs")
    return {
        "schema": "dcentos.native_zynq_sd_packed_successor_inspection.v1",
        "board_target": plan["board_target"], "native_checkpoint": 30,
        "root": _pin(raw), "entries": len(actual), "elf_objects": len(graph),
        "all_metadata_content_and_links_equal": True, "all_inode_times_equal": True,
        "epoch": EPOCH, "compressor": fs.compressor,
        "hardlink_groups": [names for names in links if len(names) > 1],
        "physical_qualification": "pending", "release_authentication_verified": False,
    }
