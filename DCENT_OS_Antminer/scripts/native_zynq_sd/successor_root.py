"""Plan a native30/SSH root from a fully inspected immutable native28 base.

Planning reads ordinary source inputs and image bytes. It does not modify an
extracted base, execute target code, create a card or open a device. A later
producer must materialize, pack and independently inspect this exact plan.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import posixpath

from dcent_toolbox.core.squashfs_files import SquashfsFiles

from .assets import Asset, source_assets
from .inspect_base import inspect_base, runtime_dependencies
from .profiles import profile

# Exact completed roots and independent readbacks in campaign evidence/i02
# seven-am{1,2}-base-inspection-v1.json and b01/seven-bases-root-readback-v2.json.
QUALIFIED_BASES = {
    "am1": (29253632, "f89842c733d01055e9b6ce30128f3e2c9a553970f6852d42539028edf1ef1885"),
    "am2": (23982080, "e8c62b6bfb05007f2c99f8a80e44c878d1132a23131912710436c7cc97da13c3"),
}


def _pin(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


@dataclass(frozen=True)
class SuccessorRootPlan:
    target: str
    base: bytes
    inventory: dict
    replacements: dict[str, Asset]
    evidence: dict

    def read(self, name: str) -> bytes:
        """Return planned file bytes without resolving host filesystem paths."""
        if name == "usr/bin/dcentrald":
            name = "usr/local/bin/dcentrald"
        if name in self.replacements:
            return self.replacements[name].content
        return SquashfsFiles(self.base).read(name)


class _PlannedFiles:
    def __init__(self, fs: SquashfsFiles, replacements: dict[str, Asset]):
        self.fs = fs
        self.replacements = replacements

    def read(self, name: str) -> bytes:
        if name == "usr/bin/dcentrald":
            name = "usr/local/bin/dcentrald"
        asset = self.replacements.get(name)
        return asset.content if asset is not None else self.fs.read(name)


def plan_successor_root(
    source_root: Path,
    target: str,
    *,
    base: bytes,
    base_manifest: dict,
    base_finalization: dict,
    native_assets: dict[str, Asset],
    native_evidence: dict,
) -> SuccessorRootPlan:
    """Join a same-family qualified base to exact target sources and native30.

    `native_assets` and `native_evidence` come from native30_assets(). The
    evidence is checked again against the actual supplied bytes here. The
    profile's native28 field describes the retained base contract; the new
    root's native version is recorded separately and explicitly as30.
    """
    selected = profile(target)
    if base_manifest.get("family") != selected["board_family"]:
        raise ValueError("native successor requires the exact base family")
    size, digest = QUALIFIED_BASES[selected["board_family"]]
    if _pin(base) != {"bytes": size, "sha256": digest}:
        raise ValueError("exact independently qualified immutable base required")
    inspected = inspect_base(base, base_manifest, base_finalization)
    fs = SquashfsFiles(base)
    original = fs.inventory()
    inventory = {name: dict(row) for name, row in original.items()}
    destinations = {
        "dcentrald": "usr/local/bin/dcentrald",
        "dcentos-discovery": "usr/bin/dcentos-discovery",
        "dcentos-init": "sbin/init",
    }
    expected_native_names = set(destinations.values()) | {
        "etc/dcentos/" + name + ".sha256" for name in destinations
    }
    if (
        native_evidence.get("schema") != "dcentos.native_zynq_sd_successor_native.v1"
        or native_evidence.get("native_checkpoint") != 30
        or set(native_assets) != expected_native_names
        or set(native_evidence.get("executables", {})) != set(destinations)
    ):
        raise ValueError("complete admitted native30 asset set required")
    for name, destination in destinations.items():
        asset = native_assets[destination]
        expected = native_evidence["executables"][name]
        if _pin(asset.content) != expected or asset.mode != 0o755:
            raise ValueError("native successor asset differs from admission: " + name)
        marker = native_assets["etc/dcentos/" + name + ".sha256"]
        if marker.content != (expected["sha256"] + "\n").encode() or marker.mode != 0o644:
            raise ValueError("native successor executable digest marker differs")
    replacements = source_assets(source_root, target)
    if set(replacements) & set(native_assets):
        raise ValueError("source overlay cannot replace a native executable asset")
    replacements.update(native_assets)
    replacements["etc/issue"] = Asset(b"DCENT_OS native30 private SD beta\n", 0o644)
    next_inode = max(row["inode"] for row in inventory.values()) + 1
    for name, asset in replacements.items():
        if (
            name.startswith("/")
            or any(part in ("", ".", "..") for part in name.split("/"))
            or not isinstance(asset.content, bytes)
            or not 0 < len(asset.content) <= 32 * 1024 * 1024
            or asset.mode not in (0o644, 0o755)
        ):
            raise ValueError("bounded canonical native root asset required")
        parent = posixpath.dirname(name)
        while parent:
            if inventory.get(parent, {}).get("kind") != 1:
                raise ValueError("asset requires existing direct root directories: " + name)
            parent = posixpath.dirname(parent)
        old = original.get(name)
        expected_links = 2 if name == "usr/local/bin/dcentrald" else 1
        if old is not None and (old["kind"] != 2 or old["nlink"] != expected_links):
            raise ValueError("asset replacement conflicts with existing type or link custody")
        if old is not None:
            inode = old["inode"]
        else:
            inode, next_inode = next_inode, next_inode + 1
        inventory[name] = {
            "kind": 2,
            "mode": asset.mode,
            "uid": 0,
            "gid": 0,
            "inode": inode,
            "nlink": expected_links,
            **_pin(asset.content),
        }
    inventory["usr/bin/dcentrald"] = dict(inventory["usr/local/bin/dcentrald"])
    changed = sorted(name for name in inventory if inventory[name] != original.get(name))
    allowed_changes = set(replacements) | {"usr/bin/dcentrald"}
    if not set(changed) <= allowed_changes:
        raise ValueError("unexpected successor root mutation")
    if set(original) - set(inventory):
        raise ValueError("successor root cannot silently remove base members")
    files = _PlannedFiles(fs, replacements)
    graph = runtime_dependencies(files, inventory)
    actual_elf_names = set(graph)
    if actual_elf_names != set(inspected["elf_dependencies"]):
        raise ValueError("unexpected executable/library set in successor root")
    evidence = {
        "schema": "dcentos.native_zynq_sd_successor_root_plan.v1",
        "board_target": target,
        "family": selected["board_family"],
        "native_checkpoint": 30,
        "base_native_checkpoint": 28,
        "base": _pin(base),
        "base_target": base_manifest["board_target"],
        "native": native_evidence,
        "changed_paths": changed,
        "added_paths": sorted(set(inventory) - set(original)),
        "overlay": {
            name: {
                **_pin(asset.content),
                "mode": asset.mode,
                "source": asset.source,
                "source_sha256": asset.source_sha256,
            }
            for name, asset in sorted(replacements.items())
        },
        "elf_dependencies": graph,
        "inventory": _pin((json.dumps(inventory, sort_keys=True) + "\n").encode()),
        "base_members_removed": False,
        "hardware_contact": False,
        "physical_qualification": "pending",
        "image_created": False,
    }
    return SuccessorRootPlan(target, base, inventory, replacements, evidence)
