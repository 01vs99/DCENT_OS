"""Bind native30 executables for successors of the retained native28 SD bases.

The old base contract remains in profiles.py and inspect_base.py. This reader
requires the new source admission, completed build and actual artifact review;
it does not reclassify an old root, create an image or permit installation.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dcent_toolbox.core.arm_elf_dependencies import arm_elf_dependencies

from .assets import Asset, read_source

NAMES = ("dcentrald", "dcentos-discovery", "dcentos-init")


def _pin(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate native successor evidence field")
        result[key] = value
    return result


def native30_assets(
    directory: Path,
    *,
    source_manifest: bytes,
    source_admission: bytes,
    build_receipt: bytes,
    artifact_review: bytes,
) -> tuple[dict[str, Asset], dict]:
    """Read three exact reviewed ARMv7 binaries into memory with their joins.

    The caller must separately capture these evidence bytes and compose and
    inspect the actual successor root. Release authenticity is a separate
    catalog concern; local metadata is not a signing identity.
    """
    originals = (source_manifest, source_admission, build_receipt, artifact_review)
    if any(not 0 < len(raw) <= 2 * 1024 * 1024 for raw in originals):
        raise ValueError("bounded complete native successor evidence required")
    manifest, admission, build, review = (
        json.loads(raw, object_pairs_hook=_unique) for raw in originals
    )
    if not all(isinstance(item, dict) for item in (manifest, admission, build, review)):
        raise ValueError("native successor evidence objects required")
    expected_snapshot = "/root/dcent-beta-native-checkpoint30-source"
    expected_target = "armv7-unknown-linux-musleabihf"
    if (
        manifest.get("snapshot") != expected_snapshot
        or admission.get("status") != "PASS_NATIVE30_INPUT_ADMISSION"
        or admission.get("manifest") != _pin(source_manifest)
        or build.get("source_snapshot") != expected_snapshot
        or build.get("source_snapshot_manifest_sha256")
        != _pin(source_manifest)["sha256"]
        or type(build.get("exit_code")) is not int
        or build["exit_code"] != 0
        or review.get("passed") is not True
        or review.get("mode") != "armv7"
        or review.get("manifest") != _pin(source_manifest)
        or review.get("receipt") != _pin(build_receipt)
        or review.get("source_admission") != _pin(source_admission)
    ):
        raise ValueError("completed native30 source/build/actual-review join required")
    command = build.get("command")
    if (
        not isinstance(command, list)
        or command.count("--target") != 1
        or command[command.index("--target") + 1 :][:1] != [expected_target]
        or "--release" not in command
        or "--locked" not in command
    ):
        raise ValueError("exact locked release ARMv7 build required")
    artifacts = build.get("artifacts")
    if not isinstance(artifacts, list) or len(artifacts) != len(NAMES):
        raise ValueError("complete three-executable native successor set required")
    by_name = {}
    expected_parent = "/root/dcent-beta-native-checkpoint30-artifacts/" + expected_target
    for row in artifacts:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("canonical native artifact row required")
        declared = Path(row["path"])
        if declared.parent.as_posix() != expected_parent or declared.name in by_name:
            raise ValueError("native successor artifact path or uniqueness differs")
        by_name[declared.name] = row
    if set(by_name) != set(NAMES):
        raise ValueError("exact native successor executable names required")
    reviewed = review.get("artifacts")
    if not isinstance(reviewed, list) or len(reviewed) != len(NAMES):
        raise ValueError("actual review of all native successor executables required")
    reviewed_names = set()
    for row in reviewed:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("canonical reviewed artifact row required")
        name = Path(row["path"]).name
        if (
            name not in by_name
            or name in reviewed_names
            or row["path"] != by_name[name]["path"]
            or row.get("bytes") != by_name[name].get("bytes")
            or row.get("sha256") != by_name[name].get("sha256")
            or row.get("machine") != 40
            or row.get("static_elf") is not True
        ):
            raise ValueError("actual artifact review differs from native build")
        reviewed_names.add(name)
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("direct native successor input directory required")
    assets = {}
    evidence = {}
    for name in NAMES:
        raw = read_source(directory / name)
        expected = {key: by_name[name].get(key) for key in ("bytes", "sha256")}
        if _pin(raw) != expected:
            raise ValueError("native successor executable differs from build: " + name)
        elf = arm_elf_dependencies(raw)
        if (
            elf["elf_class"] != 32
            or elf["machine"] != 40
            or elf["interpreter"] is not None
            or elf["needed"]
            or elf["dynamic"]
        ):
            raise ValueError("static ARMv7 native successor required: " + name)
        destination = {
            "dcentrald": "usr/local/bin/dcentrald",
            "dcentos-discovery": "usr/bin/dcentos-discovery",
            "dcentos-init": "sbin/init",
        }[name]
        assets[destination] = Asset(raw, 0o755, name, expected["sha256"])
        assets["etc/dcentos/" + name + ".sha256"] = Asset(
            (expected["sha256"] + "\n").encode(), 0o644
        )
        evidence[name] = expected
    return assets, {
        "schema": "dcentos.native_zynq_sd_successor_native.v1",
        "native_checkpoint": 30,
        "source_manifest": _pin(source_manifest),
        "source_admission": _pin(source_admission),
        "build_receipt": _pin(build_receipt),
        "artifact_review": _pin(artifact_review),
        "executables": evidence,
        "release_authentication_verified": False,
        "physical_qualification": "pending",
    }
