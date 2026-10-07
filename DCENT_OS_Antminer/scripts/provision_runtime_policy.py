#!/usr/bin/env python3
"""Install exact boot/daemon/storage capabilities from the typed registry export."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

PROJECT = Path(__file__).resolve().parent.parent
POLICY = PROJECT / "docs/architecture/board_runtime_policy.json"
HELPER = PROJECT / "br2_external_dcentos/board/amlogic/rootfs-overlay/usr/libexec/dcentos/mutation-policy.sh"
SCHEMA = "dcentos-board-runtime-policy/v1"
CAPABILITIES = {"boot_safeoff": "boot-safeoff", "daemon_hardware": "daemon-hardware", "ota_storage": "ota-storage"}
FIELDS = {"board_target", "release_channel", "persistent_update_allowed", "update_mechanism", *CAPABILITIES}


def read_file(path: Path, maximum: int) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= maximum:
        raise ValueError(f"bounded unique regular file required: {path}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_size) != (info.st_dev, info.st_ino, info.st_mode, info.st_size):
            raise ValueError("policy input changed while opening")
        result = stream.read(maximum + 1)
    if len(result) != info.st_size:
        raise ValueError("policy input changed while reading")
    return result


def load_policy(path: Path = POLICY) -> dict:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate runtime policy field: {key}")
            result[key] = value
        return result
    document = json.loads(read_file(path, 1024 * 1024), object_pairs_hook=unique)
    if not isinstance(document, dict) or set(document) != {"schema", "targets"} or document["schema"] != SCHEMA or not isinstance(document["targets"], list) or not document["targets"]:
        raise ValueError("invalid board runtime policy schema")
    rows = {}
    for row in document["targets"]:
        if not isinstance(row, dict) or set(row) != FIELDS:
            raise ValueError("invalid board runtime policy fields")
        target = row["board_target"]
        if not isinstance(target, str) or not target or len(target) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in target) or target in rows:
            raise ValueError("invalid or duplicate exact board target")
        if row["release_channel"] not in ("beta", "stable", "unsupported") or any(type(row[key]) is not bool for key in CAPABILITIES):
            raise ValueError("invalid runtime channel/capability")
        if row["release_channel"] == "unsupported" and row["daemon_hardware"]:
            raise ValueError("Unsupported board cannot gain daemon hardware")
        if type(row["persistent_update_allowed"]) is not bool or row["update_mechanism"] not in ("zynq_ubi_fw_setenv", "host_rootfs_window", "emmc_content_selector_evidence_only", "sd_image", "none"):
            raise ValueError("invalid persistent update mechanism/policy")
        if row["ota_storage"] != (row["persistent_update_allowed"] and row["update_mechanism"] == "zynq_ubi_fw_setenv"):
            raise ValueError("host storage policy cannot grant an on-target OTA writer")
        rows[target] = row
    return rows


def real_directory(root: Path, relative: str, *, create: bool = True) -> Path:
    current = root
    for part in relative.split("/"):
        current /= part
        if current.exists() or current.is_symlink():
            if not stat.S_ISDIR(current.lstat().st_mode):
                raise ValueError(f"real directory required: {current}")
        else:
            if not create:
                raise ValueError(f"required directory is missing: {current}")
            current.mkdir()
    return current


def replace_file(path: Path, data: bytes, mode: int) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".runtime-policy-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def provision(root: Path, *, policy: Path = POLICY, check: bool = False) -> dict:
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("rootfs must be a real directory")
    config = real_directory(root, "etc/dcentos", create=not check)
    board = read_file(config / "board_target", 128).decode("ascii").removesuffix("\n")
    rows = load_policy(policy)
    if board not in rows:
        raise ValueError(f"unregistered exact board target: {board}")
    row = rows[board]
    tokens = [token for key, token in CAPABILITIES.items() if row[key]]
    data = ("\n".join(tokens or ["management-only"]) + "\n").encode("ascii")
    helper = read_file(HELPER, 16384)
    destination = real_directory(root, "usr/libexec/dcentos", create=not check) / "mutation-policy.sh"
    if check:
        if read_file(config / "mutation_policy", 1024) != data or read_file(destination, 16384) != helper:
            raise ValueError("staged mutation policy/helper differs from typed registry export")
    else:
        replace_file(destination, helper, 0o644)
        replace_file(config / "mutation_policy", data, 0o644)
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("rootfs", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        print(json.dumps(provision(args.rootfs, check=args.check), sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(f"ERROR: runtime policy: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
