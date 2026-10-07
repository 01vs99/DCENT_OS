"""Create one private regular-file pristine native SD data filesystem.

No device path or existing output is accepted. This calls mkfs only on a new
file in an owned 0700 job directory, then performs read-only e2fsck. It does
not mount the filesystem or assemble, install or authorize a complete card.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

from .profiles import DATA_BYTES, profile

EPOCH = 1700000000
MKFS_CONFIG = b"""[defaults]
    default_mntopts = acl,user_xattr
    enable_periodic_fsck = 0
    blocksize = 4096
    inode_size = 256
    inode_ratio = 16384
[fs_types]
    ext4 = {
        features = has_journal,extent,filetype,sparse_super,large_file,extra_isize
    }
    small = {
        inode_ratio = 4096
    }
"""


def _pin(path: Path) -> dict:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("direct unique regular input required: " + str(path))
    raw = path.read_bytes()
    after = path.lstat()

    def identity(item):
        return (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_uid,
            item.st_gid,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )

    if identity(info) != identity(after) or len(raw) != info.st_size:
        raise ValueError("private regular file changed while reading")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def _write_new(path: Path, raw: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def prepare_data(job: Path, target: str) -> dict:
    """Prepare a create-only Linux job in a direct caller-owned directory.

    The private build directory assumes no competing writer under the same
    user. Failed jobs and command logs are retained for review, never cleaned.
    """
    selected = profile(target)
    if os.name != "posix" or not job.is_absolute() or job.name in {"", ".", ".."}:
        raise ValueError("absolute new Linux job directory required")
    if job.parent.resolve(strict=True) != job.parent:
        raise ValueError("direct existing parent directory required")
    parent = job.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
        raise ValueError("caller-owned non-writable-by-others parent required")
    if job.exists() or job.is_symlink():
        raise ValueError("preserve prior data job")
    tools = {name: Path("/usr/sbin") / name for name in ("mke2fs", "e2fsck")}
    tool_pins = {
        name: {"path": str(path), **_pin(path)} for name, path in tools.items()
    }
    job.mkdir(mode=0o700)
    config = job / "mke2fs.conf"
    image = job / "data.ext4"
    _write_new(config, MKFS_CONFIG)
    with image.open("xb") as stream:
        stream.truncate(DATA_BYTES)
        stream.flush()
        os.fsync(stream.fileno())
    identity = selected["data_uuid"]
    commands = [
        [
            str(tools["mke2fs"]),
            "-q",
            "-F",
            "-t",
            "ext4",
            "-b",
            "4096",
            "-I",
            "256",
            "-N",
            "4096",
            "-m",
            "0",
            "-L",
            selected["data_label"],
            "-U",
            identity,
            "-O",
            "none,has_journal,extent,filetype,sparse_super,large_file,extra_isize",
            "-E",
            "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,nodiscard,hash_seed="
            + identity,
            str(image),
        ],
        [str(tools["e2fsck"]), "-f", "-n", str(image)],
    ]
    overrides = {
        "MKE2FS_CONFIG": str(config),
        "E2FSPROGS_FAKE_TIME": str(EPOCH),
        "LC_ALL": "C",
    }
    environment = {**os.environ, **overrides}
    results = []
    try:
        for index, command in enumerate(commands):
            before = _pin(image)
            before_info = image.lstat()
            log = job / f"command-{index}.log"
            began = time.monotonic()
            with log.open("xb") as stream:
                completed = subprocess.run(
                    command,
                    env=environment,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=60,
                )
            after = _pin(image)
            after_info = image.lstat()
            result = {
                "command": command,
                "exit_code": completed.returncode,
                "seconds": time.monotonic() - began,
                "log": {"path": str(log), **_pin(log)},
                "image_after": after,
                "read_only_image_unchanged": before == after if index else None,
            }
            results.append(result)
            if (before_info.st_dev, before_info.st_ino, before_info.st_size) != (
                after_info.st_dev,
                after_info.st_ino,
                after_info.st_size,
            ):
                raise ValueError("private image identity or size changed")
            if completed.returncode or (index and before != after):
                raise ValueError(
                    "data filesystem command failed or read-only check modified bytes"
                )
        for name, path in tools.items():
            if _pin(path) != {key: tool_pins[name][key] for key in ("bytes", "sha256")}:
                raise ValueError("filesystem tool changed during preparation")
        if config.read_bytes() != MKFS_CONFIG:
            raise ValueError("private mkfs configuration changed")
        result = {
            "schema": "dcentos.native_zynq_sd_data_producer.v1",
            "passed": True,
            "board_target": target,
            "profile": selected,
            "image": {"path": str(image), **_pin(image)},
            "config": {"path": str(config), **_pin(config)},
            "tools": tool_pins,
            "commands": results,
            "environment_overrides": overrides,
            "portable_reader_required": "dcentos.pristine_ext4_data.v1",
            "complete_card": False,
            "mount_performed": False,
            "device_io": False,
            "signing": False,
            "publication": False,
        }
    except Exception as exc:
        result = {
            "passed": False,
            "error": str(exc),
            "commands": results,
            "device_io": False,
        }
        _write_new(job / "failed.json", (json.dumps(result, indent=2) + "\n").encode())
        raise
    _write_new(job / "data-inputs.json", (json.dumps(result, indent=2) + "\n").encode())
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, epilog="Support DCENT_OS: https://d-central.tech/fund/"
    )
    parser.add_argument("--job", type=Path, required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    print(json.dumps(prepare_data(args.job, args.target), indent=2))
