"""Materialize a successor plan into one new private ordinary-file root.

No base tree is changed. No mount, chroot, target executable, special node or
physical device is used. Partial output and a failure receipt are retained.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import posixpath
import stat

from dcent_toolbox.core.squashfs_files import SquashfsFiles

from .boot_assets import EPOCH
from .successor_root import SuccessorRootPlan, _PlannedFiles


def _pin(raw: bytes) -> dict:
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def inspect_materialized(root: Path, wanted: dict) -> dict:
    """Read every actual member, without following any image symlink."""
    pending = [root]
    observed = {}
    actual_groups = {}
    expected_groups = {}
    for name, expected in wanted.items():
        if expected["kind"] == 2:
            expected_groups.setdefault(expected["inode"], []).append(name)
    while pending:
        path = pending.pop()
        before = path.lstat()
        name = path.relative_to(root).as_posix() if path != root else ""
        expected = wanted.get(name)
        if expected is None:
            raise ValueError("unexpected materialized root member: " + name)
        if stat.S_ISDIR(before.st_mode):
            kind = 1
            pending.extend(path.iterdir())
        elif stat.S_ISREG(before.st_mode):
            kind = 2
        elif stat.S_ISLNK(before.st_mode):
            kind = 3
        else:
            raise ValueError("materialized root contains a special node")
        row = {
            "kind": kind,
            "mode": stat.S_IMODE(before.st_mode),
            "uid": before.st_uid,
            "gid": before.st_gid,
            "nlink": before.st_nlink,
        }
        if kind == 2:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                opened = os.fstat(stream.fileno())
                if not os.path.samestat(before, opened) or not stat.S_ISREG(opened.st_mode):
                    raise ValueError("materialized member changed while opening")
                raw = stream.read(expected["bytes"] + 1)
                after = os.fstat(stream.fileno())
            if (
                len(raw) != before.st_size
                or opened.st_size != after.st_size
                or opened.st_mtime_ns != after.st_mtime_ns
                or opened.st_ctime_ns != after.st_ctime_ns
                or not os.path.samestat(after, path.lstat())
            ):
                raise ValueError("materialized member changed while reading")
            row.update(_pin(raw))
            actual_groups.setdefault((before.st_dev, before.st_ino), []).append(name)
        elif kind == 3:
            row["target_hex"] = os.fsencode(os.readlink(path)).hex()
        if row != {key: expected[key] for key in row}:
            raise ValueError("materialized member differs from plan: " + name)
        if int(before.st_mtime) != EPOCH:
            raise ValueError("materialized root timestamp differs: " + name)
        observed[name] = row
    if set(observed) != set(wanted):
        raise ValueError("materialized root is incomplete")
    expected_links = sorted(sorted(names) for names in expected_groups.values())
    actual_links = sorted(sorted(names) for names in actual_groups.values())
    if actual_links != expected_links:
        raise ValueError("materialized inode groups differ from image custody")
    return {"entries": len(observed), "actual_metadata_content_and_links_equal": True,
            "files": sum(row["kind"] == 2 for row in observed.values()),
            "symlinks": sum(row["kind"] == 3 for row in observed.values()),
            "hardlink_groups": [names for names in actual_links if len(names) > 1]}


def materialize_successor_root(plan: SuccessorRootPlan, job_root: Path) -> dict:
    if os.name != "posix" or os.geteuid() != 0:
        raise ValueError("Linux root-owned image preparation required")
    job_root = Path(job_root)
    before_job = job_root.lstat()
    if (
        not job_root.is_absolute()
        or not stat.S_ISDIR(before_job.st_mode)
        or before_job.st_uid != 0
        or stat.S_IMODE(before_job.st_mode) != 0o700
        or job_root.resolve() != job_root
    ):
        raise ValueError("direct absolute private root-owned job directory required")
    root = job_root / "root"
    receipt = job_root / "root-materialization.json"
    if root.exists() or root.is_symlink() or receipt.exists() or receipt.is_symlink():
        raise ValueError("preserve previous output; a new private job is required")
    wanted = plan.inventory
    if (
        wanted.get("", {}).get("kind") != 1
        or _pin((json.dumps(wanted, sort_keys=True) + "\n").encode())
        != plan.evidence.get("inventory")
        or _pin(plan.base) != plan.evidence.get("base")
    ):
        raise ValueError("complete root plan required")
    # Refuse malformed paths and parents before writing any root member.
    for name, row in wanted.items():
        if name and (name.startswith("/") or any(p in ("", ".", "..") for p in name.split("/"))):
            raise ValueError("canonical root-relative plan member required")
        if row["kind"] not in (1, 2, 3):
            raise ValueError("ordinary files, directories and symlinks only")
        if name and wanted.get(posixpath.dirname(name), {}).get("kind") != 1:
            raise ValueError("every planned parent must be a direct directory")
    root.mkdir(mode=0o700)
    result = {"schema": "dcentos.native_zynq_sd_root_materialization.v1",
              "status": "RUNNING", "board_target": plan.target,
              "root": str(root), "epoch": EPOCH, "hardware_contact": False,
              "source_plan": _pin((json.dumps(plan.evidence, sort_keys=True) + "\n").encode())}
    try:
        directories = [name for name, row in wanted.items() if name and row["kind"] == 1]
        for name in sorted(directories, key=lambda value: (value.count("/"), value)):
            (root / name).mkdir(mode=0o700)
        files = _PlannedFiles(SquashfsFiles(plan.base), plan.replacements)
        groups = {}
        for name, row in wanted.items():
            if row["kind"] == 2:
                groups.setdefault(row["inode"], []).append(name)
        for members in groups.values():
            members.sort()
            leader = "usr/local/bin/dcentrald" if "usr/local/bin/dcentrald" in members else members[0]
            expected = wanted[leader]
            if len(members) != expected["nlink"] or any(wanted[name] != expected for name in members):
                raise ValueError("planned hardlink group differs")
            raw = files.read(leader)
            if _pin(raw) != {key: expected[key] for key in ("bytes", "sha256")}:
                raise ValueError("planned source content changed before materialization")
            primary = root / leader
            with primary.open("xb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.chown(primary, expected["uid"], expected["gid"])
            os.chmod(primary, expected["mode"])
            for name in members:
                if name != leader:
                    os.link(primary, root / name, follow_symlinks=False)
        for name, row in wanted.items():
            if row["kind"] == 3:
                if row["mode"] != 0o777 or row["nlink"] != 1:
                    raise ValueError("unsupported symlink mode or hardlink group")
                os.symlink(os.fsdecode(bytes.fromhex(row["target_hex"])), root / name)
                os.chown(root / name, row["uid"], row["gid"], follow_symlinks=False)
        # Set directory permissions only after all children exist, then set all
        # timestamps last so child creation cannot change a recorded directory.
        for name in sorted([""] + directories, key=lambda value: value.count("/"), reverse=True):
            os.chown(root / name, wanted[name]["uid"], wanted[name]["gid"])
            os.chmod(root / name, wanted[name]["mode"])
        for name in wanted:
            os.utime(root / name, (EPOCH, EPOCH), follow_symlinks=False)
        result["inspection"] = inspect_materialized(root, wanted)
        if not os.path.samestat(before_job, job_root.lstat()):
            raise ValueError("private job directory changed")
        result["status"] = "PASS"
    except BaseException as error:
        result.update(status="FAIL", error=repr(error))
        raise
    finally:
        with receipt.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    return result
