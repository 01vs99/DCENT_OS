#!/usr/bin/env python3
"""Read exact release source identity, including Windows-created WSL worktrees."""
import argparse
from pathlib import Path
import re
import os
import subprocess
import sys

from source_snapshot import GitObjects, SnapshotError


def host_path_text(value: str) -> str:
    """Rewrite Git-Bash (MSYS) drive paths (/d/dir) and long-path prefixes.

    MSYS automatic argument conversion is per-argument and inconsistent on
    long release command lines (producer runs drop1-20260916-cyg3sjwi and
    drop1-20260917-gnscaudk; the same fix landed in rust_dependency_inventory
    commit b1ae659fa and source_closure commit 4fd3d8b0e). The repository
    root is admitted by GitObjects' strict real-directory check, so the
    type converter normalizes it at the parse layer before the spelling is
    consumed. POSIX and native inputs are returned unchanged; on non-Windows
    hosts this is the identity.
    """
    if os.name != "nt" or not isinstance(value, str):
        return value
    text = value
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("//?/UNC/"):
        text = "//" + text[8:]
    else:
        for prefix in ("\\\\?\\", "//?/"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
    if (
        len(text) >= 2
        and text[0] == "/"
        and text[1].isascii()
        and text[1].isalpha()
        and (len(text) == 2 or text[2] == "/")
    ):
        return text[1].upper() + ":/" + text[3:]
    return text


def host_path(value: str) -> Path:
    """argparse Path type normalized through host_path_text."""
    return Path(host_path_text(value))


def read_source(repo_root: Path, field: str, commit: str = "HEAD") -> str:
    if commit != "HEAD" and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit):
        raise SnapshotError("HEAD or one full commit object ID required")
    git = GitObjects(repo_root)
    if field == "git-common-dir":
        common = git._run(("rev-parse", "--path-format=absolute", "--git-common-dir")).decode(sys.getfilesystemencoding(), "strict").strip()
        if os.name != "nt" and len(common) > 2 and common[1] == ":":
            common = subprocess.run(("wslpath", "-u", common), capture_output=True,
                                    check=True).stdout.decode("utf-8", "strict").strip()
        common_path = Path(common)
        if not common_path.is_absolute() or common_path.is_symlink() or not common_path.is_dir():
            raise SnapshotError("Git common object directory must be an absolute real directory")
        return str(common_path)
    resolved = git._run(("rev-parse", "--verify", commit + "^{commit}")).decode("ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{" + str(git.oid_bytes * 2) + "}", resolved):
        raise SnapshotError("Git did not return one full commit object ID")
    if field == "commit":
        return resolved
    if field != "epoch":
        raise SnapshotError("unknown release source field")
    epoch = git._run(("show", "-s", "--format=%ct", resolved)).decode("ascii").strip()
    if not re.fullmatch(r"[0-9]+", epoch):
        raise SnapshotError("invalid source commit timestamp")
    return epoch


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=host_path)
    parser.add_argument("--field", required=True, choices=("commit", "epoch", "git-common-dir"))
    parser.add_argument("--commit", default="HEAD")
    args = parser.parse_args()
    try:
        print(read_source(args.repo_root, args.field, args.commit))
    except (SnapshotError, OSError, ValueError) as error:
        print("ERROR: release source: " + str(error), file=sys.stderr)
        raise SystemExit(2)
