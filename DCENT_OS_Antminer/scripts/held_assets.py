#!/usr/bin/env python3
"""Resolve held firmware paths without weakening their independent pins."""
from __future__ import annotations

import argparse
import os
from pathlib import Path, PurePosixPath
import subprocess


def held_root(repo_root: Path, override: str | None = None) -> Path:
    value = override if override is not None else os.environ.get("DCENT_HELD_ASSETS")
    if value is not None:
        candidate = Path(value)
        if not candidate.is_absolute():
            raise ValueError("DCENT_HELD_ASSETS must be an absolute knowledge-base directory")
    else:
        # Linked worktrees share the main checkout's held assets. Native Git
        # cannot read Windows worktree metadata from WSL; git.exe is read-only.
        common = None
        for executable in ("git", "git.exe"):
            try:
                result = subprocess.run([executable, "rev-parse",
                                         "--path-format=absolute", "--git-common-dir"],
                                        cwd=repo_root, capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                continue
            if result.returncode == 0:
                common = result.stdout.strip().replace("\\", "/")
                if os.name != "nt" and len(common) > 2 and common[1:3] == ":/":
                    common = "/mnt/" + common[0].lower() + common[2:]
                break
        candidate = Path(common).parent / "knowledge-base" if common else repo_root / "knowledge-base"
    if not candidate.is_dir() or candidate.is_symlink():
        raise ValueError(f"held asset directory is absent or linked: {candidate}; set DCENT_HELD_ASSETS")
    return candidate.absolute()


def input_location(repo_root: Path, relative: str, assets: Path | None) -> tuple[Path, str]:
    path = PurePosixPath(relative)
    if (not path.parts or path.is_absolute() or path.as_posix() != relative
            or any(part in ("", ".", "..") for part in relative.split("/")) or "\\" in relative or ":" in relative):
        raise ValueError("held asset input must use a canonical repository-relative path")
    if assets is not None and path.parts[0] == "knowledge-base":
        if len(path.parts) == 1:
            raise ValueError("held asset input must name a file")
        return assets, PurePosixPath(*path.parts[1:]).as_posix()
    return repo_root, relative


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(held_root(args.repo_root))
    except ValueError as error:
        parser.exit(2, f"ERROR: {error}\n")


if __name__ == "__main__":
    main()
