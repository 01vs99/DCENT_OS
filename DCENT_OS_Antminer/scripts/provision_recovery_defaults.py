#!/usr/bin/env python3
"""Stage the exact mining-off image default and bounded About metadata."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


def provision(root, *, git_sha=None, drop=None):
    root = root.resolve(strict=True)
    source = root / "etc/dcentrald.toml"
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError("reset default requires the final regular image configuration")
    content = source.read_bytes()
    parsed = tomllib.loads(content.decode())
    if parsed.get("mining", {}).get("enabled") is not False:
        raise ValueError("reset default must explicitly disable mining")
    if git_sha is not None and not re.fullmatch(r"[0-9a-f]{40}", git_sha):
        raise ValueError("invalid authenticated source revision")
    if drop is not None and drop not in ("1", "2", "3"):
        raise ValueError("release drop must be an assigned cumulative drop 1, 2 or 3")
    outputs = {
        "usr/share/dcentos/default-dcentrald.toml": content,
        "etc/dcentos/build-info.json": (json.dumps({"git_sha": git_sha, "drop": drop}, sort_keys=True) + "\n").encode(),
    }
    for relative, value in outputs.items():
        path = root
        for component in Path(relative).parts[:-1]:
            path /= component
            if path.exists() or path.is_symlink():
                if not stat.S_ISDIR(path.lstat().st_mode):
                    raise ValueError(f"unsafe recovery provision directory: {path}")
            else:
                path.mkdir(mode=0o755)
        destination = root / relative
        if destination.exists() or destination.is_symlink():
            if not stat.S_ISREG(destination.lstat().st_mode) or destination.stat().st_nlink != 1:
                raise ValueError(f"unsafe recovery provision output: {destination}")
        destination.write_bytes(value)
        destination.chmod(0o644)
    return outputs


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rootfs", type=Path, required=True)
    args = parser.parse_args()
    try:
        provision(args.rootfs, git_sha=os.environ.get("DCENT_SOURCE_COMMIT") or os.environ.get("DCENT_CAPSULE_SOURCE_COMMIT"),
                  drop=os.environ.get("DCENT_RELEASE_DROP") or None)
    except (OSError, ValueError) as error:
        parser.exit(1, f"recovery defaults refused: {error}\n")
