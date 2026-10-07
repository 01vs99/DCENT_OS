#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build and bind the native/nandsim and standalone ARM stock-window tools."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

SOURCE = Path(__file__).with_name("am2_nand_window.c")
SCHEMA = "dcentos.am2-stock-window-tool-bundle.v1"
NAMES = ("am2-nand-window", "am2-nand-window-armv7")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def arm_contract(path: Path) -> None:
    data = path.read_bytes()
    if len(data) < 52 or data[:6] != b"\x7fELF\x01\x01":
        raise ValueError("ARM tool must be ELF32 little-endian")
    machine = struct.unpack_from("<H", data, 18)[0]
    flags = struct.unpack_from("<I", data, 36)[0]
    offset = struct.unpack_from("<I", data, 28)[0]
    size, count = struct.unpack_from("<HH", data, 42)
    if machine != 40 or flags & 0x400 == 0 or size != 32 or not count:
        raise ValueError("ARM tool requires ARM EABI hard-float program headers")
    if offset + size * count > len(data):
        raise ValueError("truncated ARM program headers")
    if any(struct.unpack_from("<I", data, offset + i * size)[0] in {2, 3}
           for i in range(count)):
        raise ValueError("ARM tool must have no dynamic segment or interpreter")


def verify(output: Path) -> dict:
    data = json.loads((output / "manifest.json").read_text())
    if data.get("schema") != SCHEMA or data.get("source_sha256") != sha(SOURCE):
        raise ValueError("stock-window source differs from the compiled bundle")
    artifacts = data.get("artifacts", [])
    if [row.get("name") for row in artifacts] != list(NAMES):
        raise ValueError("stock-window artifact inventory differs")
    for row in artifacts:
        path = output / row["name"]
        if path.is_symlink() or not path.is_file() or sha(path) != row["sha256"]:
            raise ValueError("stock-window executable differs from build receipt")
    arm_contract(output / NAMES[1])
    return data


def build(output: Path, native_cc: str, arm_cc: str) -> dict:
    output.mkdir(parents=True, exist_ok=True)
    source_sha = sha(SOURCE)
    common = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2"]
    artifacts = []
    for name, compiler, flags in (
        (NAMES[0], native_cc, common),
        (NAMES[1], arm_cc, common + ["-static", "-march=armv7-a",
                                    "-mfpu=vfpv3-d16", "-mfloat-abi=hard"]),
    ):
        resolved = shutil.which(compiler)
        if not resolved:
            raise ValueError(f"missing compiler: {compiler}")
        version = subprocess.check_output([resolved, "--version"], text=True).splitlines()[0]
        with tempfile.NamedTemporaryFile(dir=output, prefix=name + ".", delete=False) as file:
            temporary = Path(file.name)
        try:
            command = [resolved, *flags, str(SOURCE), "-o", str(temporary)]
            subprocess.run(command, check=True)
            if name == NAMES[1]:
                arm_contract(temporary)
            temporary.chmod(0o755)
            temporary.replace(output / name)
        finally:
            temporary.unlink(missing_ok=True)
        artifacts.append({"name": name, "sha256": sha(output / name),
                          "compiler": resolved, "compiler_version": version,
                          "compiler_sha256": sha(Path(resolved)), "flags": flags})
    if source_sha != sha(SOURCE):
        raise ValueError("source changed during compilation")
    data = {"schema": SCHEMA, "source_sha256": source_sha, "artifacts": artifacts}
    (output / "manifest.json").write_text(json.dumps(data, indent=2) + "\n")
    return verify(output)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--native-cc", default="gcc")
    parser.add_argument("--arm-cc", default="arm-linux-gnueabihf-gcc")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    data = (build(output, args.native_cc, args.arm_cc) if args.action == "build"
            else verify(output))
    print(json.dumps(data, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
