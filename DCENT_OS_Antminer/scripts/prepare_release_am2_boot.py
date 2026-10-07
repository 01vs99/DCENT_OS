#!/usr/bin/env python3
"""Reproduce the existing ten native AM2 boot pins from their held SD donor.

The donor's old root is discarded. Its exact kernel/DTB/SPL/U-Boot/FPGA inputs
are admitted by the existing parser, then the current checked fabric load
transform is applied. No device, mount, historical temporary output or signing
key is accessed. Existing final pins are checked before publishing the files.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import zlib

import extract_am2_s17_kernel as donor_parser
from native_zynq_sd.boot_assets import AM2_BOOT_PINS

SCRIPTS = Path(__file__).resolve().parent
# Existing pinned generated headers, reproduced deliberately. These are build
# timestamps inside boot containers, not a release date or physical claim.
KERNEL_TIMESTAMP = 1788821087
FABRIC_TIMESTAMP = 1788821088
# The am2-fabric.itb pin is the FIT exactly as built by this u-boot mkimage
# (2026-04-14 build, u-boot commit 5a998ab00758, staged sha256-pinned at
# toolchain-cache/u-boot-2026.04-mkimage/mkimage). FIT serialization differs
# across mkimage releases (drop1-20260919-4f5h9mgl: the capsule container's
# apt u-boot-tools 2022.01 emitted 896 structural bytes more than the pin),
# so byte-exact reproduction is only defined for this build.
MKIMAGE_PIN_VERSION = "mkimage version 2026.04-g5a998ab00758"
MKIMAGE_PIN_SHA256 = "998314bbd994aa5a8d37f089975f727e6500bce207dfda1322da0877c9b4c99d"


def legacy_kernel(kernel: bytes) -> bytes:
    if len(kernel) != donor_parser.KERNEL_SIZE or hashlib.sha256(kernel).hexdigest() != donor_parser.KERNEL_SHA256:
        raise ValueError("exact admitted AM2 kernel required")
    header = bytearray(struct.pack(">7I4B32s", 0x27051956, 0, KERNEL_TIMESTAMP, len(kernel),
                                  0x8000, 0x8000, zlib.crc32(kernel), 5, 2, 2, 0, b"DCENT_OS Linux 4.4.92"))
    struct.pack_into(">I", header, 4, zlib.crc32(header))
    return bytes(header) + kernel


def source_environment() -> bytes:
    # Reuse the current tracked producer's literal template without executing
    # its historical filesystem/build script or copying old prepared output.
    source = (SCRIPTS / "build_sd_s19pro.sh").read_text(encoding="utf-8")
    anchor = 'cat > "$WORKDIR/uEnv.txt" << \'UENV\'\n'
    if source.count(anchor) != 1:
        raise ValueError("unique tracked AM2 SD environment template required")
    following = source.split(anchor, 1)[1]
    if "\nUENV\n" not in following:
        raise ValueError("complete tracked AM2 SD environment template required")
    return (following.split("\nUENV\n", 1)[0] + "\n").encode()


def prepare(donor: Path, output: Path, *, mkimage="mkimage") -> dict:
    if output.exists() or output.is_symlink() or not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("new boot output inside a real existing directory required")
    kernel, dtb, _ = donor_parser.admit_donor(donor)
    raw = donor_parser._read_regular(donor, donor_parser.MAX_DONOR_BYTES, "AM2 release boot donor")
    if len(raw) != donor_parser.DONOR_SIZE or hashlib.sha256(raw).hexdigest() != donor_parser.DONOR_SHA256:
        raise ValueError("AM2 donor changed after admission")
    files = donor_parser._fat16_files(raw)
    del raw
    version = subprocess.run([mkimage, "-V"], capture_output=True, timeout=30)
    observed = version.stdout.decode("ascii", "replace").strip()
    if version.returncode or observed != MKIMAGE_PIN_VERSION:
        raise ValueError(
            "AM2 fabric FIT pins are only reproducible by the pinned mkimage "
            f"{MKIMAGE_PIN_VERSION} (toolchain-cache/u-boot-2026.04-mkimage, "
            f"sha256 {MKIMAGE_PIN_SHA256[:16]}…); this environment offers: "
            f"{observed or mkimage!r}"
        )
    with tempfile.TemporaryDirectory(prefix=".am2-release-boot-", dir=output.parent) as temporary:
        stage = Path(temporary)
        for source, name in (("BOOT.BIN", "boot.bin"), ("U-BOOT.IMG", "u-boot.img"),
                             ("SYSTEM.BIT.GZ", "system.bit.gz"), ("SYSTEM_BM.BIT.GZ", "system_bm.bit.gz"),
                             ("MINER.BTM", "miner.btm"), ("MINER.BTM.SIG", "miner.btm.sig")):
            (stage / name).write_bytes(files[source])
        (stage / "uImage").write_bytes(legacy_kernel(kernel))
        (stage / "devicetree.dtb").write_bytes(dtb)
        (stage / "uEnv.txt").write_bytes(source_environment())
        completed = subprocess.run([sys.executable, str(SCRIPTS / "prepare_am2_fabric_boot.py"),
                                    "--bitstream-gzip", str(stage / "system.bit.gz"), "--output-dir", str(stage),
                                    "--uenv", str(stage / "uEnv.txt"), "--mkimage", mkimage],
                                   env={**os.environ, "SOURCE_DATE_EPOCH": str(FABRIC_TIMESTAMP)},
                                   capture_output=True, timeout=60)
        if completed.returncode:
            raise ValueError("exact AM2 fabric transform failed: " + completed.stderr.decode(errors="replace"))
        checked = {}
        for name, expected in AM2_BOOT_PINS.items():
            content = (stage / name).read_bytes()
            actual = len(content), hashlib.sha256(content).hexdigest()
            if actual != expected:
                raise ValueError(f"reproduced AM2 boot member differs from existing pin: {name} {actual}")
            checked[name] = {"bytes": actual[0], "sha256": actual[1]}
        output.mkdir(mode=0o700)
        for name in checked:
            os.replace(stage / name, output / name)
    return checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donor", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mkimage", default="mkimage")
    args = parser.parse_args()
    try:
        prepare(args.donor, args.output, mkimage=args.mkimage)
        print("Reproduced all ten exact native AM2 boot components")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: native AM2 boot preparation: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
