#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Prepare a disposable ARM initramfs using official kernel modules and held tools."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
WORKSPACE = HERE.parents[3]
sys.path.insert(0, str(WORKSPACE / "projects/dcent-toolbox/src"))
sys.path.insert(0, str(HERE.parent))
from dcent_toolbox.core.am2_stock_recovery import PARTITIONS, PROC_MTD, MAGIC  # noqa: E402
from dcent_toolbox.core.am2_stock8_executor import stock8_defaults, HELD_CLOSURE  # noqa: E402
from dcent_toolbox.core.am2_first_install_executor import _sha  # noqa: E402


def base_guest(guest: Path, donor: Path, kernel: Path, harness: str,
               partitions: tuple, proc_mtd: bytes) -> Path:
    if guest.exists() or guest.is_symlink() or not guest.is_absolute():
        raise ValueError("guest must be a new absolute directory")
    guest.mkdir()
    subprocess.run(["cp", "-a", str(donor) + "/.", str(guest)], check=True)
    for name in ("dev", "proc", "sys", "tmp"):
        (guest / name).mkdir(exist_ok=True)
    modules = kernel / "lib/modules/6.1.0-52-armmp"
    for suffix in ("kernel/drivers/mtd/nand/raw/nandsim.ko", "kernel/lib/crc16.ko",
                   "kernel/drivers/mtd/ubi/ubi.ko", "kernel/fs/ubifs/ubifs.ko",
                   "kernel/lib/zstd/zstd_compress.ko", "kernel/crypto/zstd.ko",
                   "kernel/crypto/deflate.ko"):
        path = guest / "lib/modules/6.1.0-52-armmp" / suffix
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(modules / suffix, path)
    (guest / "init").write_bytes((HERE / harness).read_bytes())
    (guest / "init").chmod(0o755)
    identity = guest / "i01"
    inputs = identity / "inputs"
    inputs.mkdir(parents=True)
    (identity / "FIXTURE").write_text("dcent-i01-arm-kernel-ordinary-identity-v1\n")
    (identity / "proc-mtd").write_bytes(proc_mtd)
    (identity / "cmdline").write_text("console=ttyAMA0 root=/dev/ram0 rootfstype=squashfs\n")
    (identity / "net/eth0").mkdir(parents=True)
    (identity / "net/eth0/address").write_text("02:00:00:00:00:01\n")
    for i, (name, _) in enumerate(partitions):
        (identity / f"name{i}").write_text(name + "\n")
    return inputs


def pack_guest(guest: Path) -> dict:
    names = subprocess.run(["find", ".", "-print0"], cwd=guest,
                           check=True, capture_output=True).stdout
    cpio = subprocess.run(["cpio", "--null", "-o", "--format=newc"], cwd=guest,
                          input=names, check=True, capture_output=True).stdout
    archive = guest.with_name(guest.name + ".cpio.gz")
    raw = gzip.compress(cpio, compresslevel=1, mtime=0)
    with archive.open("xb") as handle:
        handle.write(raw)
    return dict(initramfs_path=str(archive), initramfs_sha256=_sha(raw), initramfs_bytes=len(raw))


def build(guest: Path, donor: Path, kernel: Path, tools: Path):
    inputs = base_guest(guest, donor, kernel, "am2_stock8_arm_guest.sh", PARTITIONS, PROC_MTD)
    identity = inputs.parent
    original = (b"original stock kernel fixture\n" * 65536).ljust(8388608, b"\xff")
    (identity / "original-kernel").write_bytes(original)
    compressed = gzip.compress(original, mtime=0)
    # Target stage1 binds the complete container plus original kernel digest;
    # the host container decoder is independently exercised with real backup.
    metadata = json.dumps({"fixture": True}).encode()
    backup = (MAGIC + struct.pack(">I", len(metadata)) + metadata).ljust(1048576, b"\xff") + compressed
    archive = WORKSPACE / ""
    with tarfile.open(archive) as tar:
        bitstream = tar.extractfile("firmware/system.bit.gz").read()
    # The stage1 only writes this bounded recovery container. Bootstrap and
    # stage2 execution belong to the companion dual-map ARM guest phase.
    migration = b"stock8 stage1 migration fixture".ljust(1048576 + 10240, b"\0")
    files = {"stage1.sh": (WORKSPACE / "projects/dcent-toolbox/src/dcent_toolbox/_am2_first_install/stock8-stage1.sh").read_bytes(),
             "am2-nand-window": (tools / "am2-nand-window-armv7").read_bytes(),
             "transition.itb": (tools / "stock8-recovery-template-v1.itb").read_bytes(),
             "system.bit.gz": bitstream, "kernel-backup.container": backup,
             "migration.container": migration,
             "fw_printenv": (donor / "usr/sbin/fw_printenv").read_bytes(),
             "fw_setenv": (donor / "usr/sbin/fw_printenv").read_bytes(),
             "ld-musl-armhf.so.1": (donor / "lib/libc.so").read_bytes(),
             "libc.so": (donor / "lib/libc.so").read_bytes(),
             "libgcc_s.so.1": (donor / "lib/libgcc_s.so.1").read_bytes()}
    for name, digest in HELD_CLOSURE.items():
        if _sha(files[name]) != digest:
            raise ValueError("held environment closure differs")
    files["env.defaults"] = stock8_defaults((HERE / "stock8-boot-defaults.env").read_bytes(),
        mac="02:00:00:00:00:01", hwid="fixture123", anchor="a" * 64, network={})
    request = {"schema": "dcentos.am2-stock8-stage1-request.v1", "source": "stock-8part-single-slot",
               "mac": "02:00:00:00:00:01", "hwid": "fixture123", "board_target": "am2-s19jpro-zynq",
               "original_kernel_sha256": _sha(original), "migration_request_sha256": "a" * 64}
    for name, key in (("am2-nand-window", "writer"), ("transition.itb", "transition"),
                      ("system.bit.gz", "recovery_fpga"), ("kernel-backup.container", "kernel_backup"),
                      ("migration.container", "migration"), ("env.defaults", "defaults"),
                      ("fw_printenv", "fw_tool"), ("ld-musl-armhf.so.1", "loader"),
                      ("libc.so", "libc"), ("libgcc_s.so.1", "libgcc")):
        request[key + "_sha256"] = _sha(files[name])
    files["request"] = "".join(f"{key}={value}\n" for key, value in sorted(request.items())).encode()
    for name, raw in files.items():
        (inputs / name).write_bytes(raw)
    return {"kernel_sha256": _sha((kernel / "boot/vmlinuz-6.1.0-52-armmp").read_bytes()),
            "files": {name: _sha(raw) for name, raw in files.items()},
            "harness_sha256": _sha((guest / "init").read_bytes())}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("guest", "donor", "kernel", "tools"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--pack", action="store_true")
    args = parser.parse_args()
    report = build(args.guest, args.donor, args.kernel, args.tools)
    if args.pack:
        report.update(pack_guest(args.guest))
    print(json.dumps(report, indent=2))
