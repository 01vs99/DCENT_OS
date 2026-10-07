#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build the isolated ARM stage2 guest with an actual AM2 kernel/rootfs/FIT."""
from __future__ import annotations

import argparse
import gzip
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile

from prepare_am2_arm_guest import HERE, WORKSPACE, base_guest, pack_guest
from dcent_toolbox.core.am2_first_install_executor import (
    EXPECTED_PARTITIONS, _sha, validate_kernel_image, validate_rootfs_image,
    validate_fpga_image,
)
from dcent_toolbox.core.am2_stock8_executor import stock8_defaults
from dcent_toolbox.core.am2_stock_payload import build_stock_migration
from dcent_toolbox.core.am2_stock_recovery import MAGIC
from dcent_toolbox.core import am2_stock_recovery as stock
from dcent_toolbox.core.am2_stock_restore import WINDOWS, RESTORE_SCRIPT, build_stock_restore_plan
from prepare_am2_fabric_boot import nand_boot_environment, prepare


def build(guest: Path, donor: Path, kernel: Path, tools: Path, rootfs: Path,
          full_restore: bool = False) -> dict:
    proc = ('dev:    size   erasesize  name\n' + ''.join(
        f'mtd{i}: {size:08x} 00020000 "{name}"\n'
        for i, (name, size) in enumerate(EXPECTED_PARTITIONS))).encode()
    inputs = base_guest(guest, donor, kernel, "am2_stock8_stage2_arm_guest.sh",
                        EXPECTED_PARTITIONS, proc)
    identity = inputs.parent
    for source, destination in (
        (tools / "am2-nand-window-armv7", guest / "usr/libexec/dcent-am2-nand-window"),
        (HERE / "am2_stock_bootstrap.sh", guest / "usr/sbin/dcent-stock-bootstrap"),
        (HERE / "am2_stock_stage2.sh", guest / "usr/sbin/dcent-stock-stage2"),
    ):
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        destination.chmod(0o755)
    archive = WORKSPACE / ""
    with tarfile.open(archive) as tar:
        bitstream = tar.extractfile("firmware/system.bit.gz").read()
    (identity / "system.bit.gz").write_bytes(bitstream)
    uenv = identity / "uEnv.txt"
    uenv.write_text("bm_load_bitstream=fixture\nbm_set_bootargs=fixture\nsd_uenvcmd=fixture\n")
    fabric = prepare(identity / "system.bit.gz", identity / "fabric", uenv, "/usr/local/bin/mkimage")
    old = WORKSPACE / "DCENT_OS_Antminer/output/beta-xil-20260617/DCENTOS_XIL3_S19jPro_beta20260617.tar"
    with tarfile.open(old) as tar:
        kernel_raw = tar.extractfile("sysupgrade-am2-s19j/kernel").read()
    validate_kernel_image(kernel_raw)
    rootfs_raw = rootfs.read_bytes()
    validate_rootfs_image(rootfs_raw)
    validate_fpga_image(fabric.read_bytes())
    original = (b"original stock kernel fixture\n" * 65536).ljust(8388608, b"\xff")
    (identity / "original-kernel").write_bytes(original)
    metadata = json.dumps({"fixture": True}).encode()
    backup = (MAGIC + struct.pack(">I", len(metadata)) + metadata).ljust(1048576, b"\xff") + gzip.compress(original, mtime=0)
    (identity / "kernel-backup.container").write_bytes(backup)
    # Disposable guest-only SSH identity. No private key is reused by a miner.
    hostkey = identity / "ssh-host-rsa"
    qemu = shutil.which("qemu-arm") or shutil.which("qemu-arm-static")
    if qemu is None:
        raise ValueError("ARM user emulator required only to generate a disposable host key")
    subprocess.run([qemu, "-L", str(guest), str(guest / "usr/bin/dropbearkey"),
                    "-t", "rsa", "-s", "1024", "-f", str(hostkey)], check=True,
                   stdout=subprocess.DEVNULL)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    public = Ed25519PrivateKey.from_private_bytes(bytes([1]) * 32).public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH) + b"\n"
    boot = nand_boot_environment(1, "run nandboot_recovery")
    payloads = {"kernel": kernel_raw, "rootfs": rootfs_raw, "am2-fabric.itb": fabric.read_bytes(),
                "dcentrald.toml": b'[mining]\nenabled = false\n',
                "env.boot": ''.join(f'{k} {v}\n' for k, v in sorted(boot.items())).encode(),
                "ssh-authorized_keys": public, "ssh-host-rsa": hostkey.read_bytes(),
                "ssh-host-ed25519": b"", "network-static": b"IP=192.0.2.10\nMASK=255.255.255.0\nGW=192.0.2.1\nDNS=192.0.2.53\n"}
    migration, anchor = build_stock_migration(payloads, board_target="am2-s19jpro-zynq",
        mac="02:00:00:00:00:01", hwid="fixture123", kernel_backup_sha256=_sha(backup),
        kernel_backup_size=len(backup), original_kernel_sha256=_sha(original))
    (identity / "migration.container").write_bytes(migration)
    (identity / "anchor").write_text(anchor + "\n")
    defaults = stock8_defaults((HERE / "stock8-boot-defaults.env").read_bytes(),
        mac="02:00:00:00:00:01", hwid="fixture123", anchor=anchor, network={})
    (identity / "env.defaults").write_bytes(defaults)
    for name, raw in payloads.items():
        (inputs / name).write_bytes(raw)
    if full_restore:
        prepare_restore(guest, donor, tools, original, anchor)
    return {"kernel_sha256": _sha((kernel / "boot/vmlinuz-6.1.0-52-armmp").read_bytes()),
            "harness_sha256": _sha((guest / "init").read_bytes()),
            "bootstrap_sha256": _sha((HERE / "am2_stock_bootstrap.sh").read_bytes()),
            "stage2_sha256": _sha((HERE / "am2_stock_stage2.sh").read_bytes()),
            "migration_sha256": _sha(migration), "anchor": anchor,
            "payloads": {name: {"sha256": _sha(raw), "bytes": len(raw)} for name, raw in payloads.items()}}


def prepare_restore(guest: Path, donor: Path, tools: Path, original: bytes, anchor: str) -> None:
    """Use a complete retained source fixture to drive the actual replay script.

    Source BOOT bytes are real and pinned; rootfs/ramfs/config source regions
    are erased fixture data, so this proves NAND replay, not a stock OS boot.
    """
    source = guest.with_name(guest.name + "-stock-backup")
    source.mkdir()
    full = source / "full_nand"
    full.mkdir()
    boot = (WORKSPACE / "").read_bytes()
    for i, (_, size) in enumerate(stock.PARTITIONS):
        with (full / f"mtd{i}.bin").open("xb") as handle:
            for _ in range(size // stock.MIB):
                handle.write(b"\xff" * stock.MIB)
    with (full / "mtd0.bin").open("r+b") as handle:
        handle.write(boot)
        handle.seek(32*stock.MIB)
        handle.write(original)
    manifest = {"schema": stock.BACKUP_SCHEMA, "source_layout": stock.SOURCE_STOCK_8PART,
        "board_target": "am2-s19jpro-zynq", "mac": "02:00:00:00:00:01",
        "proc_mtd_sha256": stock.PROC_MTD_SHA256,
        "partitions": [{"dev": f"/dev/mtd{i}", "name": name, "size_bytes": size,
            "erasesize": 131072, "path": f"full_nand/mtd{i}.bin", "sha256": stock._file_sha(full/f"mtd{i}.bin")}
            for i, (name, size) in enumerate(stock.PARTITIONS)]}
    (source / stock.BACKUP_MANIFEST).write_text(json.dumps(manifest))
    plan = build_stock_restore_plan(source, "am2-s19jpro-zynq", "02:00:00:00:00:01")
    (source / "restore-plan.json").write_text(json.dumps(plan, indent=2))
    identity = guest / "i01"
    staged = identity / "restore"
    staged.mkdir()
    files = {"am2-nand-window": (tools/"am2-nand-window-armv7").read_bytes(),
             "restore.sh": RESTORE_SCRIPT.read_bytes(), "env.restore": plan["environment"].encode(),
             "fw_printenv": (donor/"usr/sbin/fw_printenv").read_bytes(),
             "fw_setenv": (donor/"usr/sbin/fw_printenv").read_bytes(),
             "ld-musl-armhf.so.1": (donor/"lib/libc.so").read_bytes(),
             "libc.so": (donor/"lib/libc.so").read_bytes(),
             "libgcc_s.so.1": (donor/"lib/libgcc_s.so.1").read_bytes()}
    request = {"schema": "dcentos.am2-stock8-restore-request.v1", "mac": "02:00:00:00:00:01",
        "hwid": "fixture123", "backup_sha256": plan["backup_sha256"], "installation_sha256": anchor}
    keys = {"writer": "am2-nand-window", "fw_tool": "fw_printenv", "loader": "ld-musl-armhf.so.1",
            "libc": "libc.so", "libgcc": "libgcc_s.so.1", "environment": "env.restore"}
    request.update({key + "_sha256": _sha(files[name]) for key, name in keys.items()})
    request.update({row["name"].replace("-", "_") + "_sha256": row["sha256"] for row in plan["windows"]})
    files["request"] = ''.join(f'{key}={value}\n' for key, value in sorted(request.items())).encode()
    for name, raw in files.items():
        (staged/name).write_bytes(raw)
    (identity / "stock-BOOT.bin").write_bytes(boot)
    (identity / "restore-windows").write_text(''.join(f'{w.name} {w.size}\n' for w in WINDOWS if not w.preserve))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("guest", "donor", "kernel", "tools", "rootfs"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--pack", action="store_true")
    parser.add_argument("--full-restore", action="store_true")
    args = parser.parse_args()
    report = build(args.guest, args.donor, args.kernel, args.tools, args.rootfs, args.full_restore)
    if args.pack:
        report.update(pack_guest(args.guest))
    print(json.dumps(report, indent=2))
