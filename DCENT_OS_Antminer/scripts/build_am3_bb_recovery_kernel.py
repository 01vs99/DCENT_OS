#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Isolated, pinned-source BB RAM-recovery kernel producer; never flashes.

Produces a kernel without claiming carrier/image admission. An optional
historical S19J_IO DTB has its own exact-source gate; the dedicated BBCtrl RAM
recovery DTB has a separate source-comparing producer. A build receipt proves
source/config/artifact custody, not successful physical boot.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import zlib

SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR.parents[1]/"dcent-toolbox/src"))
from dcent_toolbox.core.flattened_device_tree import parse_fdt  # noqa: E402 - standalone monorepo bootstrap

VERSION = "5.4.242"
SOURCE_URL = "https://cdn.kernel.org/pub/linux/kernel/v5.x/linux-5.4.242.tar.xz"
# https://cdn.kernel.org/pub/linux/kernel/v5.x/sha256sums.asc
SOURCE_SHA256 = "142f9aed1c9f2e409dd72c5c490ad824dddf31f955ed2097d5989c4b5074fc28"
LOAD_PROFILE = "am335x-zimage32-fdt64-initrd80/v1"
MODEL = "BeagleBone_Black_v2.1 on S19J_IO_BOARD_V2_0"
REVIEWED_CARRIER_DTB_HASHES = frozenset({
    # Read-only live capture, pinned by am3-bb-s19jpro.hardware-contract.json.
    # This hash is not a claim that the original capture is retained locally.
    "574a6a9b3a9d540451f9a3dec9cc7a5e9e61dccd5531367605a7598e6308f38b",
})
SIZES = (0x20000, 0x20000, 0x20000, 0x20000, 0x1c0000, 0x20000,
         0x20000, 0x500000, 0x1400000, 0x200000, 0x200000, 0x6000000)
OFFSETS = (0, 0x20000, 0x40000, 0x60000, 0x80000, 0x240000, 0x260000,
           0x280000, 0x800000, 0x1c00000, 0x1e00000, 0x2000000)
NAMES = ("spl", "spl_backup1", "spl_backup2", "spl_backup3", "u-boot",
         "bootenv", "fdt", "kernel", "root", "config", "sig", "nvdata")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def carrier_dtb(data: bytes) -> None:
    dt = parse_fdt(data)
    if len(data) > 0x20000 or dt.ascii_string("/", "model") != MODEL:
        raise ValueError("exact reviewed S19J_IO_BOARD_V2_0 carrier DTB required")
    if sha(data) not in REVIEWED_CARRIER_DTB_HASHES:
        raise ValueError("carrier DTB lacks an independently reviewed source digest")
    nodes = {node.path: {prop.name: prop.value for prop in node.properties} for node in dt.nodes}
    gpmc = "/ocp/gpmc@50000000"
    nand = gpmc+"/nand@0,0"
    expected = {gpmc: {"reg": struct.pack(">II", 0x50000000, 0x1000000),
                       "ranges": struct.pack(">4I", 0, 0, 0x8000000, 0x10000000),
                       "compatible": b"ti,am3352-gpmc\0"},
                nand: {"reg": bytes(12)}}
    for path, properties in expected.items():
        if any(nodes.get(path, {}).get(key) != value for key, value in properties.items()):
            raise ValueError("reviewed recovery DTB NAND controller contract differs")
    partitions = [props for path, props in nodes.items() if path.startswith(nand+"/") and "reg" in props]
    if len(partitions) != 12:
        raise ValueError("exact twelve-partition recovery DTB required")
    observed = sorted((props.get("label"), props["reg"]) for props in partitions)
    wanted = sorted((name.encode()+b"\0", struct.pack(">II", offset, size))
                    for name, offset, size in zip(NAMES, OFFSETS, SIZES))
    if observed != wanted:
        raise ValueError("recovery DTB physical partition layout differs")


def config_values(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            result[line[2:-11]] = "n"
    return result


def verify_config(actual: str, fragment: str) -> None:
    values = config_values(actual)
    for key, expected in config_values(fragment).items():
        # Removed legacy compatibility symbols need no false positive; all
        # required metadata, storage and recovery runtime symbols are checked.
        if key == "CONFIG_PROC_DEVICETREE" and key not in values:
            continue
        if values.get(key, "n") != expected:
            raise ValueError(f"kernel configuration did not retain {key}={expected}")


def legacy_kernel(zimage: bytes, image: bytes) -> bytes:
    # Linux ARM zImage header has magic/start/end at offsets36/40/44. The
    # uncompressed Image bound leaves ample room below the64MiB external FDT,
    # including <=8MiB compressed-kernel relocation and decompressor scratch.
    if (not 48 <= len(zimage) <= 0x800000-64 or not 0 < len(image) <= 0x2000000 or
            struct.unpack_from("<I", zimage, 36)[0] != 0x016f2818):
        raise ValueError("kernel exceeds the reviewed modern zImage load profile")
    start, end = struct.unpack_from("<II", zimage, 40)
    if end <= start or end-start > len(zimage):
        raise ValueError("kernel zImage span differs")
    header = struct.pack(">7I4B32s", 0x27051956, 0, 0, len(zimage), 0x80008000,
                         0x80008000, zlib.crc32(zimage), 5, 2, 2, 0, b"DCENT BB recovery 5.4.242")
    return header[:4]+struct.pack(">I", zlib.crc32(header))+header[8:]+zimage


def run(argv: list[str], directory: Path, log) -> None:
    log.write((json.dumps(argv)+"\n").encode())
    log.flush()
    result = subprocess.run(argv, cwd=directory, stdout=log, stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise ValueError(f"kernel producer step failed ({result.returncode}): {argv[0]}; inspect build.log")


def source_filter(member: tarfile.TarInfo, destination: str):
    if not member.issym():
        return tarfile.data_filter(member, destination)
    # Ubuntu's Python3.10 data_filter backport resolves symlinks from archive
    # root, incorrectly rejecting Linux's internal ../ source links. Resolve
    # symlinks from their containing directory, still rejecting every escape.
    root = Path(destination).resolve()
    target = (root/Path(member.name).parent/member.linkname).resolve()
    if Path(member.linkname).is_absolute() or (target != root and root not in target.parents):
        raise ValueError("kernel source symlink escapes isolated extraction")
    result = tarfile.tar_filter(member, destination)
    return result.replace(uid=None, gid=None, uname=None, gname=None, mode=None)


def build(archive: Path, dtb_path: Path | None, output: Path, *, cross_compile: str = "arm-linux-gnueabihf-",
          plan_only: bool = False) -> dict:
    archive, output = archive.absolute(), output.absolute()
    if archive.is_symlink() or not archive.is_file() or archive.stat().st_size > 160*1024*1024:
        raise ValueError("bounded regular pinned Linux source archive required")
    source = archive.read_bytes()
    if sha(source) != SOURCE_SHA256:
        raise ValueError("Linux source archive differs from kernel.org SHA256 pin")
    dtb = None
    if dtb_path is not None:
        dtb_path = dtb_path.absolute()
        if dtb_path.is_symlink() or not dtb_path.is_file():
            raise ValueError("regular reviewed carrier DTB required")
        dtb = dtb_path.read_bytes()
        carrier_dtb(dtb)
    fragment = (SCRIPT_DIR/"first_install/am3_bb_recovery_kernel.config").read_text()
    receipt = {"schema": "dcentos.am3-bb-recovery-kernel/v1", "kernel_version": VERSION,
               "source_url": SOURCE_URL, "source_sha256": SOURCE_SHA256,
               "config_fragment_sha256": sha(fragment.encode()), "dtb_sha256": sha(dtb) if dtb else None,
               "carrier_dtb_present": dtb is not None,
               "carrier_image_admitted": False,
               "load_profile": LOAD_PROFILE, "load_addresses": {"kernel": 0x80200000,
               "fdt": 0x84000000, "ramdisk": 0x85000000}, "kernel_image_max_bytes": 0x2000000,
               "metadata": "Linux mtdpart sysfs offset and direct omap NAND OF parent",
               "physical_boot_validated": False, "persistent_install_ready": False,
               "plan_only": plan_only}
    if plan_only:
        return receipt
    if os.name != "posix" or not re.fullmatch(r"[A-Za-z0-9_./+-]+-", cross_compile):
        raise ValueError("Linux build host and bounded cross-compiler prefix required")
    for tool in ("make", "gcc", "bison", "flex", "bc", cross_compile+"gcc"):
        if not shutil.which(tool):
            raise ValueError("kernel producer tool missing: "+tool)
    if not hasattr(tarfile, "data_filter"):
        raise ValueError("Python with safe tar extraction filter required")
    output.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(source), mode="r:xz") as tar:
        tar.extractall(output, filter=source_filter)
    tree = output/("linux-"+VERSION)
    build_dir = output/"build"
    build_dir.mkdir()
    command = ["make", "-C", str(tree), "O="+str(build_dir), "ARCH=arm", "CROSS_COMPILE="+cross_compile, "-j2"]
    with (output/"build.log").open("xb") as log:
        run(command+["omap2plus_defconfig"], output, log)
        # Merge text then olddefconfig resolves dependencies. Verification below
        # refuses any symbol silently dropped by the selected kernel version.
        with (build_dir/".config").open("a") as config:
            config.write("\n"+fragment)
        run(command+["olddefconfig"], output, log)
        config = (build_dir/".config").read_text()
        verify_config(config, fragment)
        run(command+["zImage", "Image"], output, log)
    zimage = (build_dir/"arch/arm/boot/zImage").read_bytes()
    image = (build_dir/"arch/arm/boot/Image").read_bytes()
    kernel = legacy_kernel(zimage, image)
    artifacts = {"uImage": kernel, "kernel.config": config.encode()}
    if dtb is not None:
        artifacts["devicetree.dtb"] = dtb
    for name, data in artifacts.items():
        with (output/name).open("xb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
    receipt.update({"uimage_sha256": sha(kernel), "zimage_sha256": sha(zimage),
                    "uncompressed_image_sha256": sha(image), "uncompressed_image_bytes": len(image),
                    "kernel_config_sha256": sha(config.encode()),
                    "metadata_source_sha256": sha((tree/"drivers/mtd/mtdpart.c").read_bytes()),
                    "omap_source_sha256": sha((tree/"drivers/mtd/nand/raw/omap2.c").read_bytes())})
    with (output/"kernel-receipt.json").open("x") as destination:
        json.dump(receipt, destination, indent=2)
        destination.write("\n")
        destination.flush()
        os.fsync(destination.fileno())
    return receipt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--linux-archive", type=Path, required=True)
    parser.add_argument("--carrier-dtb", type=Path, help="omit only for kernel-only output without carrier/image admission")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cross-compile", default="arm-linux-gnueabihf-")
    parser.add_argument("--plan", action="store_true")
    args = parser.parse_args()
    print(json.dumps(build(args.linux_archive, args.carrier_dtb, args.output,
                           cross_compile=args.cross_compile, plan_only=args.plan), indent=2))


if __name__ == "__main__":
    main()
