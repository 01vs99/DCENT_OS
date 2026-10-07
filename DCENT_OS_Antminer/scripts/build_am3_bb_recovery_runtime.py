#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build isolated BB recovery-only userspace from retained Buildroot source."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import zlib

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLBOX = SCRIPT_DIR.parents[1]/"dcent-toolbox/src"
sys.path.insert(0, str(TOOLBOX))
from dcent_toolbox.core.am3_bb_recovery_ramdisk import inspect_runtime  # noqa: E402
SOURCE_DIRS = ("arch", "board", "boot", "configs", "docs", "fs", "linux", "package", "support", "system", "toolchain", "utils")
SOURCE_FILES = ("Makefile", "Makefile.legacy", "Config.in", "Config.in.legacy", "COPYING", "README")
PROFILE = "dcentos.bbctrl-recovery-runtime/v1"
REQUIRED = {"BR2_arm": "y", "BR2_cortex_a8": "y", "BR2_PACKAGE_PYTHON3": "y",
            "BR2_PACKAGE_PYTHON3_ZLIB": "y", "BR2_PACKAGE_PYTHON3_XZ": "y",
            "BR2_PACKAGE_PYTHON_CRYPTOGRAPHY": "y",
            "BR2_PACKAGE_DROPBEAR": "y", "BR2_TARGET_ROOTFS_CPIO_GZIP": "y"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024*1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write(path: Path, data: bytes, mode: int = 0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as destination:
        destination.write(data)
    path.chmod(mode)


def module_closure(entry: str) -> dict[str, bytes]:
    class EagerImports(ast.NodeVisitor):
        def visit_ImportFrom(self, node):
            if node.module and node.module.startswith("dcent_toolbox."):
                pending.append(node.module)
                for alias in node.names:
                    candidate = node.module+"."+alias.name
                    if (TOOLBOX/Path(*candidate.split("."))).with_suffix(".py").is_file():
                        pending.append(candidate)

        def visit_Import(self, node):
            pending.extend(alias.name for alias in node.names if alias.name.startswith("dcent_toolbox."))

        def visit_FunctionDef(self, node):
            pass

        visit_AsyncFunctionDef = visit_FunctionDef

    pending = [entry, "dcent_toolbox", "dcent_toolbox.core"]
    result = {}
    while pending:
        module = pending.pop()
        relative = Path(*module.split("."))
        path = TOOLBOX/relative.with_suffix(".py")
        if not path.is_file():
            path = TOOLBOX/relative/"__init__.py"
        name = path.relative_to(TOOLBOX).as_posix()
        if name in result:
            continue
        data = path.read_bytes()
        result[name] = data
        tree = ast.parse(data)
        EagerImports().visit(tree)
    return result


def snapshot(source: Path, destination: Path) -> dict:
    if "export BR2_VERSION := 2025.11-rc1" not in (source/"Makefile").read_text():
        raise ValueError("recorded Buildroot 2025.11-rc1 source required")
    destination.mkdir()
    for name in SOURCE_FILES:
        shutil.copyfile(source/name, destination/name)
    for name in SOURCE_DIRS:
        shutil.copytree(source/name, destination/name, symlinks=True)
    pins = {}
    for path in sorted(destination.rglob("*")):
        relative = path.relative_to(destination).as_posix()
        if path.is_symlink():
            # One upstream OpenRC rootfs template deliberately contains an
            # absolute target-runtime symlink. It is preserved as a link and
            # OpenRC is not selected; never follow it as a host source file.
            runtime_link = (relative == "package/skeleton-init-openrc/skeleton/etc/runlevels/default/sysv-rcs"
                            and os.readlink(path) == "/etc/init.d/sysv-rcs")
            if destination.resolve() not in path.resolve().parents and not runtime_link:
                raise ValueError("Buildroot source link escapes isolated snapshot")
            pins[relative] = {"symlink": os.readlink(path)}
        elif path.is_file():
            pins[relative] = {"sha256": file_sha(path), "mode": path.stat().st_mode & 0o777}
    return pins


def run(command, log):
    log.write((json.dumps(command)+"\n").encode())
    log.flush()
    environment = dict(os.environ, PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                       LC_ALL="C", FORCE_UNSAFE_CONFIGURE="1")
    environment.pop("BR2_EXTERNAL", None)
    environment.pop("PYTHONPATH", None)
    result = subprocess.run(command, env=environment, stdout=log, stderr=subprocess.STDOUT, check=False)
    if result.returncode:
        raise ValueError(f"runtime build step failed ({result.returncode}): {command[0]}; inspect build.log")


def legacy_ramdisk(cpio_gzip: bytes) -> bytes:
    if not 0 < len(cpio_gzip) <= 0x4000000-64:
        raise ValueError("bounded gzip newc recovery initramfs required")
    inspect_runtime(cpio_gzip)
    header = struct.pack(">7I4B32s", 0x27051956, 0, 0, len(cpio_gzip), 0, 0,
                         zlib.crc32(cpio_gzip), 5, 2, 3, 0, b"DCENT BBCtrl RAM recovery")
    return header[:4]+struct.pack(">I", zlib.crc32(header))+header[8:]+cpio_gzip


def populate_overlay(output: Path):
    overlay = output/"overlay"
    overlay.mkdir()
    modules = module_closure("dcent_toolbox.core.am3_bb_recovery_service")
    # Python version comes from the exact pinned Buildroot package source.
    version = next(line.split("=", 1)[1].strip() for line in (output/"source/package/python3/python3.mk").read_text().splitlines()
                   if line.startswith("PYTHON3_VERSION_MAJOR ="))
    site = f"usr/lib/python{version}/site-packages"
    packaged = {}
    for name, data in modules.items():
        target = site+"/"+name
        write(overlay/target, data)
        packaged["/"+target] = sha(data)
    init = (SCRIPT_DIR/"first_install/am3_bb_recovery_init").read_bytes()
    write(overlay/"init", init, 0o755)
    packaged["/init"] = sha(init)
    entry = b"#!/usr/bin/python3 -I\nfrom dcent_toolbox.core.am3_bb_recovery_service import main\nraise SystemExit(main())\n"
    write(overlay/"usr/bin/dcent-bb-recovery-service", entry, 0o755)
    packaged["/usr/bin/dcent-bb-recovery-service"] = sha(entry)
    # BusyBox init must never discover generated /etc/init.d scripts.
    write(overlay/"etc/inittab", b"# Recovery PID1 only reaps children; no rcS, shell, reboot, or mining service.\n")
    write(overlay/"etc/dcentos/board_target", b"am3-bb-s19jpro\n")
    dhcp = (b"#!/bin/sh\nexport PATH=/usr/sbin:/usr/bin:/sbin:/bin\n"
            b'case "$1" in\n deconfig) /sbin/ifconfig eth0 0.0.0.0 ;;\n'
            b' bound|renew) /sbin/ifconfig eth0 "$ip" netmask "$subnet" ;;\nesac\n')
    write(overlay/"usr/lib/dcent-bb-recovery/dhcp", dhcp, 0o755)
    packaged["/usr/lib/dcent-bb-recovery/dhcp"] = sha(dhcp)
    helper_source = (SCRIPT_DIR/"first_install/am3_bb_nand_window.c").read_bytes()
    write(output/"am3_bb_nand_window.c", helper_source)
    config = (SCRIPT_DIR/"first_install/am3_bb_recovery_runtime_defconfig").read_text()
    config += f'\nBR2_DL_DIR="{output}/dl"\nBR2_ROOTFS_OVERLAY="{overlay}"\nBR2_JLEVEL=2\n'
    write(output/"recovery_defconfig", config.encode())
    return {"defconfig_sha256": sha(config.encode()), "helper_source_sha256": sha(helper_source),
            "files": packaged, "python_version": version}


def prepare(source: Path, cache: Path, output: Path) -> dict:
    if os.name != "posix" or not output.is_absolute() or any(char.isspace() for char in str(output)):
        raise ValueError("Linux isolated absolute output without whitespace required")
    if output.exists() or output.is_symlink():
        raise ValueError("new isolated runtime output required; retained targets are never reused")
    output.mkdir(mode=0o700)
    pins = snapshot(source, output/"source")
    (output/"dl").mkdir()
    cache_pins = {}
    # Copy retained download archives only; never share writable .lock files or
    # cache inodes with another build. Buildroot verifies its package hashes.
    for name in ("toolchain-external-custom", "python3", "libopenssl", "busybox", "dropbear",
                 "libffi", "libzlib", "zlib", "expat", "xz", "libxcrypt", "host-rust-bin",
                 "tar", "cpio", "rsync", "m4", "bison", "flex", "autoconf", "automake",
                 "autoconf-archive", "gettext-tiny", "libtool", "pkgconf", "fakeroot",
                 "libiconv", "gawk", "patchelf", "ncurses", "acl", "attr"):
        directory = cache/name
        if not directory.is_dir():
            continue
        for item in directory.iterdir():
            if item.is_file() and not item.is_symlink() and not item.name.startswith("."):
                target = output/"dl"/name/item.name
                target.parent.mkdir(exist_ok=True)
                shutil.copyfile(item, target)
                cache_pins[str(target.relative_to(output/"dl"))] = file_sha(target)
    overlay_receipt = populate_overlay(output)
    receipt = {"schema": PROFILE, "state": "prepared", "buildroot_source": str(source),
               "source_tree_sha256": sha(json.dumps(pins, sort_keys=True).encode()),
               "source_files": pins, "cached_downloads": cache_pins,
               **overlay_receipt, "build_parallelism": 2,
               "automatic_installation": False, "physical_boot_validated": False,
               "persistent_install_ready": False}
    write(output/"prepared.json", (json.dumps(receipt, indent=2)+"\n").encode())
    return receipt


def exclusive_output(function):
    def locked(output):
        import fcntl
        descriptor = os.open(output/".producer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise ValueError("private runtime producer lock required")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return function(output)
        finally:
            os.close(descriptor)
    return locked


@exclusive_output
def revise_prepared(output: Path) -> dict:
    """Preserve a stopped preparation before refreshing source/config overlay.

    This is allowed only before Python/userspace compilation, so a capability
    correction cannot silently reuse incompatible configured package objects.
    """
    if (output.is_symlink() or output.resolve() != output or
            any((output/"build/build").glob("python3-*/.stamp_configured")) or
            (output/"runtime-receipt.json").exists()):
        raise ValueError("overlay revision requires direct pre-userspace build output")
    receipt = json.loads((output/"prepared.json").read_text())
    revision = int(receipt.get("preparation_revision", 0))+1
    archive = output/f"preparation-before-revision-{revision:03d}"
    archive.mkdir()
    for name in ("overlay", "recovery_defconfig", "am3_bb_nand_window.c", "prepared.json"):
        (output/name).rename(archive/name)
    receipt.update(populate_overlay(output))
    receipt["preparation_revision"] = revision
    receipt["previous_preparation_sha256"] = file_sha(archive/"prepared.json")
    write(output/"prepared.json", (json.dumps(receipt, indent=2)+"\n").encode())
    return receipt


@exclusive_output
def build_prepared(output: Path) -> dict:
    receipt = json.loads((output/"prepared.json").read_text())
    if receipt.get("schema") != PROFILE or receipt.get("state") != "prepared":
        raise ValueError("prepared isolated runtime recipe required")
    if (file_sha(output/"recovery_defconfig") != receipt["defconfig_sha256"] or
            file_sha(output/"am3_bb_nand_window.c") != receipt["helper_source_sha256"]):
        raise ValueError("prepared configuration/helper source changed")
    for name, pin in receipt["source_files"].items():
        path = output/"source"/name
        if ("symlink" in pin and (not path.is_symlink() or os.readlink(path) != pin["symlink"])) or (
                "sha256" in pin and (path.is_symlink() or file_sha(path) != pin["sha256"])):
            raise ValueError("prepared Buildroot source changed: "+name)
    for name, digest in receipt["files"].items():
        if file_sha(output/"overlay"/name.lstrip("/")) != digest:
            raise ValueError("prepared recovery module changed: "+name)
    command = ["make", "-C", str(output/"source"), "O="+str(output/"build"), "-j2",
               "BR2_WGET=wget -nd -t 2 --connect-timeout=10 --read-timeout=30"]
    with (output/"build.log").open("ab") as log:
        run(command+["BR2_DEFCONFIG="+str(output/"recovery_defconfig"), "defconfig"], log)
        config = (output/"build/.config").read_text()
        values = dict(line.split("=", 1) for line in config.splitlines() if line.startswith("BR2_") and "=" in line)
        if any(values.get(key) != value for key, value in REQUIRED.items()):
            raise ValueError("resolved recovery package/config requirement was dropped")
        run(command+["toolchain"], log)
        compiler = output/"build/host/bin/arm-linux-gnueabihf-gcc"
        helper = output/"overlay/usr/sbin/am3-bb-nand-window"
        helper.parent.mkdir(parents=True, exist_ok=True)
        run([str(compiler), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-static",
             str(output/"am3_bb_nand_window.c"), "-o", str(helper)], log)
        helper.chmod(0o755)
        receipt["files"]["/usr/sbin/am3-bb-nand-window"] = file_sha(helper)
        runtime = {"schema": PROFILE, "files": receipt["files"], "automatic_installation": False}
        runtime_path = output/"overlay/etc/dcentos/recovery-runtime.json"
        runtime_bytes = (json.dumps(runtime, indent=2)+"\n").encode()
        if runtime_path.exists():
            if runtime_path.read_bytes() != runtime_bytes:
                raise ValueError("previous runtime receipt differs; preserve and review the output")
        else:
            write(runtime_path, runtime_bytes)
        run(command, log)
    rootfs = (output/"build/images/rootfs.cpio.gz").read_bytes()
    inspected = inspect_runtime(rootfs, expected_helper_sha256=receipt["files"]["/usr/sbin/am3-bb-nand-window"])
    ramdisk = legacy_ramdisk(rootfs)
    write(output/"uramdisk.image.gz", ramdisk)
    write(output/"runtime.config", config.encode())
    receipt.update(state="built", ramdisk_sha256=sha(ramdisk), ramdisk_bytes=len(ramdisk),
                   rootfs_cpio_gzip_sha256=sha(rootfs), resolved_config_sha256=sha(config.encode()),
                   build_log_sha256=file_sha(output/"build.log"), initramfs_inspection=inspected)
    write(output/"runtime-receipt.json", (json.dumps(receipt, indent=2)+"\n").encode())
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--buildroot-source", type=Path)
    parser.add_argument("--download-cache", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--build-prepared", action="store_true")
    parser.add_argument("--revise-prepared", action="store_true")
    args = parser.parse_args()
    if args.revise_prepared:
        result = revise_prepared(args.output.absolute())
    elif args.build_prepared:
        result = build_prepared(args.output.absolute())
    else:
        if args.buildroot_source is None or args.download_cache is None:
            parser.error("source and download cache are required to prepare")
        result = prepare(args.buildroot_source.absolute(), args.download_cache.absolute(), args.output.absolute())
        if not args.prepare_only:
            result = build_prepared(args.output.absolute())
    print(json.dumps({key: value for key, value in result.items() if key not in ("source_files",)}, indent=2))
