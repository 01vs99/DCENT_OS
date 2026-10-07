#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Build a regular-file BB recovery card from signed, reviewed inputs.

No block device is opened. Resident NAND SPL/U-Boot remains the boot frontend;
FAT partition 1 has a fixed recovery entry and ext4 partition 2 retains the
signed capsule/helper plus space for the coordinator's original-source backups.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid

SCRIPT_DIR = Path(__file__).resolve().parent
TOOLBOX_SOURCE = SCRIPT_DIR.parents[1] / "dcent-toolbox" / "src"
if TOOLBOX_SOURCE.is_dir():
    sys.path.insert(0, str(TOOLBOX_SOURCE))

from dcent_toolbox.core.am2_xil_first_install import _read_capsule_members  # noqa: E402
from dcent_toolbox.core.am3_bb_nand_transaction import (  # noqa: E402
    RECOVERY_FILES, ERASE, _legacy_image, load_boot_capsule,
)
from dcent_toolbox.core.flattened_device_tree import parse_fdt  # noqa: E402
from dcent_toolbox.core import am3_bb_modern_boot as modern_boot  # noqa: E402
from dcent_toolbox.core.am3_bb_recovery_ramdisk import inspect_runtime  # noqa: E402
from dcent_toolbox.core.am3_bb_recovery_keys import host_key_identity  # noqa: E402
from dcent_toolbox.core.am3_bb_recovery_service import authorized_key  # noqa: E402
from dcent_toolbox.core.am3_bb_recovery_bundle import load_bundle, static_arm_helper  # noqa: E402

HELPER_MEMBER = "transition/am3-bb-nand-window"
MIB = 1024 * 1024
P1_START = 1
P2_START = 128 * MIB // 512
MIN_IMAGE_MIB = 1024
TOOLS = ("mkfs.fat", "mmd", "mcopy", "fsck.fat", "mke2fs", "e2fsck", "debugfs")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for data in iter(lambda: source.read(MIB), b""):
            result.update(data)
    return result.hexdigest()


def inputs(capsule: Path, recovery_root: Path, *, recovery_only: bool = False,
           signing_preparation: bool = False) -> tuple[dict, dict[str, bytes], bytes]:
    if signing_preparation and not recovery_only:
        raise ValueError("unsigned preparation cannot admit a native installation capsule")
    if recovery_only:
        bundle = load_bundle(capsule, signing_preparation=signing_preparation)
        recovery = {name: bundle["files"][name] for name in RECOVERY_FILES}
        return bundle, recovery, bundle["files"][HELPER_MEMBER]
    bundle = load_boot_capsule(capsule)
    if bundle["plan"]["schema"] != modern_boot.SCHEMA:
        raise ValueError("recovery media requires the distinct reviewed modern boot profile")
    files, digest, _size = _read_capsule_members(capsule)
    if digest != bundle["capsule_sha256"] or HELPER_MEMBER not in files:
        raise ValueError("capsule changed or lacks the signed native helper member")
    helper = files[HELPER_MEMBER]
    static_arm_helper(helper)
    recovery = {}
    for name in RECOVERY_FILES:
        path = recovery_root/name
        if path.is_symlink() or not path.is_file() or path.resolve() != path.absolute():
            raise ValueError("recovery input must be a direct regular file: " + str(path))
        if not 0 < path.stat().st_size <= 64*MIB:
            raise ValueError("recovery input exceeds its fixed bound")
        data = path.read_bytes()
        if sha(data) != bundle["plan"]["sd_recovery_files"][name]:
            raise ValueError("recovery input differs from its release-signed digest")
        recovery[name] = data
    kernel, fdt, ramdisk = (recovery[name] for name in RECOVERY_FILES)
    _legacy_image(kernel, 2)
    _legacy_image(ramdisk, 3)
    dt = parse_fdt(fdt)
    recovery_model, recovery_compatible = modern_boot.recovery_identity(bundle["plan"])
    if (len(kernel) > 0x800000 or len(fdt) > ERASE or
            dt.ascii_string("/", "model") != recovery_model or
            list(dt.string_list("/", "compatible")) != recovery_compatible):
        raise ValueError("recovery image spans/carrier DTB differ from the signed plan")
    inspect_runtime(ramdisk[64:], expected_helper_sha256=sha(helper))
    return bundle, recovery, helper


def uenv(console: str) -> bytes:
    if console != "ttyS0":
        raise ValueError("unsupported console dialect")
    # Imported by the exact original resident-U-Boot profile on first recovery
    # boot. A committed DCENT selector also loads the same files directly.
    text = ("bootenv=uEnv.txt\n"
            "uenvcmd=setenv bootargs console=" + console + ",115200n8 root=/dev/ram0 rw rdinit=/init panic=0; "
            "mmc dev 0 && mmc rescan && "
            "fatload mmc 0:1 0x80200000 dcent-recovery/uImage && "
            "fatload mmc 0:1 0x84000000 dcent-recovery/devicetree.dtb && "
            "fatload mmc 0:1 0x85000000 dcent-recovery/uramdisk.image.gz && "
            "bootm 0x80200000 0x85000000 0x84000000\n")
    return text.encode("ascii")


def mbr(image_mib: int) -> bytes:
    if type(image_mib) is not int or not MIN_IMAGE_MIB <= image_mib <= 8192:
        raise ValueError("recovery card must be 1024..8192 MiB")
    sectors = image_mib*MIB//512
    result = bytearray(512)
    for index, (status, kind, first, count) in enumerate((
        (0x80, 0x0C, P1_START, P2_START-P1_START),
        (0, 0x83, P2_START, sectors-P2_START),
    )):
        # The held BB resident-loader convention uses active p1 at LBA 1 and
        # FAT16 with type 0x0c. No MLO or alternate U-Boot is placed on the card.
        result[446+index*16:462+index*16] = struct.pack("<B3sB3sII", status,
            b"\xfe\xff\xff", kind, b"\xfe\xff\xff", first, count)
    result[510:512] = b"\x55\xaa"
    return bytes(result)


def run(argv: list[str], *, cwd: Path) -> str:
    result = subprocess.run(argv, cwd=cwd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, check=False, env=dict(os.environ, LC_ALL="C"))
    if result.returncode:
        raise ValueError(f"filesystem tool failed ({result.returncode}): {argv[0]}\n{result.stdout}")
    return result.stdout


def verify_ext4_custody(ext: Path, staging: Path, retained_name: str) -> dict:
    checks = {}
    for name, kind, mode in (("dcent-backups", "directory", 0o700),
                             ("dcent-recovery-tools", "directory", 0o755),
                             ("dcent-recovery-tools/operator.pub", "regular", 0o600),
                             ("dcent-recovery-tools/ssh_host_ed25519_key", "regular", 0o600),
                             ("dcent-recovery-tools/am3-bb-nand-window", "regular", 0o755),
                             ("dcent-recovery-tools/"+retained_name, "regular", 0o644)):
        detail = run(["debugfs", "-R", "stat /"+name, str(ext)], cwd=staging)
        observed = re.search(r"Type:\s+(\w+)\s+Mode:\s+([0-7]+)", detail)
        ownership = re.search(r"User:\s+(\d+)\s+Group:\s+(\d+)", detail)
        if (observed is None or ownership is None or observed.group(1) != kind or
                int(observed.group(2), 8) != mode or ownership.groups() != ("0", "0") or
                (kind == "regular" and not re.search(r"Links:\s+1\s", detail))):
            raise ValueError("ext4 recovery custody differs: "+name)
        checks[name] = {"type": kind, "mode": f"{mode:04o}", "uid": 0, "gid": 0}
    return checks


def copy_sparse(source: Path, destination, offset: int) -> None:
    with source.open("rb") as handle:
        while True:
            data = handle.read(MIB)
            if not data:
                return
            if data.strip(b"\0"):
                destination.seek(offset)
                destination.write(data)
            offset += len(data)


def build(capsule: Path, recovery_root: Path, output: Path, *, operator_key: Path, host_key: Path,
          image_mib: int = 1024, plan_only: bool = False, recovery_only: bool = False,
          signing_preparation: bool = False) -> dict:
    capsule = capsule.absolute()
    recovery_root = recovery_root.absolute()
    output = output.absolute()
    partition_table = mbr(image_mib)
    bundle, recovery, helper = inputs(capsule, recovery_root, recovery_only=recovery_only,
                                      signing_preparation=signing_preparation)
    for path in (operator_key, host_key):
        if (path.is_symlink() or not path.is_file() or path.resolve() != path.absolute() or
                not 0 < path.stat().st_size <= 4096):
            raise ValueError("bounded regular recovery transport key files required")
    if os.name == "posix" and host_key.stat().st_mode & 0o077:
        raise ValueError("private recovery host key must have mode 0600")
    operator_bytes, host_bytes = operator_key.read_bytes(), host_key.read_bytes()
    authorized_key(operator_bytes)
    transport = host_key_identity(host_bytes)
    boot_environment = uenv(bundle["plan"]["console"])
    receipt = {"schema": "dcentos.am3-bb-nand-recovery-media/v2", "board_target": "am3-bb-s19jpro",
               "input_artifact_sha256": bundle["capsule_sha256"], "helper_sha256": sha(helper),
               "bootloader_image_sha256": bundle["plan"]["bootloader_image_sha256"],
               "image_bytes": image_mib*MIB, "partition1": {"start_sector": P1_START,
               "sectors": P2_START-P1_START, "filesystem": "FAT16"},
               "partition2": {"start_sector": P2_START, "sectors": image_mib*MIB//512-P2_START,
               "filesystem": "ext4", "disabled_features": ["metadata_csum", "64bit"]},
               "recovery_files": {name: sha(data) for name, data in recovery.items()},
               "uenv_sha256": sha(boot_environment), "persistent_install_ready": False,
               "transport": transport, "operator_public_key_sha256": sha(operator_bytes),
               "boot_validation": "not_performed", "device_contact": "none",
               "signature_state": bundle.get("signature_state", "verified_configured_release_pin"),
               "verified_signer_public_key_sha256": bundle.get("verified_signer_public_key_sha256"),
               "native_install_capsule_retained": not recovery_only,
               "automatic_installation": False,
               "scope": "recovery-only RAM boot and identity" if recovery_only else "modern recovery with native capsule",
               "physical_validation_required": True}
    if plan_only:
        return dict(receipt, mode="plan", output=str(output))
    if os.name != "posix" or any(shutil.which(name) is None for name in TOOLS):
        raise ValueError("build requires Linux filesystem tools; run through WSL with dosfstools, mtools and e2fsprogs")
    if os.geteuid() != 0 or os.getegid() != 0:
        raise ValueError("media composition requires Linux root so ext4 recovery files are owned by 0:0")
    manifest_path = output.with_suffix(output.suffix+".json")
    if output.exists() or output.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise ValueError("output/receipt already exists; no replacement")
    if not output.parent.is_dir() or output.parent.resolve() != output.parent:
        raise ValueError("direct existing output directory required")
    with tempfile.TemporaryDirectory(prefix=".bb-recovery-media-", dir=output.parent) as raw:
        staging = Path(raw)
        fat = staging/"fat.img"
        ext = staging/"data.ext4"
        fat_tree = staging/"fat-tree"
        ext_tree = staging/"ext-tree"
        (fat_tree/"dcent-recovery").mkdir(parents=True)
        (ext_tree/"dcent-recovery-tools").mkdir(parents=True)
        (ext_tree/"dcent-recovery-tools").chmod(0o755)
        (ext_tree/"dcent-backups").mkdir(mode=0o700)
        # Private metadata must survive the staging filesystem into ext4.
        custody = (ext_tree/"dcent-backups").stat()
        if custody.st_mode & 0o077 or custody.st_uid or custody.st_gid:
            raise ValueError("media staging requires Linux filesystem permission semantics")
        for name, data in recovery.items():
            (fat_tree/name).write_bytes(data)
        (fat_tree/"uEnv.txt").write_bytes(boot_environment)
        tool = ext_tree/"dcent-recovery-tools/am3-bb-nand-window"
        tool.write_bytes(helper)
        tool.chmod(0o755)
        for name, data in (("operator.pub", operator_bytes), ("ssh_host_ed25519_key", host_bytes)):
            key_path = ext_tree/"dcent-recovery-tools"/name
            key_path.write_bytes(data)
            key_path.chmod(0o600)
        retained_name = "recovery-bundle.tar.gz" if recovery_only else "capsule.tar.gz"
        retained_capsule = ext_tree/"dcent-recovery-tools"/retained_name
        shutil.copyfile(capsule, retained_capsule)
        retained_capsule.chmod(0o644)
        if file_sha(retained_capsule) != bundle["capsule_sha256"]:
            raise ValueError("capsule changed before media retention")
        (ext_tree/"dcent-recovery-tools/MEDIA.json").write_text(json.dumps(receipt, indent=2)+"\n", encoding="utf-8")
        with fat.open("wb") as handle:
            handle.truncate((P2_START-P1_START)*512)
        run(["mkfs.fat", "-F", "16", "-n", "DCENTRESCUE", "-i", bundle["capsule_sha256"][:8], str(fat)], cwd=staging)
        run(["mmd", "-i", str(fat), "::dcent-recovery"], cwd=staging)
        for name in (*RECOVERY_FILES, "uEnv.txt"):
            run(["mcopy", "-i", str(fat), str(fat_tree/name), "::"+name], cwd=staging)
        checks = {"fat": run(["fsck.fat", "-n", str(fat)], cwd=staging)}
        for number, name in enumerate((*RECOVERY_FILES, "uEnv.txt")):
            copied = staging/f"fat-readback-{number}"
            run(["mcopy", "-i", str(fat), "::"+name, str(copied)], cwd=staging)
            expected = boot_environment if name == "uEnv.txt" else recovery[name]
            if copied.read_bytes() != expected:
                raise ValueError("FAT recovery-file readback differs")
        with ext.open("wb") as handle:
            handle.truncate(image_mib*MIB-P2_START*512)
        run(["mke2fs", "-q", "-t", "ext4", "-F", "-L", "DCENT_BACKUP", "-m", "0",
             "-O", "^metadata_csum,^64bit", "-E", "lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0",
             "-U", str(uuid.uuid5(uuid.NAMESPACE_URL, bundle["capsule_sha256"])),
             "-d", str(ext_tree), str(ext)], cwd=staging)
        checks["ext4"] = run(["e2fsck", "-f", "-n", str(ext)], cwd=staging)
        for name in ("am3-bb-nand-window", retained_name, "MEDIA.json", "operator.pub", "ssh_host_ed25519_key"):
            run(["debugfs", "-R", f"dump -p /dcent-recovery-tools/{name} ext-readback", str(ext)], cwd=staging)
            if file_sha(staging/"ext-readback") != file_sha(ext_tree/"dcent-recovery-tools"/name):
                raise ValueError("ext4 signed tool/capsule readback differs")
            (staging/"ext-readback").unlink()
        checks["backup_directory"] = run(["debugfs", "-R", "stat /dcent-backups", str(ext)], cwd=staging)
        if "Type: directory" not in checks["backup_directory"]:
            raise ValueError("ext4 backup directory absent")
        checks["recovery_custody"] = verify_ext4_custody(ext, staging, retained_name)
        candidate = staging/"candidate.img"
        with candidate.open("xb") as image:
            candidate.chmod(0o600)
            image.truncate(image_mib*MIB)
            image.write(partition_table)
            copy_sparse(fat, image, P1_START*512)
            copy_sparse(ext, image, P2_START*512)
            image.flush()
            os.fsync(image.fileno())
        # Verify both composed partition spans independently of source images.
        with candidate.open("rb") as image:
            if image.read(512) != partition_table:
                raise ValueError("composed MBR differs")
            for path, offset in ((fat, P1_START*512), (ext, P2_START*512)):
                image.seek(offset)
                total = path.stat().st_size
                actual = hashlib.sha256()
                while total:
                    data = image.read(min(MIB, total))
                    if not data:
                        raise ValueError("composed partition is truncated")
                    actual.update(data)
                    total -= len(data)
                if actual.hexdigest() != file_sha(path):
                    raise ValueError("composed partition readback differs")
        receipt.update(mode="built", output=str(output), image_sha256=file_sha(candidate),
                       filesystem_checks=checks, fat_partition_sha256=file_sha(fat),
                       ext4_partition_sha256=file_sha(ext))
        receipt_file = staging/"receipt.json"
        with receipt_file.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(receipt, indent=2)+"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(candidate, output)
        os.link(receipt_file, manifest_path)
        descriptor = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, epilog="Support DCENT development: https://d-central.tech/fund/")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--capsule", type=Path)
    source.add_argument("--recovery-only-bundle", type=Path)
    parser.add_argument("--recovery-root", type=Path, default=Path("."), help="required with a native install capsule")
    parser.add_argument("--signing-preparation", action="store_true", help="allow an unsigned recovery-only signing preparation; never native install authority")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--operator-key", required=True, type=Path, help="operator.pub from the per-card transport key set")
    parser.add_argument("--host-key", required=True, type=Path, help="private Dropbear Ed25519 host key for this card")
    parser.add_argument("--size-mib", type=int, default=1024)
    parser.add_argument("--plan", action="store_true", help="validate signed inputs and print geometry without building")
    args = parser.parse_args(argv)
    try:
        receipt = build(args.capsule or args.recovery_only_bundle, args.recovery_root, args.output, operator_key=args.operator_key,
                        host_key=args.host_key, image_mib=args.size_mib, plan_only=args.plan,
                        recovery_only=args.recovery_only_bundle is not None, signing_preparation=args.signing_preparation)
    except (OSError, ValueError) as exc:
        print("BB recovery media: " + str(exc), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
