#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Repack the pinned stock8 transition with fixed DCENT recovery handlers."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "dcent-toolbox/src"))
from dcent_toolbox.core.flattened_device_tree import FdtLimits, parse_fdt  # noqa: E402
from dcent_toolbox.core.am2_first_install_executor import validate_static_arm_writer  # noqa: E402

HELD_OUTER_SHA256 = "dc795c621c0a70fd92c560f54434ab1e4617fe3da97c7e2795780b2bcb7af492"
HELD_RAMDISK_SHA256 = "946d1a1d66956134ed3e355d20a7ff1f78784df09521535da142f2e1ad1907d5"
FIT_LIMITS = FdtLimits(max_total_bytes=8 * 1048576, max_property_bytes=8 * 1048576,
                       max_nodes=128, max_properties=512, max_depth=16)


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def replace_fit_properties(raw: bytes, replacements: dict[tuple[str, str], bytes]) -> bytes:
    """Serialize the same bounded FIT tree with explicit property replacements."""
    doc = parse_fdt(raw, limits=FIT_LIMITS)
    if doc.reservations:
        raise ValueError("held FIT unexpectedly contains memory reservations")
    known = {(node.path, prop.name) for node in doc.nodes for prop in node.properties}
    if set(replacements) - known:
        raise ValueError("FIT replacement names an absent property")
    strings = bytearray()
    paths = {node.path: node for node in doc.nodes}

    def align(value):
        return value + bytes(-len(value) % 4)

    def serialize(path):
        name = "" if path == "/" else path.rsplit("/", 1)[1]
        result = struct.pack(">I", 1) + align(name.encode() + b"\0")
        for prop in paths[path].properties:
            value = replacements.get((path, prop.name), prop.value)
            offset = len(strings)
            strings.extend(prop.name.encode() + b"\0")
            result += struct.pack(">III", 3, len(value), offset) + align(value)
        for child in doc.nodes:
            parent = child.path.rsplit("/", 1)[0] or "/"
            if child.path != "/" and parent == path:
                result += serialize(child.path)
        return result + struct.pack(">I", 2)

    body = serialize("/") + struct.pack(">I", 9)
    output = struct.pack(">10I", 0xd00dfeed, 56 + len(body) + len(strings),
                         56, 56 + len(body), 40, 17, 16, doc.header.boot_cpu_id,
                         len(strings), len(body)) + bytes(16) + body + strings
    parse_fdt(output, limits=FIT_LIMITS)
    return output


def transition_parts(raw: bytes):
    if _sha(raw) != HELD_OUTER_SHA256:
        raise ValueError("transition U-Boot/FIT is not the pinned stock8 donor")
    outer = parse_fdt(raw, limits=FIT_LIMITS)
    if (outer.ascii_string("/configurations", "default") != "standard"
            or outer.ascii_string("/configurations/standard", "kernel") != "kernel"
            or any(outer.u32_cells("/images/kernel", key) != (0x4000000,)
                   for key in ("load", "entry"))):
        raise ValueError("outer transition entry differs")
    payload = outer.require_property("/images/kernel", "data")
    inner_raw = payload[1048576:]
    inner = parse_fdt(inner_raw, limits=FIT_LIMITS)
    ramdisk = inner.require_property("/images/ramdisk@1", "data")
    if _sha(ramdisk) != HELD_RAMDISK_SHA256:
        raise ValueError("recovery rootfs differs from the pinned donor")
    return outer, inner, payload[:1048576], inner_raw, ramdisk


def repack_fit(raw: bytes, ramdisk: bytes) -> bytes:
    outer, inner, prefix, inner_raw, _ = transition_parts(raw)
    if not ramdisk.startswith(b"hsqs"):
        raise ValueError("recovery ramdisk is not SquashFS")
    replacements = {
        ("/images/ramdisk@1", "data"): ramdisk,
        ("/images/ramdisk@1/hash@1", "value"): struct.pack(">I", zlib.crc32(ramdisk)),
        ("/images/ramdisk@1/hash@2", "value"): hashlib.sha1(ramdisk).digest(),
    }
    rewritten = replace_fit_properties(inner_raw, replacements)
    after = parse_fdt(rewritten, limits=FIT_LIMITS)
    for image in ("kernel@1", "fdt@1"):
        path = "/images/" + image
        if after.require_property(path, "data") != inner.require_property(path, "data"):
            raise ValueError("recovery kernel/device tree changed")
    payload = prefix + rewritten
    result = replace_fit_properties(raw, {
        ("/images/kernel", "data"): payload,
        ("/images/kernel/hash", "value"): struct.pack(">I", zlib.crc32(payload)),
    })
    if len(result) > 8 * 1048576:
        raise ValueError("custom transition exceeds the stock 8 MiB kernel window")
    return result


def build(archive: Path, writer: Path, output: Path, scratch: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("recovery template output already exists")
    validate_static_arm_writer(writer.read_bytes())
    with tarfile.open(archive, "r:gz") as tar:
        matches = [member for member in tar if member.name == "firmware/uImage.itb"]
        if len(matches) != 1 or not matches[0].isfile() or matches[0].size > 8 * 1048576:
            raise ValueError("held transition member differs")
        raw = tar.extractfile(matches[0]).read()
    _, _, _, _, ramdisk = transition_parts(raw)
    with tempfile.TemporaryDirectory(prefix="dcent-stock8-template-", dir=scratch) as temporary:
        folder = Path(temporary)
        original = folder / "original.squashfs"
        original.write_bytes(ramdisk)
        root = folder / "root"
        subprocess.run(["unsquashfs", "-processors", "2", "-d", str(root), str(original)], check=True)
        for name in ("am2_stock_bootstrap.sh", "am2_stock_stage2.sh"):
            source = HERE / name
            destination = root / "usr/sbin" / name.replace("am2_", "dcent_").replace("_", "-").removesuffix(".sh")
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o755)
        helper = root / "usr/libexec/dcent-am2-nand-window"
        helper.parent.mkdir(parents=True, exist_ok=True)
        helper.write_bytes(writer.read_bytes())
        helper.chmod(0o755)
        dropbear = root / "etc/init.d/dropbear"
        script = dropbear.read_text()
        for marker in ("keygen()\n{\n", "start_service()\n{\n"):
            if script.count(marker) != 1:
                raise ValueError("held Dropbear init template differs")
        script = script.replace("keygen()\n{\n", "keygen()\n{\n\treturn 0 # preserve the admitted existing host keys\n")
        script = script.replace("start_service()\n{\n", "start_service()\n{\n\t[ -f /tmp/dcent-stock-recovery/ssh.ready ] || return 1\n")
        dropbear.write_text(script)
        for name in ("authorized_keys", "dropbear_rsa_host_key", "dropbear_ed25519_host_key",
                     "dropbear_dss_host_key", "dropbear_ecdsa_host_key"):
            key = root / "etc/dropbear" / name
            if key.exists() or key.is_symlink():
                key.unlink()
        # The held button-failsafe hook starts a separate unpinned server.
        # This image has one SSH bootstrap, using only the captured unit keys.
        failsafe = root / "lib/preinit/99_10_failsafe_dropbear"
        if failsafe.exists() or failsafe.is_symlink():
            failsafe.unlink()
        for name, order, command in (("dcent_stock_bootstrap", 40, "dcent-stock-bootstrap"),
                                      ("bos_recovery", 99, "dcent-stock-stage2 auto-install")):
            init = root / "etc/init.d" / name
            init.write_text(f"#!/bin/sh /etc/rc.common\nSTART={order}\nstart() {{ /usr/sbin/{command}; }}\n")
            init.chmod(0o755)
            link = root / "etc/rc.d" / f"S{order:02d}{name}"
            if not link.is_symlink():
                link.symlink_to("../init.d/" + name)
        rebuilt = folder / "recovery.squashfs"
        subprocess.run(["mksquashfs", str(root), str(rebuilt), "-noappend", "-comp", "xz",
                        "-b", "131072", "-processors", "2", "-all-time", "0", "-mkfs-time", "0"], check=True)
        packed = repack_fit(raw, rebuilt.read_bytes())
        with output.open("xb") as handle:
            handle.write(packed)
            handle.flush()
            os.fsync(handle.fileno())
        return {"schema": "dcentos.am2-stock8-recovery-template.v1",
                "source_sha256": _sha(raw), "writer_sha256": _sha(writer.read_bytes()),
                "transition_sha256": _sha(packed), "transition_bytes": len(packed),
                "bootstrap_sha256": _sha((HERE / "am2_stock_bootstrap.sh").read_bytes()),
                "stage2_sha256": _sha((HERE / "am2_stock_stage2.sh").read_bytes())}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--held-archive", type=Path, required=True)
    parser.add_argument("--writer", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--receipt", type=Path,
                        help="write the exact composition receipt for the signed capsule")
    args = parser.parse_args()
    if args.receipt is not None and (args.receipt.exists() or args.receipt.is_symlink()):
        parser.error("composition receipt already exists")
    report = build(args.held_archive, args.writer, args.output, args.scratch)
    encoded = json.dumps(report, indent=2) + "\n"
    if args.receipt is not None:
        with args.receipt.open("x", encoding="utf-8") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    print(encoded, end="")
