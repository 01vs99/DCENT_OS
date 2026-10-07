#!/usr/bin/env python3
"""Test-only raw NAND replay inside the runner's disposable virtme guest.

The public entry points always check the real guest, module and character
devices. Pure page iteration below opens no device and grants no write access.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile

from nandsim_snapshot import SnapshotError, allocated_pages, load_snapshot, regular, sha


RELEASE = "5.15.0-181-generic"
KERNEL_SHA = "6d08ef6d2f4c8e609cb91a512e7f37e85e9077561667da10de8f44e2eec6d85d"
MODULE_SHA = "6f16a506ede045c51f3a39a0dfb71e13c96683ed2b9ed99547f73cbf6d4e1e5d"
MODULE = Path("/lib/modules") / RELEASE / "kernel/drivers/mtd/nand/raw/nandsim.ko"
PART_BLOCKS = (64, 96, 16, 16, 4, 4, 696, 456, 456, 240)
PAGE, RAW_PAGE, ERASE = 2048, 2112, 131072
ERASED = b"\xff" * RAW_PAGE


def token_is_valid(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def guard(token: str):
    """Refuse before opening a writable device outside this exact guest."""
    if (os.name != "posix" or os.geteuid() != 0 or os.uname().release != RELEASE
            or not token_is_valid(token)
            or os.environ.get("DCENT_DISPOSABLE_VIRTME") != "am2-first-install-v1"):
        raise SnapshotError("exact disposable root guest and run token required")
    if not {"nopti", "no5lvl"}.issubset(Path("/proc/cmdline").read_text().split()):
        raise SnapshotError("snapshot requires the explicit four-level kernel mapping")
    if Path("/sys/class/dmi/id/product_serial").read_text().strip() != "DCENT-NANDSIM-" + token:
        raise SnapshotError("guest DMI does not bind this runner's QEMU instance")
    if sha(regular(MODULE, 4*1024**2)) != MODULE_SHA:
        raise SnapshotError("guest nandsim module bytes differ")
    parameters = Path("/sys/module/nandsim/parameters")
    for name in ("cache_file", "weakblocks", "weakpages", "gravepages"):
        if (parameters / name).read_text().strip() not in ("", "(null)"):
            raise SnapshotError("unmodeled simulator cache/fault state: " + name)
    for name in ("bitflips", "bbt", "bch"):
        if (parameters / name).read_text().strip() != "0":
            raise SnapshotError("unmodeled simulator fault/ECC mode: " + name)
    devices = []
    rows = Path("/proc/mtd").read_text().splitlines()[1:]
    if len(rows) != len(PART_BLOCKS):
        raise SnapshotError("exclusive ten-partition simulated NAND required")
    for index, blocks in enumerate(PART_BLOCKS):
        fields = rows[index].split()
        if (fields[:3] != [f"mtd{index}:", f"{blocks*ERASE:08x}", "00020000"]
                or "NAND simulator" not in " ".join(fields[3:])):
            raise SnapshotError("exact nandsim partition inventory differs")
        node = Path(f"/sys/class/mtd/mtd{index}")
        for field, expected in (("size", blocks*ERASE), ("erasesize", ERASE),
                                ("writesize", PAGE), ("oobsize", 64)):
            if int((node / field).read_text()) != expected:
                raise SnapshotError("simulated device geometry differs")
        device = Path(f"/dev/mtd{index}")
        info = device.lstat()
        major, minor = map(int, (node / "dev").read_text().strip().split(":"))
        if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(major, minor):
            raise SnapshotError("exact real simulated character device required")
        devices.append((device, blocks))
    return tuple(devices)


def bad_blocks(devices):
    """Observe the actual MTD owner's bad-block decision, including raw OOB."""
    import fcntl
    found, base = [], 0
    for device, blocks in devices:
        fd = os.open(device, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            for block in range(blocks):
                offset = bytearray(struct.pack("<q", block * ERASE))
                result = fcntl.ioctl(fd, 0x40084D0B, offset, True)  # MEMGETBADBLOCK, exact x86-64 ABI.
                if result not in (0, 1):
                    raise SnapshotError("unexpected raw MTD bad-block result")
                if result:
                    found.append(base + block)
        finally:
            os.close(fd)
        base += blocks
    return found


def runtime_binding(token: str):
    devices = guard(token)
    symbols = [line.split() for line in Path("/proc/kallsyms").read_text().splitlines()
               if line.split()[2:] == ["nsmtd", "[nandsim]"]]
    if len(symbols) != 1 or int(symbols[0][0], 16) == 0:
        raise SnapshotError("unique visible loaded nandsim symbol required")
    return {"token": token, "kernel_release": RELEASE, "kernel_sha256": KERNEL_SHA,
            "module_sha256": MODULE_SHA, "base_btf_sha256": sha(Path("/sys/kernel/btf/vmlinux").read_bytes()),
            "module_btf_sha256": sha(Path("/sys/kernel/btf/nandsim").read_bytes()),
            "symbol_address": int(symbols[0][0], 16),
            "bss_address": int(Path("/sys/module/nandsim/sections/.bss").read_text(), 16),
            "bad_blocks": bad_blocks(devices)}


def replay_runs(allocation: bytes, pages: bytes):
    """Yield bounded contiguous raw records; preserve allocated all-FF pages."""
    if len(allocation) != 16384 or len(pages) != sum(value.bit_count() for value in allocation) * RAW_PAGE:
        raise SnapshotError("complete bounded raw allocation map required")
    partition, first_page = 0, 0
    start, pending = None, bytearray()
    for page, raw in allocated_pages(allocation, pages):
        while page >= first_page + PART_BLOCKS[partition] * (ERASE // PAGE):
            if pending:
                yield partition, start*PAGE, bytes(pending)
                start, pending = None, bytearray()
            first_page += PART_BLOCKS[partition] * (ERASE // PAGE)
            partition += 1
            if partition == len(PART_BLOCKS):
                raise SnapshotError("raw allocation exceeds simulator partitions")
        local_page = page - first_page
        if pending and (local_page != start + len(pending)//RAW_PAGE or len(pending) >= RAW_PAGE*64):
            yield partition, start*PAGE, bytes(pending)
            start, pending = None, bytearray()
        if start is None:
            start = local_page
        pending.extend(raw)
    if pending:
        yield partition, start*PAGE, bytes(pending)


def raw_pages(device: Path, blocks: int):
    """Independent mtd-utils raw reader, with neither ECC nor bad-block skips."""
    with tempfile.TemporaryFile() as diagnostics:
        child = subprocess.Popen(["nanddump", "-q", "--noecc", "--oob", "--bb=dumpbad", str(device)],
                                 stdout=subprocess.PIPE, stderr=diagnostics)
        try:
            for _ in range(blocks * (ERASE // PAGE)):
                raw = child.stdout.read(RAW_PAGE)
                if len(raw) != RAW_PAGE:
                    raise SnapshotError("independent raw NAND reader returned a short page")
                yield raw
            if child.stdout.read(1) or child.wait(timeout=30) != 0:
                raise SnapshotError("independent raw NAND reader failed or exceeded geometry")
        finally:
            child.stdout.close()
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)


def compare_raw(devices, allocation: bytes, pages: bytes):
    expected = iter(allocated_pages(allocation, pages))
    next_page = next(expected, None)
    number, digest = 0, hashlib.sha256()
    for device, blocks in devices:
        for actual in raw_pages(device, blocks):
            wanted = next_page[1] if next_page and next_page[0] == number else ERASED
            if actual != wanted:
                raise SnapshotError(f"fresh guest raw NAND/OOB replay differs at page {number}")
            if next_page and next_page[0] == number:
                next_page = next(expected, None)
            digest.update(actual)
            number += 1
    if number != 131072 or next_page is not None:
        raise SnapshotError("independent NAND readback geometry differs")
    return digest.hexdigest()


def replay(directory: Path, token: str):
    meta, allocation, pages, _ = load_snapshot(directory, kernel_sha256=KERNEL_SHA, module_sha256=MODULE_SHA)
    devices = guard(token)
    # No existing contents are erased to make this precondition pass.
    if bad_blocks(devices):
        raise SnapshotError("fresh replay guest already has bad-block state")
    compare_raw(devices, bytes(16384), b"")
    with tempfile.TemporaryDirectory(prefix="dcent-raw-replay-") as temporary:
        piece = Path(temporary) / "pages.raw"
        for partition, offset, raw in replay_runs(allocation, pages):
            piece.write_bytes(raw)
            result = subprocess.run(["nandwrite", "-q", "-n", "-N", "-o", "-s", str(offset),
                                     str(devices[partition][0]), str(piece)], capture_output=True, timeout=30)
            if result.returncode:
                raise SnapshotError("raw NAND owner rejected replay: " + result.stderr.decode(errors="replace")[-2048:])
    observed = compare_raw(devices, allocation, pages)
    if bad_blocks(devices) != meta["bad_blocks"]:
        raise SnapshotError("fresh guest MTD bad-block decisions differ after raw replay")
    return {"raw_nand_oob_sha256": observed, "bad_blocks": meta["bad_blocks"],
            "boundary": meta["boundary"], "raw_readback": "verified"}
