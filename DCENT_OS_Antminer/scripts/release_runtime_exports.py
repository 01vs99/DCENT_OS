#!/usr/bin/env python3
"""Verify/export the signed runtime pair from the actual release artifact.

Only the canonical producer table selects a container/root format. All reads
are bounded and read-only; archives are never extracted onto the host. The
outer artifact signature and boot-input completeness remain the producer's
separate obligations. A valid exported pair alone cannot qualify an artifact.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import zlib

import runtime_image_manifest as runtime

MAX_ARTIFACT = 1024 * 1024 * 1024
MAX_ROOT = 256 * 1024 * 1024
LIMITS = {runtime.DAEMON: runtime.MAX_DAEMON, runtime.MANIFEST: 4096, runtime.SIGNATURE: 64}
TOOLBOX = Path(__file__).resolve().parents[2] / "dcent-toolbox/src"


def producer_for(board: str):
    from release_producer import list_producers
    matches = [row for row in list_producers() if row.board_target == board]
    if len(matches) != 1:
        raise runtime.ManifestError("exact canonical release producer required")
    return matches[0]


@contextmanager
def artifact_reader(path: Path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_ARTIFACT:
        raise runtime.ManifestError("bounded single-link regular release artifact required")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise runtime.ManifestError("artifact changed while opening")
        yield stream, opened.st_size
        identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
        if identity(opened) != identity(os.fstat(stream.fileno())) or identity(before) != identity(path.lstat()):
            raise runtime.ManifestError("artifact changed during runtime verification")


def region(stream, start: int, size: int, maximum: int) -> bytes:
    if start < 0 or not 0 < size <= maximum:
        raise runtime.ManifestError("artifact region exceeds bounds")
    stream.seek(start)
    raw = stream.read(size)
    if len(raw) != size:
        raise runtime.ManifestError("truncated artifact region")
    return raw


def canonical(name: str, *, dot_prefix=False) -> str:
    if dot_prefix and name.startswith("./"):
        name = name[2:]
    if not name or len(name) > 512 or any(c in name for c in "\\\0:") or any(part in ("", ".", "..") for part in name.split("/")):
        raise runtime.ManifestError("noncanonical archive member")
    return name


def tar_payloads(stream, expected: dict[str, int]) -> dict[str, bytes]:
    found, seen = {}, set()
    # No auto-detection: current producers emit plain POSIX tar, not nested or
    # compressed whole-archive carriers. Reject every alias/duplicate member.
    with tarfile.open(fileobj=stream, mode="r:") as archive:
        for index, member in enumerate(archive):
            name = canonical(member.name.rstrip("/") if member.isdir() else member.name)
            if index >= 128 or name in seen or not (member.isdir() or member.isreg()) or member.sparse:
                raise runtime.ManifestError("duplicate, linked or unsupported release tar member")
            seen.add(name)
            if name in expected:
                if not member.isreg() or not 0 < member.size <= expected[name]:
                    raise runtime.ManifestError("bounded regular release payload required")
                found[name] = archive.extractfile(member).read(expected[name] + 1)
                if len(found[name]) != member.size:
                    raise runtime.ManifestError("truncated release tar payload")
    if set(found) != set(expected):
        raise runtime.ManifestError("required exact-target release payload missing")
    return found


def gunzip(raw: bytes) -> bytes:
    decoder = zlib.decompressobj(31)
    result = decoder.decompress(raw, MAX_ROOT + 1)
    if len(result) > MAX_ROOT or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise runtime.ManifestError("bounded single complete gzip member required")
    return result


def ramdisk(raw: bytes, *, arm64=False) -> bytes:
    if len(raw) < 64:
        raise runtime.ManifestError("truncated legacy ramdisk")
    header = bytearray(raw[:64])
    magic, crc, _, size, _, _, data_crc, system, arch, kind, compression, _ = struct.unpack(">7I4B32s", header)
    struct.pack_into(">I", header, 4, 0)
    # Amlogic mkimage intentionally labels its Linux initramfs as ARM64.
    if (magic != 0x27051956 or crc != zlib.crc32(header) or size != len(raw) - 64
            or data_crc != zlib.crc32(raw[64:]) or system != 5
            or arch != (22 if arm64 else 2) or kind != 3 or compression != 1):
        raise runtime.ManifestError("legacy ramdisk header, CRC or architecture mismatch")
    return gunzip(raw[64:])


def cpio_files(raw: bytes, *, expected: dict[str, int] = None) -> dict[str, bytes]:
    """Read bounded newc files; publication always uses the signed runtime set.

    Read-only archive audits may supply their own exact member roster. This
    low-level extraction helper does not confer publication/image authority.
    """
    if expected is not None:
        if not isinstance(expected, dict) or not 0 < len(expected) <= 128:
            raise runtime.ManifestError("invalid requested initramfs file roster")
        for name, limit in expected.items():
            canonical(name)
            if type(limit) is not int or not 0 < limit <= MAX_ROOT:
                raise runtime.ManifestError("invalid requested initramfs file bound")
    position, entries, payloads, ended = 0, {}, {}, False
    for _ in range(65536):
        header = raw[position:position + 110]
        if len(header) != 110 or header[:6] not in (b"070701", b"070702"):
            raise runtime.ManifestError("invalid newc initramfs header")
        try:
            fields = [int(header[6 + i * 8:14 + i * 8], 16) for i in range(13)]
        except ValueError as error:
            raise runtime.ManifestError("invalid newc numeric field") from error
        ino, mode, _, _, links, _, size, devmajor, devminor, _, _, namesize, checksum = fields
        position += 110
        if not 1 <= namesize <= 513 or size > MAX_ROOT:
            raise runtime.ManifestError("newc member exceeds bounds")
        name = raw[position:position + namesize]
        if len(name) != namesize or name[-1:] != b"\0" or b"\0" in name[:-1]:
            raise runtime.ManifestError("invalid newc member name")
        position = (position + namesize + 3) & ~3
        data = raw[position:position + size]
        if len(data) != size:
            raise runtime.ManifestError("truncated newc member")
        position = (position + size + 3) & ~3
        if header[:6] == b"070702" and checksum != sum(data) & 0xFFFFFFFF:
            raise runtime.ManifestError("newc checksum mismatch")
        name = name[:-1].decode("utf-8", errors="strict")
        if name == "TRAILER!!!":
            if size or any(raw[position:]):
                raise runtime.ManifestError("unexpected trailing initramfs contents")
            ended = True
            break
        if name in (".", "./"):
            if not stat.S_ISDIR(mode):
                raise runtime.ManifestError("newc root must be a directory")
            continue
        name = canonical(name, dot_prefix=True)
        if name in entries:
            raise runtime.ManifestError("duplicate initramfs path")
        identity = (devmajor, devminor, ino)
        entries[name] = (mode, links, identity)
        if stat.S_ISREG(mode) and size:
            if identity in payloads and payloads[identity] != data:
                raise runtime.ManifestError("conflicting initramfs hardlink payload")
            payloads[identity] = data
    if not ended:
        raise runtime.ManifestError("initramfs trailer missing or member limit exceeded")
    result = {}
    if expected is None:
        manifest_entry = entries.get(runtime.MANIFEST)
        if manifest_entry is None:
            raise runtime.ManifestError("required initramfs runtime manifest missing")
        manifest = payloads.get(manifest_entry[2], b"")
        expected = runtime.signed_runtime.required_files(manifest)
    for name, limit in expected.items():
        for parent in Path(name).parents:
            if str(parent) != "." and (parent.as_posix() not in entries or not stat.S_ISDIR(entries[parent.as_posix()][0])):
                raise runtime.ManifestError("runtime path traverses a missing/non-directory initramfs member")
        if name not in entries:
            raise runtime.ManifestError("required initramfs runtime member missing: " + name)
        mode, links, identity = entries[name]
        value = payloads.get(identity, b"")
        if not stat.S_ISREG(mode) or not 0 < len(value) <= limit or links < 1 or (name != runtime.DAEMON and links != 1):
            raise runtime.ManifestError("bounded regular runtime initramfs member required")
        result[name] = value
    return result


def squashfs_files(raw: bytes) -> dict[str, bytes]:
    return runtime.signed_runtime.squashfs_files(raw)


def ext2_files(raw: bytes, board: str) -> dict[str, bytes]:
    # Reuse the independent exact-layout readers. This keeps publication
    # portable and preserves their allocation, owner, link and feature checks.
    if str(TOOLBOX) not in sys.path:
        sys.path.insert(0, str(TOOLBOX))
    if board in ("am1-s9se", "am1-s9k"):
        from dcent_toolbox.core.c43_native_image import ExtFiles
    elif board in ("am2-t17e", "am2-s17e"):
        from dcent_toolbox.core.bm1396_sd_media import ExtFiles
    else:
        from dcent_toolbox.core.bm1391_sd_media import ExtFiles
    filesystem = ExtFiles(raw)
    daemon_inode = filesystem.find(runtime.DAEMON)
    if daemon_inode is None or daemon_inode != filesystem.find("usr/bin/dcentrald"):
        raise runtime.ManifestError("native daemon alias must share the canonical inode")
    return {name: filesystem.read(name, maximum, expected_links=2 if name == runtime.DAEMON else 1)
            for name, maximum in runtime.signed_runtime.required_files(filesystem.read(runtime.MANIFEST, 4096)).items()}


def partition(stream, total: int, index: int) -> bytes:
    mbr = region(stream, 0, 512, 512)
    if mbr[510:] != b"\x55\xaa":
        raise runtime.ManifestError("native SD MBR missing")
    extents = []
    for number in range(4):
        boot, _, kind, _, start, count = struct.unpack_from("<B3sB3sII", mbr, 446 + number * 16)
        if not kind:
            if start or count:
                raise runtime.ManifestError("invalid empty MBR partition")
            continue
        begin, end = start * 512, (start + count) * 512
        if boot not in (0, 128) or kind not in (0x0B, 0x0C, 0x83) or not count or begin < 512 or end > total or any(begin < other_end and other_begin < end for _, other_begin, other_end, _ in extents):
            raise runtime.ManifestError("invalid or overlapping native SD partition")
        extents.append((number, begin, end, kind))
    matches = [entry for entry in extents if entry[0] == index]
    if len(matches) != 1 or (index == 0 and matches[0][3] not in (0x0B, 0x0C)) or (index == 1 and matches[0][3] != 0x83):
        raise runtime.ManifestError("canonical native runtime partition missing")
    _, begin, end, _ = matches[0]
    return region(stream, begin, end - begin, MAX_ROOT)


def artifact_files(artifact: Path, board: str) -> dict[str, bytes]:
    try:
        return _artifact_files(artifact, board)
    except (tarfile.TarError, zlib.error, struct.error, EOFError) as error:
        raise runtime.ManifestError("malformed release container: " + str(error)) from error


def _artifact_files(artifact: Path, board: str) -> dict[str, bytes]:
    producer = producer_for(board)
    with artifact_reader(artifact) as (stream, total):
        if producer.runtime_root == "sysupgrade-root":
            name = f"sysupgrade-{board}/root"
            payload = tar_payloads(stream, {name: MAX_ROOT})[name]
            return cpio_files(ramdisk(payload, arm64=True)) if producer.cargo_variant == "amlogic" else squashfs_files(payload)
        if producer.runtime_root == "bb-ramdisk":
            prefix = f"dcentos-{board}-sdcard/"
            files = tar_payloads(stream, {prefix + "ramdisk.gz": MAX_ROOT, prefix + "uramdisk.image.gz": MAX_ROOT})
            root = ramdisk(files[prefix + "ramdisk.gz"])
            if root != gunzip(files[prefix + "uramdisk.image.gz"]):
                raise runtime.ManifestError("BB boot and inspection ramdisks disagree")
            return cpio_files(root)
        if producer.runtime_root == "fat-ramdisk":
            if str(TOOLBOX) not in sys.path:
                sys.path.insert(0, str(TOOLBOX))
            from dcent_toolbox.core.flat_fat32 import read_flat_fat32
            boot = read_flat_fat32(partition(stream, total, 0), label="DCENTOS", limits={
                "BOOT.BIN": 4 * 1024**2, "devicetree.dtb": 1024**2, "system.bit": 4 * 1024**2,
                "uImage": 8 * 1024**2, "uEnv.txt": 65536, "uramdisk.image.gz": 48 * 1024**2})
            return squashfs_files(ramdisk(boot["uramdisk.image.gz"]))
        if producer.runtime_root == "partition2-squashfs":
            return squashfs_files(partition(stream, total, 1))
        if producer.runtime_root == "partition2-ext2":
            return ext2_files(partition(stream, total, 1), board)
        raise runtime.ManifestError("unsupported canonical runtime root format")


def verify_files(files: dict[str, bytes], board: str, channel: str, version: str, pubkey: Path, hardware_recipe: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="dcent-packaged-runtime-") as temporary:
        root = Path(temporary)
        for name, data in files.items():
            limits = {**LIMITS, runtime.SETTINGS_DEFAULT: runtime.signed_runtime.MAX_SETTINGS}
            if name not in limits or not 0 < len(data) <= limits[name]:
                raise runtime.ManifestError("unexpected or oversized runtime file")
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        return runtime.verify(root, board, channel, version, pubkey, hardware_recipe)


def verify_artifact_runtime(artifact: Path, manifest: Path, signature: Path, pubkey: Path,
                            board: str, channel: str, version: str, hardware_recipe: str) -> dict:
    files = artifact_files(artifact, board)
    if files[runtime.MANIFEST] != runtime.regular_bytes(manifest, 4096) or files[runtime.SIGNATURE] != runtime.regular_bytes(signature, 64):
        raise runtime.ManifestError("exported runtime pair differs from actual packaged pair")
    return verify_files(files, board, channel, version, pubkey, hardware_recipe)


def export_artifact_runtime(artifact: Path, pubkey: Path, board: str, channel: str,
                            version: str, hardware_recipe: str = "board-default") -> dict:
    files = artifact_files(artifact, board)
    document = verify_files(files, board, channel, version, pubkey, hardware_recipe)
    # Byte-copy the in-image signed pair; never re-sign/reconstruct metadata.
    with tempfile.TemporaryDirectory(prefix=".runtime-exports-", dir=artifact.parent) as temporary:
        staged = Path(temporary)
        for source, suffix in ((runtime.MANIFEST, ".runtime-image.json"), (runtime.SIGNATURE, ".runtime-image.sig")):
            destination = Path(str(artifact) + suffix)
            if destination.is_symlink() or (destination.exists() and not destination.is_file()):
                raise runtime.ManifestError("runtime export destination must be a regular path")
            candidate = staged / Path(source).name
            candidate.write_bytes(files[source])
            os.replace(candidate, destination)
    return document


def host_path_text(value: str) -> str:
    """Rewrite Git-Bash (MSYS) drive paths (/d/dir) and long-path prefixes.

    MSYS automatic argument conversion is per-argument and inconsistent on
    long release command lines (see runs drop1-20260916-cyg3sjwi and
    drop1-20260917-gnscaudk/c1e73bep). Normalizing at the lexical layer
    makes the shell conversion behavior irrelevant. POSIX and native
    inputs are returned unchanged; on non-Windows hosts this is identity.
    """
    if os.name != "nt" or not isinstance(value, str):
        return value
    text = value
    if text.startswith("\\\\?\\UNC\\"):
        text = "\\\\" + text[8:]
    elif text.startswith("//?/UNC/"):
        text = "//" + text[8:]
    else:
        for prefix in ("\\\\?\\", "//?/"):
            if text.startswith(prefix):
                text = text[len(prefix) :]
                break
    if (
        len(text) >= 2
        and text[0] == "/"
        and text[1].isascii()
        and text[1].isalpha()
        and (len(text) == 2 or text[2] == "/")
    ):
        return text[1].upper() + ":/" + text[3:]
    return text


def host_path(path_text: str) -> Path:
    """argparse Path type normalized through host_path_text."""
    return Path(host_path_text(path_text))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("export", "verify"))
    parser.add_argument("--artifact", required=True, type=host_path)
    parser.add_argument("--board-target", required=True)
    parser.add_argument("--channel", required=True, choices=("beta", "stable"))
    parser.add_argument("--version", required=True)
    parser.add_argument("--pubkey", required=True, type=host_path)
    parser.add_argument("--hardware-recipe", default="board-default")
    args = parser.parse_args()
    try:
        if args.action == "export":
            result = export_artifact_runtime(args.artifact, args.pubkey, args.board_target, args.channel, args.version, args.hardware_recipe)
        else:
            result = verify_artifact_runtime(args.artifact, Path(str(args.artifact) + ".runtime-image.json"), Path(str(args.artifact) + ".runtime-image.sig"), args.pubkey, args.board_target, args.channel, args.version, args.hardware_recipe)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, tarfile.TarError, zlib.error) as error:
        print(f"ERROR: packaged runtime: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
