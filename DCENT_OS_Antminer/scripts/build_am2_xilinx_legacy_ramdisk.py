#!/usr/bin/env python3
"""Build a target-bound AM2 Xilinx U-Boot legacy ramdisk on the host.

The source is a Buildroot ``rootfs.cpio.gz``.  This producer validates its
target and management content without extracting it, inserts the external-
media ephemeral-root marker into a copy, deterministically recompresses that
copy, and wraps it as a Linux/ARM/gzip U-Boot ramdisk.  It never contacts or
writes a device and grants no boot, media-write, or install authority.
"""

from __future__ import annotations

import argparse
import binascii
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
from typing import BinaryIO, Mapping
import zlib


SCHEMA = "dcentos.am2_xilinx_legacy_ramdisk.v1"
EPHEMERAL_MARKER = "etc/dcentos/external-media-ephemeral-root"
UBOOT_MAGIC = 0x27051956
MAX_SOURCE_BYTES = 32 * 1024 * 1024
MAX_CPIO_BYTES = 256 * 1024 * 1024
MAX_CPIO_ENTRIES = 65_536
COPY_CHUNK_BYTES = 1024 * 1024
EXTERNAL_MEDIA_RUNLEVEL_SHA256 = {
    "etc/init.d/rcS": "91895a0c0faa460de1ce9ee27cf9773ce88203670886f4b7473b54551ccfbefb",
    "etc/init.d/rcK": "56520de8349b02e2c36d71ba62ac9d62f92286126c54c470fce80e4d9a1dd5cc",
}
EXTERNAL_MEDIA_ALLOWED_INIT_SHA256 = {
    "etc/init.d/S01syslogd": "04e70e4d94d046c59f4863e33b3f78ec43faceb3e31e1115c78b682b78a052de",
    "etc/init.d/S02klogd": "e2f967bf785912d605e5dd8055e1c2c668e8523a88df1c39109df00eb9564285",
    "etc/init.d/S40network": "6dc692692f4fa8fc6b8e69a88f2bc5a55665e021279b7591fe806e4154770807",
    "etc/init.d/S41ntp": "17ceed6f66997f9d22e628f134855ff25fc77f8b02d968fd1431320044c594f2",
    "etc/init.d/S43logrotate": "6f7f8c44b22ced4c43a00465136e314b7b10da67b673144bb64bf677f0fa4a6a",
    "etc/init.d/S45persistent": "efc67721a90f8f48a9673822bfcdae9c98bc3223ab35651be9ff813ce96c90ff",
    "etc/init.d/S50dropbear": "a216df4737ca71405ad87ff61de9082a9f89b1b8a7d9d43126ca0f8462fb5d49",
}
EXTERNAL_MEDIA_DROPBEAR_DEFAULT_SHA256 = (
    "83e6818af133ab36d6269a2290a454b0b5b3f3d771d5d17657c67c81f716540d"
)
FORBIDDEN_SOURCED_CONFIG_MEMBERS = frozenset(
    {"etc/network/static", "etc/default/syslogd", "etc/default/klogd"}
)
WINDOWS_DEVICE_PREFIXES = ("\\\\.\\", "\\\\?\\", "//./", "//?/")
WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)


class LegacyRamdiskError(ValueError):
    """The requested host artifact operation is not safely admitted."""


@dataclass(frozen=True)
class TargetProfile:
    build_target: str
    payload_board_target: str
    defconfig: str
    idle_config_paths: tuple[str, ...]
    update_window_bytes: int
    variant: str
    platform: str = "zynq-bm3-am2"
    board_family: str = "am2"

    @property
    def image_name(self) -> str:
        return f"DCENT_OS {self.payload_board_target}"


TARGETS: Mapping[str, TargetProfile] = {
    "am2-s19j": TargetProfile(
        "am2-s19j",
        "am2-s19j",
        "dcentos_am2_s19jpro_defconfig",
        ("etc/dcentrald.toml", "etc/dcentrald/xil_override.toml"),
        12_876_990,
        "s19jpro",
    ),
    "am2-s19pro": TargetProfile(
        "am2-s19pro",
        "am2-s19pro",
        "dcentos_am2_s19pro_defconfig",
        ("etc/dcentrald.toml",),
        12_867_731,
        "s19pro",
    ),
}

CORE_REQUIRED_MEMBERS = frozenset(
    {
        "bin/busybox",
        "init",
        "sbin/init",
        "usr/sbin/dropbear",
        "usr/local/bin/dcentrald",
        "etc/dcentos/board_target",
        "etc/dcentos/board_family",
        "etc/dcentos/platform",
        "etc/dcentos/dcentos-init.sha256",
        "etc/dcentos/first-boot-grace",
        "etc/dcentrald-target.conf",
        "etc/default/dropbear",
        "etc/dcentos-early-init.sh",
        "usr/libexec/dcentos/zynq-external-media-ephemeral.sh",
        "etc/init.d/rcS",
        "etc/init.d/rcK",
        *EXTERNAL_MEDIA_ALLOWED_INIT_SHA256,
    }
)
SOURCE_POLICY_MEMBERS = frozenset(
    {
        "etc/init.d/S82dcentrald",
        "etc/init.d/S99upgrade",
    }
)
SELECTED_MEMBERS = CORE_REQUIRED_MEMBERS | SOURCE_POLICY_MEMBERS


@dataclass(frozen=True)
class SourceSnapshot:
    path: Path
    compressed: bytes
    sha256: str


@dataclass(frozen=True)
class CpioAnalysis:
    uncompressed_sha256: str
    uncompressed_size: int
    entry_count: int
    selected: Mapping[str, tuple[int, bytes]]
    trailer_offset: int
    maximum_inode: int
    marker_present: bool
    member_spans: Mapping[str, tuple[int, int]]
    member_modes: Mapping[str, int]
    auto_start_names: tuple[str, ...]


def _is_reparse(info: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(getattr(info, "st_file_attributes", 0) & marker)


def _path_key(path: Path) -> str:
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def _reject_device_namespace(path: Path, *, label: str) -> None:
    text = os.fspath(path)
    normalized = text.replace("\\", "/")
    if (
        text.startswith(WINDOWS_DEVICE_PREFIXES)
        or normalized.startswith("//")
        or normalized == "/dev"
        or normalized.startswith("/dev/")
    ):
        raise LegacyRamdiskError(f"{label} must not use a UNC or device namespace")
    _drive, tail = os.path.splitdrive(text)
    if os.name == "nt" and ":" in tail:
        raise LegacyRamdiskError(f"{label} must not use an alternate data stream")
    stem = path.name.split(".", 1)[0].rstrip(" .").upper()
    if stem in WINDOWS_RESERVED_NAMES:
        raise LegacyRamdiskError(f"{label} uses a reserved device name")


def _read_source_once(path: Path) -> SourceSnapshot:
    _reject_device_namespace(path, label="source")
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise LegacyRamdiskError(f"cannot stat source CPIO.GZ: {exc}") from exc
    if not stat.S_ISREG(before.st_mode) or _is_reparse(before):
        raise LegacyRamdiskError("source CPIO.GZ must be a non-reparse regular file")
    if getattr(before, "st_nlink", 1) != 1:
        raise LegacyRamdiskError("source CPIO.GZ must have exactly one hard link")
    if before.st_size < 18 or before.st_size > MAX_SOURCE_BYTES:
        raise LegacyRamdiskError("source CPIO.GZ size is outside the safe bound")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LegacyRamdiskError(f"cannot open source CPIO.GZ safely: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or getattr(opened, "st_nlink", 1) != 1
            or not os.path.samestat(before, opened)
        ):
            raise LegacyRamdiskError("source CPIO.GZ identity changed while opening")
        chunks: list[bytes] = []
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise LegacyRamdiskError("source CPIO.GZ was truncated while reading")
            chunks.append(chunk)
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise LegacyRamdiskError("source CPIO.GZ grew while reading")
        after = os.fstat(descriptor)
        if (
            after.st_size != opened.st_size
            or after.st_mtime_ns != opened.st_mtime_ns
            or after.st_ctime_ns != opened.st_ctime_ns
            or not os.path.samestat(opened, after)
        ):
            raise LegacyRamdiskError("source CPIO.GZ changed while reading")
        try:
            current = os.lstat(path)
        except OSError as exc:
            raise LegacyRamdiskError("source CPIO.GZ disappeared while reading") from exc
        if not os.path.samestat(opened, current) or _is_reparse(current):
            raise LegacyRamdiskError("source CPIO.GZ pathname identity changed while reading")
        return SourceSnapshot(path=path, compressed=b"".join(chunks), sha256=digest.hexdigest())
    finally:
        os.close(descriptor)


def _decompress_exact_gzip(data: bytes) -> bytes:
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        output = decoder.decompress(data, MAX_CPIO_BYTES + 1)
    except zlib.error as exc:
        raise LegacyRamdiskError("source gzip decompression failed") from exc
    if len(output) > MAX_CPIO_BYTES or decoder.unconsumed_tail:
        raise LegacyRamdiskError("source CPIO exceeds the decompression bound")
    try:
        output += decoder.flush(MAX_CPIO_BYTES + 1 - len(output))
    except zlib.error as exc:
        raise LegacyRamdiskError("source gzip finalization failed") from exc
    if len(output) > MAX_CPIO_BYTES or not decoder.eof or decoder.unused_data:
        raise LegacyRamdiskError("source gzip is incomplete, concatenated, or has trailing bytes")
    return output


def _compress_deterministic_gzip(data: bytes) -> bytes:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = compressor.compress(data) + compressor.flush()
    # RFC 1952 header: deflate, no optional fields, mtime=0, max compression,
    # OS=255.  Constructing it explicitly avoids host-dependent gzip headers.
    header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
    trailer = struct.pack("<II", binascii.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    result = header + body + trailer
    if _decompress_exact_gzip(result) != data:
        raise LegacyRamdiskError("deterministic gzip semantic readback failed")
    return result


def _safe_member_name(raw_name: bytes) -> str:
    try:
        name = raw_name.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyRamdiskError("newc member name is not UTF-8") from exc
    normalized = name[2:] if name.startswith("./") else name
    parts = normalized.replace("\\", "/").split("/")
    if (
        not normalized
        or normalized.startswith("/")
        or ".." in parts
        or "" in parts
        or "\0" in normalized
    ):
        raise LegacyRamdiskError("newc archive contains an unsafe member path")
    return normalized


def _analyze_newc(data: bytes) -> CpioAnalysis:
    selected_names = SELECTED_MEMBERS | {
        EPHEMERAL_MARKER,
        "etc/dcentrald.toml",
        "etc/dcentrald/xil_override.toml",
        "etc/init.d/S81dcentos-xil-seed",
    }
    selected: dict[str, tuple[int, bytes]] = {}
    member_spans: dict[str, tuple[int, int]] = {}
    member_modes: dict[str, int] = {}
    auto_start_names: list[str] = []
    seen: set[str] = set()
    offset = 0
    count = 0
    maximum_inode = 0
    for _ in range(MAX_CPIO_ENTRIES):
        if offset + 110 > len(data) or data[offset : offset + 6] != b"070701":
            raise LegacyRamdiskError("source is not an exact bounded newc archive")
        header = data[offset : offset + 110]
        try:
            fields = [int(header[position : position + 8], 16) for position in range(6, 110, 8)]
        except ValueError as exc:
            raise LegacyRamdiskError("newc header contains a non-hexadecimal field") from exc
        inode, mode, file_size, name_size = fields[0], fields[1], fields[6], fields[11]
        maximum_inode = max(maximum_inode, inode)
        if name_size < 1 or name_size > 4096:
            raise LegacyRamdiskError("newc member name length is invalid")
        name_start = offset + 110
        name_end = name_start + name_size
        if name_end > len(data) or data[name_end - 1] != 0:
            raise LegacyRamdiskError("newc member name is truncated")
        name = _safe_member_name(data[name_start : name_end - 1])
        if name in seen:
            raise LegacyRamdiskError(f"newc member is duplicated: {name}")
        seen.add(name)
        data_start = (name_end + 3) & ~3
        data_end = data_start + file_size
        if data_end > len(data):
            raise LegacyRamdiskError("newc member body is truncated")
        if name == "TRAILER!!!":
            if file_size != 0 or any(data[(data_end + 3) & ~3 :]):
                raise LegacyRamdiskError("newc trailer or trailing padding is invalid")
            return CpioAnalysis(
                uncompressed_sha256=hashlib.sha256(data).hexdigest(),
                uncompressed_size=len(data),
                entry_count=count,
                selected=selected,
                trailer_offset=offset,
                maximum_inode=maximum_inode,
                marker_present=EPHEMERAL_MARKER in seen,
                member_spans=member_spans,
                member_modes=member_modes,
                auto_start_names=tuple(sorted(auto_start_names)),
            )
        if mode == 0:
            raise LegacyRamdiskError(f"newc member has no file type/mode: {name}")
        if name in selected_names:
            selected[name] = (mode, data[data_start:data_end])
        count += 1
        next_offset = (data_end + 3) & ~3
        member_spans[name] = (offset, next_offset)
        member_modes[name] = mode
        if name.startswith("etc/init.d/S"):
            auto_start_names.append(name)
        offset = next_offset
    raise LegacyRamdiskError("newc archive exceeds the member-count bound")


def _regular_text(analysis: CpioAnalysis, path: str) -> str:
    mode, payload = analysis.selected[path]
    if mode & 0o170000 != 0o100000:
        raise LegacyRamdiskError(f"identity member is not a regular file: {path}")
    try:
        return payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise LegacyRamdiskError(f"identity member is not ASCII: {path}") from exc


def _validate_rootfs_contract(
    analysis: CpioAnalysis, profile: TargetProfile, *, external: bool = False
) -> None:
    required = CORE_REQUIRED_MEMBERS if external else SELECTED_MEMBERS
    missing = sorted(required - analysis.selected.keys())
    if missing:
        raise LegacyRamdiskError(
            "CPIO is missing required AM2 management members: " + ", ".join(missing)
        )
    forbidden = sorted(FORBIDDEN_SOURCED_CONFIG_MEMBERS & analysis.member_spans.keys())
    if forbidden:
        raise LegacyRamdiskError(
            "CPIO contains a root-sourced configuration outside the admitted closure: "
            + ", ".join(forbidden)
        )
    forbidden_devices = sorted(
        name
        for name in analysis.member_spans
        if name.startswith(("dev/mtd", "dev/ubi", "dev/nand"))
    )
    if forbidden_devices:
        raise LegacyRamdiskError(
            "CPIO contains pre-baked persistent-storage device nodes: "
            + ", ".join(forbidden_devices)
        )
    identity = {
        "etc/dcentos/board_target": profile.payload_board_target,
        "etc/dcentos/board_family": profile.board_family,
        "etc/dcentos/platform": profile.platform,
    }
    for path, expected in identity.items():
        actual = _regular_text(analysis, path).strip()
        if actual != expected:
            raise LegacyRamdiskError(
                f"rootfs identity mismatch at {path}: {actual!r} != {expected!r}"
            )
    target_config = _regular_text(analysis, "etc/dcentrald-target.conf")
    values: dict[str, str] = {}
    for raw_line in target_config.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise LegacyRamdiskError("dcentrald-target.conf contains an invalid assignment")
        key, value = line.split("=", 1)
        if key in values:
            raise LegacyRamdiskError(f"dcentrald-target.conf duplicates {key}")
        values[key] = value
    expected_values = {
        "BOARD_FAMILY": profile.board_family,
        "BOARD_TARGET": profile.payload_board_target,
        "PLATFORM": profile.platform,
        "SOC": "zynq-7000",
        "ARCH": "armv7",
        "VARIANT": profile.variant,
    }
    for key, expected in expected_values.items():
        if values.get(key) != expected:
            raise LegacyRamdiskError(
                f"dcentrald-target.conf {key} mismatch: {values.get(key)!r} != {expected!r}"
            )
    for path in required:
        mode, payload = analysis.selected[path]
        if mode & 0o170000 not in {0o100000, 0o120000}:
            raise LegacyRamdiskError(f"required AM2 member is not a file or symlink: {path}")
        if not payload:
            raise LegacyRamdiskError(f"required AM2 member is empty: {path}")
    for binary_path in (
        "bin/busybox",
        "sbin/init",
        "usr/sbin/dropbear",
        "usr/local/bin/dcentrald",
    ):
        _validate_arm_elf(binary_path, analysis.selected[binary_path])
    init_digest_mode, init_digest_payload = analysis.selected[
        "etc/dcentos/dcentos-init.sha256"
    ]
    expected_init_digest = (
        hashlib.sha256(analysis.selected["sbin/init"][1]).hexdigest() + "\n"
    ).encode("ascii")
    if (
        init_digest_mode & 0o170000 != 0o100000
        or init_digest_payload != expected_init_digest
    ):
        raise LegacyRamdiskError(
            "dcentos-init self-hash does not bind the exact /sbin/init bytes"
        )
    init_mode, init_target = analysis.selected["init"]
    if init_mode & 0o170000 != 0o120000 or init_target not in {b"sbin/init", b"/sbin/init"}:
        raise LegacyRamdiskError("initramfs /init must resolve exactly to /sbin/init")
    for config_path in profile.idle_config_paths:
        member = analysis.selected.get(config_path)
        if member is None:
            raise LegacyRamdiskError(f"required idle-first config is missing: {config_path}")
        mode, payload = member
        if mode & 0o170000 != 0o100000 or not payload:
            raise LegacyRamdiskError(f"idle-first config is not a nonempty regular file: {config_path}")
        _validate_idle_config(config_path, payload)
    dropbear_mode, dropbear_defaults = analysis.selected["etc/default/dropbear"]
    if dropbear_mode & 0o170000 != 0o100000:
        raise LegacyRamdiskError("dropbear defaults are not a regular file")
    if hashlib.sha256(dropbear_defaults).hexdigest() != EXTERNAL_MEDIA_DROPBEAR_DEFAULT_SHA256:
        raise LegacyRamdiskError("dropbear defaults hash is outside the external-media closure")
    if (
        profile.payload_board_target == "am2-s19pro"
        and "etc/dcentrald/xil_override.toml" in analysis.selected
    ):
        raise LegacyRamdiskError("am2-s19pro rootfs must not contain the BM1362 XIL override")
    # The XIL .25 seeder is a lab-only member (staged only behind
    # DCENT_LAB_XIL25_SEED=1, never in release builds), so its absence is the
    # normal am2-s19j release shape and is not required here.
    xil25_seed = "etc/init.d/S81dcentos-xil-seed"
    if profile.payload_board_target == "am2-s19pro" and xil25_seed in analysis.selected:
        raise LegacyRamdiskError("am2-s19pro rootfs must not contain the S19j XIL .25 seed")


def _validate_arm_elf(path: str, member: tuple[int, bytes]) -> None:
    mode, payload = member
    if mode & 0o170000 != 0o100000 or not mode & 0o111 or len(payload) < 84:
        raise LegacyRamdiskError(f"required runtime binary is not a regular ARM ELF: {path}")
    if payload[:7] != b"\x7fELF\x01\x01\x01":
        raise LegacyRamdiskError(f"required runtime binary has wrong ELF identity: {path}")
    elf_type, machine, version = struct.unpack_from("<HHI", payload, 16)
    entry, program_header_offset = struct.unpack_from("<II", payload, 24)
    header_size, program_header_size, program_header_count = struct.unpack_from(
        "<HHH", payload, 40
    )
    if (
        elf_type not in {2, 3}
        or machine != 40
        or version != 1
        or header_size != 52
        or program_header_size != 32
        or not 1 <= program_header_count <= 64
        or program_header_offset < header_size
        or program_header_offset + program_header_size * program_header_count > len(payload)
    ):
        raise LegacyRamdiskError(f"required runtime binary is not ARMv7 executable ELF: {path}")
    entry_is_executable = False
    for index in range(program_header_count):
        offset = program_header_offset + index * program_header_size
        segment_type, file_offset, virtual_address, _physical_address, file_size, memory_size, flags, _alignment = struct.unpack_from(
            "<8I", payload, offset
        )
        if segment_type != 1:
            continue
        if (
            file_size == 0
            or memory_size < file_size
            or file_offset + file_size > len(payload)
        ):
            raise LegacyRamdiskError(f"required runtime binary has an invalid PT_LOAD: {path}")
        if flags & 0x1 and virtual_address <= entry < virtual_address + memory_size:
            entry_is_executable = True
    if not entry_is_executable:
        raise LegacyRamdiskError(
            f"required runtime binary entry point is not in an executable PT_LOAD: {path}"
        )


def _toml_value(text: str, section: str, key: str) -> str | None:
    current = ""
    found: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            continue
        if current != section or "=" not in line:
            continue
        candidate, value = line.split("=", 1)
        if candidate.strip() != key:
            continue
        if found is not None:
            raise LegacyRamdiskError(f"idle-first config duplicates [{section}] {key}")
        found = value.strip()
    return found


def _validate_idle_config(path: str, payload: bytes) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LegacyRamdiskError(f"idle-first config is not UTF-8: {path}") from exc
    enabled = _toml_value(text, "mining", "enabled")
    pool_url = _toml_value(text, "pool", "url")
    hash_on_disconnect = _toml_value(text, "hash_on_disconnect", "enabled")
    if enabled != "false":
        raise LegacyRamdiskError(f"{path} is not idle-first: [mining] enabled must be false")
    if pool_url not in {'""', "''"}:
        raise LegacyRamdiskError(f"{path} is not idle-first: [pool] url must be empty")
    if hash_on_disconnect != "false":
        raise LegacyRamdiskError(
            f"{path} is not idle-first: [hash_on_disconnect] enabled must be false"
        )


def _validate_source_policy_scripts(analysis: CpioAnalysis) -> dict[str, str]:
    if analysis.marker_present:
        raise LegacyRamdiskError("ordinary source CPIO must not carry the ephemeral-root marker")
    required_tokens = {
        "etc/dcentos-early-init.sh": (
            b"/usr/libexec/dcentos/zynq-external-media-ephemeral.sh",
            b"EXTERNAL_MEDIA_EPHEMERAL=1",
            b"MTD/UBI device-node creation suppressed",
            b"elif mount -t ubifs",
            b"External-media identity is absent or unsafe",
            b"hardware writes suppressed",
            b"exit 82",
        ),
        "usr/libexec/dcentos/zynq-external-media-ephemeral.sh": (
            b"dcent_external_media_prepare_ephemeral_root",
            b"mount -t tmpfs -o size=16m,mode=0755,nosuid,nodev,noexec",
            b"dcent_external_media_data_is_ephemeral",
            b"external-media-ephemeral-ready",
        ),
        "etc/init.d/S45persistent": (
            b"persistent save/restore disabled; /data is volatile",
            b"external-media-ephemeral-ready",
        ),
        "etc/init.d/S82dcentrald": (
            b"DCENTOS_EXTERNAL_MEDIA_MARKER",
            b"[SKIP] dcentrald hardware owner: external-media boot remains safe-idle/management-only",
        ),
        "etc/init.d/S99upgrade": (b"U-Boot environment commit is disabled",),
        "etc/init.d/rcS": (
            b"DCENTOS_EXTERNAL_MEDIA_START_ALLOWLIST=",
            b"skipped init service:",
            b"run_start_script",
        ),
        "etc/init.d/rcK": (
            b"DCENTOS_EXTERNAL_MEDIA_STOP_ALLOWLIST=",
            b"restricted shutdown allowlist active",
            b"run_stop_script",
        ),
    }
    if "etc/init.d/S81dcentos-xil-seed" in analysis.selected:
        required_tokens["etc/init.d/S81dcentos-xil-seed"] = (
            b"DCENTOS_EXTERNAL_MEDIA_MARKER",
            b"External-media posture: XIL .25 persistent mining seed is disabled",
        )
    hashes: dict[str, str] = {}
    for path, tokens in required_tokens.items():
        mode, payload = analysis.selected[path]
        if mode & 0o170000 != 0o100000:
            raise LegacyRamdiskError(f"external-media policy script is not regular: {path}")
        missing = [token.decode("ascii") for token in tokens if token not in payload]
        if missing:
            raise LegacyRamdiskError(
                f"external-media policy contract is incomplete in {path}: " + ", ".join(missing)
            )
        hashes[path] = hashlib.sha256(payload).hexdigest()
        expected_hash = EXTERNAL_MEDIA_RUNLEVEL_SHA256.get(path)
        if expected_hash is not None and hashes[path] != expected_hash:
            raise LegacyRamdiskError(
                f"external-media runlevel dispatcher hash mismatch: {path}"
            )
    for path, expected_hash in EXTERNAL_MEDIA_ALLOWED_INIT_SHA256.items():
        mode, payload = analysis.selected[path]
        if mode & 0o170000 != 0o100000 or not mode & 0o111:
            raise LegacyRamdiskError(
                f"external-media allowed init service is not executable: {path}"
            )
        actual_hash = hashlib.sha256(payload).hexdigest()
        if actual_hash != expected_hash:
            raise LegacyRamdiskError(
                f"external-media allowed init service hash mismatch: {path}"
            )
        hashes[path] = actual_hash
    return hashes


def _newc_empty_regular(name: str, inode: int) -> bytes:
    name_bytes = name.encode("utf-8") + b"\0"
    values = (inode, 0o100444, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(name_bytes), 0)
    result = b"070701" + b"".join(f"{value:08X}".encode("ascii") for value in values)
    result += name_bytes
    result += b"\0" * (-len(result) % 4)
    return result


def _build_external_cpio(
    data: bytes, analysis: CpioAnalysis
) -> tuple[bytes, tuple[str, ...]]:
    if analysis.marker_present:
        raise LegacyRamdiskError(
            "ordinary rootfs CPIO already contains the external-media-only marker"
        )
    inode = analysis.maximum_inode + 1
    if inode > 0xFFFFFFFF:
        raise LegacyRamdiskError("cannot allocate a bounded inode for the external-media marker")
    allowed = frozenset(EXTERNAL_MEDIA_ALLOWED_INIT_SHA256)
    removed = tuple(sorted(set(analysis.auto_start_names) - allowed))
    kept = bytearray()
    cursor = 0
    for name, (start, end) in sorted(analysis.member_spans.items(), key=lambda item: item[1][0]):
        if start < cursor or end > analysis.trailer_offset:
            raise LegacyRamdiskError("newc member spans overlap or escape the archive")
        kept.extend(data[cursor:start])
        if name in allowed or not name.startswith("etc/init.d/S"):
            kept.extend(data[start:end])
        cursor = end
    kept.extend(data[cursor:analysis.trailer_offset])
    result = bytes(kept) + _newc_empty_regular(EPHEMERAL_MARKER, inode) + data[analysis.trailer_offset:]
    transformed = _analyze_newc(result)
    if not transformed.marker_present:
        raise LegacyRamdiskError("external-media marker insertion readback failed")
    mode, payload = transformed.selected[EPHEMERAL_MARKER]
    if mode & 0o170000 != 0o100000 or payload:
        raise LegacyRamdiskError("external-media marker has invalid content or type")
    unexpected = sorted(set(transformed.auto_start_names) - allowed)
    missing = sorted(allowed - set(transformed.auto_start_names))
    if unexpected or missing:
        raise LegacyRamdiskError(
            "external-media init allowlist transformation failed; "
            f"unexpected={unexpected}, missing={missing}"
        )
    return result, removed


def _legacy_image(compressed: bytes, profile: TargetProfile, epoch: int) -> bytes:
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise LegacyRamdiskError("source-date epoch must fit an unsigned 32-bit field")
    name = profile.image_name.encode("ascii")
    header = bytearray(
        struct.pack(
            ">7I4B32s",
            UBOOT_MAGIC,
            0,
            epoch,
            len(compressed),
            0,
            0,
            binascii.crc32(compressed) & 0xFFFFFFFF,
            5,
            2,
            3,
            1,
            name.ljust(32, b"\0"),
        )
    )
    struct.pack_into(">I", header, 4, binascii.crc32(header) & 0xFFFFFFFF)
    image = bytes(header) + compressed
    if len(image) > profile.update_window_bytes:
        raise LegacyRamdiskError(
            "target-bound legacy ramdisk does not fit the exact vendor update window: "
            f"{len(image)} > {profile.update_window_bytes} bytes"
        )
    _validate_legacy_image(image, profile, epoch)
    return image


def _validate_legacy_image(image: bytes, profile: TargetProfile, epoch: int) -> None:
    fields = struct.unpack(">7I4B32s", image[:64])
    magic, header_crc, timestamp, size, load, entry, data_crc = fields[:7]
    os_id, architecture, image_type, compression, raw_name = fields[7:]
    header = bytearray(image[:64])
    header[4:8] = b"\0\0\0\0"
    if (
        magic != UBOOT_MAGIC
        or header_crc != binascii.crc32(header) & 0xFFFFFFFF
        or timestamp != epoch
        or size != len(image) - 64
        or load != 0
        or entry != 0
        or data_crc != binascii.crc32(image[64:]) & 0xFFFFFFFF
        or (os_id, architecture, image_type, compression) != (5, 2, 3, 1)
        or raw_name.rstrip(b"\0") != profile.image_name.encode("ascii")
    ):
        raise LegacyRamdiskError("generated legacy image failed semantic readback")


def _validate_output_path(output: Path, source: Path) -> tuple[Path, Path, os.stat_result]:
    _reject_device_namespace(output, label="output")
    if output.suffix.lower() != ".uimg":
        raise LegacyRamdiskError("output must use the .uimg suffix")
    absolute = Path(os.path.abspath(os.fspath(output)))
    manifest = Path(f"{absolute}.manifest.json")
    if _path_key(absolute) == _path_key(source) or _path_key(manifest) == _path_key(source):
        raise LegacyRamdiskError("output path aliases the protected source")
    if os.path.lexists(absolute) or os.path.lexists(manifest):
        raise LegacyRamdiskError("output and manifest must both be new paths")
    parent = absolute.parent
    try:
        parent_info = os.lstat(parent)
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise LegacyRamdiskError(f"output parent is not an existing safe directory: {exc}") from exc
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or _is_reparse(parent_info)
        or _path_key(parent) != _path_key(resolved_parent)
    ):
        raise LegacyRamdiskError("output parent must be an existing non-reparse directory")
    return absolute, manifest, parent_info


def _write_all(handle: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    offset = 0
    while offset < len(view):
        written = handle.write(view[offset : offset + COPY_CHUNK_BYTES])
        if written is None or written <= 0:
            raise LegacyRamdiskError("exclusive output write made no progress")
        offset += written


def _exclusive_write(path: Path, data: bytes, parent_info: os.stat_result) -> os.stat_result:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    opened: os.stat_result | None = None
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or getattr(opened, "st_nlink", 1) != 1:
            raise LegacyRamdiskError("exclusive output is not a single-link regular file")
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            _write_all(handle, data)
            handle.flush()
            os.fsync(descriptor)
        final = os.fstat(descriptor)
        current = os.lstat(path)
        current_parent = os.lstat(path.parent)
        if (
            not os.path.samestat(opened, final)
            or not os.path.samestat(final, current)
            or not os.path.samestat(parent_info, current_parent)
            or final.st_size != len(data)
            or getattr(final, "st_nlink", 1) != 1
            or _is_reparse(current)
        ):
            raise LegacyRamdiskError("exclusive output identity changed during publication")
        return final
    except (OSError, LegacyRamdiskError):
        _remove_owned(path, opened)
        raise
    finally:
        os.close(descriptor)


def _remove_owned(path: Path, identity: os.stat_result | None) -> None:
    if identity is None:
        return
    try:
        current = os.lstat(path)
        if os.path.samestat(identity, current) and stat.S_ISREG(current.st_mode):
            os.unlink(path)
    except OSError:
        pass


def _readback(path: Path, identity: os.stat_result, expected: bytes) -> None:
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        current = os.lstat(path)
        if (
            not os.path.samestat(identity, opened)
            or not os.path.samestat(opened, current)
            or not stat.S_ISREG(opened.st_mode)
            or getattr(opened, "st_nlink", 1) != 1
            or _is_reparse(current)
        ):
            raise LegacyRamdiskError("published output identity changed before readback")
        chunks: list[bytes] = []
        remaining = len(expected)
        while remaining:
            chunk = os.read(descriptor, min(COPY_CHUNK_BYTES, remaining))
            if not chunk:
                raise LegacyRamdiskError("published output was truncated before readback")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or b"".join(chunks) != expected:
            raise LegacyRamdiskError("published output readback mismatch")
        final = os.fstat(descriptor)
        current = os.lstat(path)
        if not os.path.samestat(opened, final) or not os.path.samestat(final, current):
            raise LegacyRamdiskError("published output identity changed during readback")
    finally:
        os.close(descriptor)


def _manifest_document(
    profile: TargetProfile,
    source: SourceSnapshot,
    source_analysis: CpioAnalysis,
    external_cpio: bytes,
    external_gzip: bytes,
    policy_script_hashes: Mapping[str, str],
    removed_auto_start_members: tuple[str, ...],
    output: Path,
    image: bytes,
    epoch: int,
) -> dict[str, object]:
    early_init = source_analysis.selected["etc/dcentos-early-init.sh"][1]
    marker_reference_present = ("/" + EPHEMERAL_MARKER).encode("ascii") in early_init
    return {
        "schema": SCHEMA,
        "product": "DCENT_OS",
        "artifact_type": "uboot-legacy-linux-arm-gzip-initramfs",
        "build_target": profile.build_target,
        "buildroot_defconfig": profile.defconfig,
        "payload_board_target": profile.payload_board_target,
        "control_board_family": profile.platform,
        "source": {
            "name": source.path.name,
            "size": len(source.compressed),
            "sha256": source.sha256,
            "format": "buildroot-newc-cpio-gzip",
            "uncompressed_size": source_analysis.uncompressed_size,
            "uncompressed_sha256": source_analysis.uncompressed_sha256,
            "entry_count": source_analysis.entry_count,
            "ordinary_rootfs_marker_absent": not source_analysis.marker_present,
        },
        "validated_member_sha256": {
            path: hashlib.sha256(payload).hexdigest()
            for path, (_mode, payload) in sorted(source_analysis.selected.items())
        },
        "external_media_cpio": {
            "format": "newc-cpio-gzip",
            "uncompressed_size": len(external_cpio),
            "uncompressed_sha256": hashlib.sha256(external_cpio).hexdigest(),
            "compressed_size": len(external_gzip),
            "compressed_sha256": hashlib.sha256(external_gzip).hexdigest(),
            "ephemeral_marker": "/" + EPHEMERAL_MARKER,
            "ephemeral_marker_inserted": True,
            "early_init_marker_reference_present": marker_reference_present,
            "idle_first_config_verified": True,
            "policy_scripts_verified": True,
            "policy_script_sha256": dict(sorted(policy_script_hashes.items())),
            "auto_start_allowlist_sha256": dict(
                sorted(EXTERNAL_MEDIA_ALLOWED_INIT_SHA256.items())
            ),
            "auto_start_members_removed": list(removed_auto_start_members),
            "unexpected_auto_start_members_present": False,
            "custom_pid1_broad_enumeration_contained_by_artifact_filter": True,
            "pid1_binary_self_hash_binding_verified": True,
            "pid1_external_media_start_order": [
                "S45persistent",
                "S01syslogd",
                "S02klogd",
                "S40network",
                "S41ntp",
                "S43logrotate",
                "S50dropbear",
            ],
            "pid1_external_media_gate_release_attested": False,
            "ephemeral_policy_semantics_proven": False,
        },
        "output": {
            "name": output.name,
            "size": len(image),
            "sha256": hashlib.sha256(image).hexdigest(),
        },
        "exact_vendor_update_window_bytes": profile.update_window_bytes,
        "legacy_ramdisk_fits_vendor_update_window": True,
        "uboot": {
            "magic": "0x27051956",
            "timestamp": epoch,
            "name": profile.image_name,
            "os": "linux",
            "architecture": "arm",
            "image_type": "ramdisk",
            "compression": "gzip",
            "load_address": 0,
            "entry_address": 0,
        },
        "maturity": "Experimental",
        "proof_scope": "target-bound-host-legacy-ramdisk-artifact-only",
        "external_media_marker_inserted": True,
        "idle_first_config_verified": True,
        "policy_scripts_verified": True,
        "device_contact": "none",
        "network_contact": "none",
        "block_device_write": "none",
        "host_artifact_materialization_authorized": True,
        "external_media_write_authorized": False,
        "operator_boot_authorized": False,
        "persistent_install_authorized": False,
        "vendor_nand_execution_authorized": False,
        "cold_boot_witnessed": False,
        "first_stage_compatibility_proven": False,
        "required_next_evidence": [
            "independent release provenance and semantic attestation for the built rootfs",
            "exact target-bound donor BOOT/kernel/DTB/container admission",
            "physical SD selector and cold-boot witness on the exact controller tuple",
            "runtime management and safe-shutdown witness",
        ],
    }


def prepare_legacy_ramdisk(
    build_target: str,
    source_path: Path,
    output_path: Path,
    *,
    source_date_epoch: int = 0,
    execute: bool = False,
) -> dict[str, object]:
    """Validate, plan, and optionally publish one host-only legacy ramdisk."""

    profile = TARGETS.get(build_target)
    if profile is None:
        raise LegacyRamdiskError(
            "unsupported build target; admitted targets are am2-s19j and am2-s19pro"
        )
    source = _read_source_once(Path(source_path))
    source_cpio = _decompress_exact_gzip(source.compressed)
    source_analysis = _analyze_newc(source_cpio)
    _validate_rootfs_contract(source_analysis, profile)
    policy_script_hashes = _validate_source_policy_scripts(source_analysis)
    external_cpio, removed_auto_start_members = _build_external_cpio(
        source_cpio, source_analysis
    )
    external_analysis = _analyze_newc(external_cpio)
    _validate_rootfs_contract(external_analysis, profile, external=True)
    external_gzip = _compress_deterministic_gzip(external_cpio)
    image = _legacy_image(external_gzip, profile, source_date_epoch)
    output, manifest_path, parent_info = _validate_output_path(Path(output_path), source.path)
    document = _manifest_document(
        profile,
        source,
        source_analysis,
        external_cpio,
        external_gzip,
        policy_script_hashes,
        removed_auto_start_members,
        output,
        image,
        source_date_epoch,
    )
    document["state"] = (
        "host-artifact-generated-readback-verified"
        if execute
        else "host-artifact-plan-ready-no-output"
    )
    if not execute:
        document["manifest_path"] = str(manifest_path)
        return document

    manifest_bytes = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    output_identity: os.stat_result | None = None
    manifest_identity: os.stat_result | None = None
    try:
        output_identity = _exclusive_write(output, image, parent_info)
        _readback(output, output_identity, image)
        manifest_identity = _exclusive_write(manifest_path, manifest_bytes, parent_info)
        _readback(manifest_path, manifest_identity, manifest_bytes)
    except (OSError, LegacyRamdiskError) as exc:
        _remove_owned(manifest_path, manifest_identity)
        _remove_owned(output, output_identity)
        if isinstance(exc, LegacyRamdiskError):
            raise
        raise LegacyRamdiskError(f"exclusive artifact publication failed: {exc}") from exc
    document["output_path"] = str(output)
    document["manifest_path"] = str(manifest_path)
    return document


def _epoch_argument(value: str) -> int:
    try:
        epoch = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("epoch must be a base-10 integer") from exc
    if not 0 <= epoch <= 0xFFFFFFFF:
        raise argparse.ArgumentTypeError("epoch must fit an unsigned 32-bit field")
    return epoch


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-target", required=True, choices=sorted(TARGETS))
    parser.add_argument("--rootfs-cpio-gz", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--source-date-epoch",
        type=_epoch_argument,
        default=_epoch_argument(os.environ.get("SOURCE_DATE_EPOCH", "0")),
        help="deterministic U-Boot timestamp (default: SOURCE_DATE_EPOCH or 0)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="exclusively create the host artifact and manifest after validation",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = prepare_legacy_ramdisk(
            args.build_target,
            args.rootfs_cpio_gz,
            args.output,
            source_date_epoch=args.source_date_epoch,
            execute=args.execute,
        )
    except LegacyRamdiskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
