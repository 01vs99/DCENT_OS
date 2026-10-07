#!/usr/bin/env python3
"""Fail-closed producer for the S19k Pro persistent-image evidence set.

This module owns four boundaries that the inner Buildroot wrapper cannot
truthfully attest on its own:

* admission of one clean, signed, externally selected Git commit;
* exact-set sealing of a materialized, source-only dependency bundle;
* validation of two isolated offline build result stages; and
* equality-gated post-A/B signing derivation and no-replace v4 evidence.

It does not grant signing, install, flash, reboot, or target-contact authority.
The production CLI is intentionally POSIX-only because durable directory fsync
is part of the evidence contract.  Pure validation helpers remain portable so
their adversarial tests can run on developer workstations.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import json
import os
import re
import secrets
import selectors
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping, NoReturn, Protocol, Sequence


SOURCE_SCHEMA = "dcentos.s19k-hermetic-source-admission/v2"
DEPENDENCY_SELECTION_SCHEMA = "dcentos.s19k-hermetic-dependency-selection/v1"
DEPENDENCY_POLICY_SCHEMA = "dcentos.s19k-hermetic-dependency-policy/v1"
DEPENDENCY_BUNDLE_SCHEMA = "dcentos.s19k-hermetic-dependency-bundle/v2"
DEPENDENCY_OWNER_SCHEMA = "dcentos.s19k-hermetic-dependency-owner/v1"
RELEASE_INPUT_SCHEMA = "dcentos.s19k-hermetic-release-inputs/v2"
RELEASE_INPUT_OWNER_SCHEMA = "dcentos.s19k-hermetic-release-input-owner/v1"
MATERIALIZER_OBSERVATION_SCHEMA = "dcentos.s19k-hermetic-materializer-observation/v1"
MATERIALIZER_OWNER_SCHEMA = "dcentos.s19k-hermetic-materializer-owner/v2"
MATERIALIZER_SUCCESS_SCHEMA = "dcentos.s19k-hermetic-materializer-success/v1"
RUNTIME_OBSERVATION_SCHEMA = "dcentos.s19k-hermetic-runtime-observation/v1"
BUILD_RESULT_SCHEMA = "dcentos.s19k-hermetic-build-result/v2"
BUILD_OWNER_SCHEMA = "dcentos.s19k-hermetic-build-owner/v3"
BUILD_FAILURE_SCHEMA = "dcentos.s19k-hermetic-build-failure/v2"
BUILD_ATTESTATION_SCHEMA = "dcentos.s19k-reproducible-build-attestation/v1"
PRODUCER_RESULT_SCHEMA = "dcentos.s19k-hermetic-image-producer/v2"
BUILD_PAIR_CAPABILITY_SCHEMA = "dcentos.s19k-hermetic-build-pair-capability/v1"
SIGNER_RUNTIME_SCHEMA = "dcentos.s19k-hermetic-isolated-signer-runtime/v1"

BUILD_TARGET = "dcentos_am3_s19kpro_defconfig"
BUILD_ARCH = "aarch64"
INNER_PACKAGE_NAME = "dcentos-sysupgrade-am3-s19kpro.unsigned.tar"
RUNTIME_LOG_PREFIX = b"DCENT_S19K_HERMETIC_RUNTIME_OBSERVATION\n"
INNER_LOG_PREFIX = b"DCENT_S19K_HERMETIC_BUILD_LOG\n"
EVIDENCE_PUBLIC_FILES = (
    "build-a.unsigned.tar",
    "build-b.unsigned.tar",
    "build-a.json",
    "build-b.json",
    "host-preflight.json",
    "trusted-release-key.pem",
    "native-owner-verification.json",
    "stock-recovery-verification.json",
)
EVIDENCE_INPUT_FILES = (
    *EVIDENCE_PUBLIC_FILES,
    "dcentos-sysupgrade-am3-s19kpro.tar",
    "signer-inspect-after.json",
    "signer-inspect-before.json",
    "signer.log",
    "signer-runtime.json",
    "signing-receipt.json",
)
EVIDENCE_FINAL_FILES = (*EVIDENCE_INPUT_FILES, "verification.json")
BUILD_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "build_id",
        "build_root_id",
        "clean_build",
        "build_cache_reused",
        "network_used",
        "source_commit",
        "source_date_epoch",
        "build_target",
        "build_arch",
        "toolchain_id",
        "package_name",
        "package_sha256",
        "package_bytes",
    }
)
MUTABLE_ROOT_ROLES = (
    "source-exec",
    "cargo-home",
    "cargo-target",
    "buildroot-output",
    "tmp",
    "dashboard",
    "result",
    "logs",
)
DEPENDENCY_CLASSES = frozenset(
    {
        "amlogic-input",
        "buildroot-download",
        "buildroot-source",
        "cargo-index",
        "cargo-source",
        "dashboard-dependency",
        "toolchain-archive",
    }
)
DEPENDENCY_POLICY_SHA256 = (
    "f7101ab4eff6fe2eb59a4080f0d3aef96d9e6ef525e0071c861298c4d4378fa1"
)
DEPENDENCY_POLICY_RELATIVE = "DCENT_OS_Antminer/scripts/s19k_hermetic_dependencies.json"
REQUIRED_DEPENDENCY_CLASSES = (
    "amlogic-input",
    "buildroot-download",
    "buildroot-source",
    "cargo-source",
    "dashboard-dependency",
    "toolchain-archive",
)
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_KEY_BYTES = 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024 * 1024
MAX_PACKAGE_BYTES = 256 * 1024 * 1024
MAX_DEPENDENCY_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_DEPENDENCY_FILES = 1_000_000
MAX_SOURCE_EPOCH = 0xFFFFFFFF
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
FULL_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
OPENPGP_SIGNER = re.compile(r"openpgp:(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:@/-]{0,255}\Z")
IMMUTABLE_IMAGE = re.compile(
    r"(?:[a-z0-9._-]+(?::[0-9]+)?/)*[a-z0-9._-]+@sha256:[0-9a-f]{64}\Z"
)

# A result directory is deliberately not a production capability.  Only the
# coordinator that actually executed both builds can place a one-use binding
# in this process-local registry.  Nothing written by either build can mint or
# persist this authority, so copied/fabricated result stages cannot enter the
# v4 publication path and an interrupted invocation cannot be resumed as clean.
_ISSUED_BUILD_PAIR_CAPABILITIES: dict[str, bytes] = {}

# These names can only represent mutable/compiled build products in a sealed
# dependency bundle.  Source files named "target" are conservatively refused;
# a reviewed manifest can rename such source material before sealing.
FORBIDDEN_DIRECTORY_NAMES = frozenset(
    {
        "__pycache__",
        "node_modules",
        "output",
        "target",
    }
)
FORBIDDEN_BUILDROOT_COMPONENTS = frozenset(
    {"build", "host", "images", "staging", "target"}
)
FORBIDDEN_COMPILED_SUFFIXES = (
    ".class",
    ".d",
    ".dll",
    ".dylib",
    ".ko",
    ".o",
    ".obj",
    ".pyc",
    ".pyo",
    ".rlib",
    ".rmeta",
    ".so",
)


class ProducerError(RuntimeError):
    """A production-evidence boundary could not be proven."""


def fail(message: str) -> NoReturn:
    raise ProducerError(message)


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _exact_object(value: object, keys: Iterable[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(keys):
        expected = set(keys)
        actual = set(value) if isinstance(value, dict) else set()
        fail(
            f"{label} has an invalid key set "
            f"(missing={sorted(expected - actual)}, extra={sorted(actual - expected)})"
        )
    return value


def _is_reparse(metadata: os.stat_result) -> bool:
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(marker and getattr(metadata, "st_file_attributes", 0) & marker)


def _require_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail(f"{label} does not exist: {path}")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        fail(f"{label} must be a non-link directory: {path}")
    return metadata


_MOUNTINFO_ESCAPE = re.compile(r"\\([0-7]{3})")


def _decode_mountinfo_path(value: str) -> str:
    """Decode the octal escapes permitted in Linux mountinfo path fields."""

    return _MOUNTINFO_ESCAPE.sub(lambda match: chr(int(match.group(1), 8)), value)


def _linux_mount_contract(path: Path) -> tuple[str, frozenset[str]]:
    """Return the deepest Linux mount's filesystem and VFS option set."""

    if os.name == "nt":
        fail("production root filesystem admission requires Linux")
    resolved = Path(os.path.realpath(os.fspath(path)))
    try:
        rows = Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        fail(f"cannot read Linux mount custody for {path}: {error}")
    matches: list[tuple[int, str, frozenset[str]]] = []
    for row in rows:
        if " - " not in row:
            fail("Linux mountinfo contains a malformed row")
        left_raw, right_raw = row.split(" - ", 1)
        left = left_raw.split()
        right = right_raw.split()
        if len(left) < 6 or len(right) < 3:
            fail("Linux mountinfo contains a truncated row")
        mountpoint = Path(_decode_mountinfo_path(left[4]))
        try:
            inside = os.path.commonpath((os.fspath(resolved), os.fspath(mountpoint))) == os.fspath(
                mountpoint
            )
        except ValueError:
            inside = False
        if inside:
            matches.append((len(mountpoint.parts), right[0], frozenset(left[5].split(","))))
    if not matches:
        fail(f"production root has no identifiable Linux mount: {path}")
    _, filesystem, options = max(matches, key=lambda item: item[0])
    return filesystem, options


def _require_private_ext4_parent(path: Path, label: str) -> os.stat_result:
    """Admit one exact-owner 0700 writable ext4 production allocation parent."""

    metadata = _require_directory(path, label)
    uid = os.getuid()
    gid = os.getgid()
    if uid < 1000 or gid < 1000:
        fail("production roots require a non-system host UID and GID (both >=1000)")
    if metadata.st_uid != uid or metadata.st_gid != gid:
        fail(f"{label} is not owned by the executing host UID/GID")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        fail(f"{label} must have exact mode 0700")
    filesystem, options = _linux_mount_contract(path)
    if filesystem != "ext4" or "rw" not in options:
        fail(f"{label} must be on one writable Linux-native ext4 mount")
    return metadata


def _require_regular(path: Path, maximum: int, label: str) -> os.stat_result:
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        fail(f"{label} does not exist: {path}")
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or _is_reparse(metadata)
    ):
        fail(f"{label} must be a regular non-link file: {path}")
    if metadata.st_nlink != 1:
        fail(f"{label} must have exactly one hard link: {path}")
    if metadata.st_size > maximum:
        fail(f"{label} exceeds its {maximum}-byte bound: {path}")
    return metadata


def _stable_signature(metadata: os.stat_result) -> tuple[int, ...]:
    values = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
    )
    # NTFS can expose a delayed ctime update between lstat() and fstat() even
    # though the same open handle, size, mode, inode, and mtime are unchanged.
    # POSIX ctime remains a useful metadata-race signal for production runs.
    if os.name != "nt":
        values += (
            getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
        )
    return values


def read_regular(path: Path, maximum: int, label: str) -> bytes:
    before = _require_regular(path, maximum, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if _stable_signature(opened) != _stable_signature(before):
            fail(
                f"{label} changed while being opened "
                f"(path={_stable_signature(before)!r}, handle={_stable_signature(opened)!r})"
            )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                fail(f"{label} exceeds its {maximum}-byte bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = _require_regular(path, maximum, label)
    if (
        _stable_signature(opened) != _stable_signature(after)
        or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
    ):
        fail(f"{label} changed while being read")
    return b"".join(chunks)


def hash_regular(path: Path, maximum: int, label: str) -> tuple[str, int]:
    """Hash one stable regular file without retaining its bytes in memory."""

    before = _require_regular(path, maximum, label)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(descriptor)
        if _stable_signature(opened) != _stable_signature(before):
            fail(
                f"{label} changed while being opened "
                f"(path={_stable_signature(before)!r}, handle={_stable_signature(opened)!r})"
            )
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                fail(f"{label} exceeds its {maximum}-byte bound")
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = _require_regular(path, maximum, label)
    if (
        _stable_signature(opened) != _stable_signature(after)
        or (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino)
    ):
        fail(f"{label} changed while being hashed")
    return digest.hexdigest(), size


def load_canonical_json(path: Path, maximum: int, label: str) -> dict[str, Any]:
    raw = read_regular(path, maximum, label)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not valid JSON: {error}")
    if not isinstance(value, dict) or raw != canonical_json(value):
        fail(f"{label} must be one canonical JSON object")
    return value


def _fsync_directory(path: Path, *, strict: bool) -> None:
    if os.name == "nt":
        if strict:
            fail("production publication requires Linux/WSL directory fsync")
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_no_replace(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        fail(f"refusing to replace existing output: {path}")
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            mode,
        )
        created = True
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail(f"short write while creating {path}")
            view = view[written:]
        os.fsync(descriptor)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)


def copy_no_replace(
    source: Path,
    destination: Path,
    maximum: int,
    label: str,
    *,
    mode: int = 0o600,
) -> tuple[str, int]:
    before = _require_regular(source, maximum, label)
    if destination.exists() or destination.is_symlink():
        fail(f"refusing to replace existing {label}: {destination}")
    source_flags = (
        os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    )
    source_fd = os.open(source, source_flags)
    destination_fd: int | None = None
    created = False
    digest = hashlib.sha256()
    size = 0
    try:
        opened = os.fstat(source_fd)
        if _stable_signature(opened) != _stable_signature(before):
            fail(f"{label} changed while being opened")
        destination_fd = os.open(
            destination,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_BINARY", 0),
            mode,
        )
        created = True
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > maximum:
                fail(f"{label} exceeds its {maximum}-byte bound")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(destination_fd, view)
                if written <= 0:
                    fail(f"short write while copying {label}")
                view = view[written:]
        after = os.fstat(source_fd)
        if _stable_signature(opened) != _stable_signature(after):
            fail(f"{label} changed while being copied")
        current = _require_regular(source, maximum, label)
        if (after.st_dev, after.st_ino) != (current.st_dev, current.st_ino):
            fail(f"{label} pathname changed while being copied")
        os.fsync(destination_fd)
    except Exception:
        if destination_fd is not None:
            os.close(destination_fd)
            destination_fd = None
        if created:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    finally:
        os.close(source_fd)
        if destination_fd is not None:
            os.close(destination_fd)
    retained_digest, retained_size = hash_regular(
        destination, maximum, f"retained {label}"
    )
    if retained_size != size or retained_digest != digest.hexdigest():
        fail(f"retained {label} differs from the opened source bytes")
    return digest.hexdigest(), size


def _safe_relative(value: object, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{label} is not a canonical POSIX relative path")
    pure = PurePosixPath(value)
    if (
        pure.is_absolute()
        or pure.as_posix() != value
        or any(part in ("", ".", "..") for part in pure.parts)
    ):
        fail(f"{label} is unsafe or noncanonical: {value!r}")
    for part in pure.parts:
        if any(ord(character) < 32 or character == "\x7f" for character in part):
            fail(f"{label} contains a control character")
        if part.endswith((" ", ".")) or ":" in part:
            fail(f"{label} is not portable: {value!r}")
    return value


def _validate_dependency_path(path: str, dependency_class: str) -> None:
    pure = PurePosixPath(_safe_relative(path, "dependency path"))
    folded = tuple(part.casefold() for part in pure.parts)
    if set(folded) & FORBIDDEN_DIRECTORY_NAMES:
        fail(f"dependency path contains a compiled/cache directory: {path}")
    if dependency_class.startswith("buildroot-"):
        for index, component in enumerate(folded[:-1]):
            if component == "buildroot" and index + 1 < len(folded):
                if folded[index + 1] in FORBIDDEN_BUILDROOT_COMPONENTS:
                    fail(f"dependency path contains Buildroot output state: {path}")
    if dependency_class not in ("toolchain-archive", "amlogic-input"):
        lower = pure.name.casefold()
        if lower.endswith(FORBIDDEN_COMPILED_SUFFIXES):
            fail(f"dependency path looks like a compiled result: {path}")
        if lower.startswith(("rootfs.", "uimage", "fit.itb")):
            fail(f"dependency path looks like a generated firmware image: {path}")


def _parse_dependency_policy(raw: bytes) -> dict[str, Any]:
    if sha256_bytes(raw) != DEPENDENCY_POLICY_SHA256:
        fail("dependency policy differs from the reviewed authenticated digest")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"dependency policy is not valid JSON: {error}")
    if not isinstance(value, dict) or raw != canonical_json(value):
        fail("dependency policy must be one canonical JSON object")
    policy = _exact_object(
        value,
        (
            "amlogic_inputs",
            "authority",
            "builder",
            "buildroot",
            "cargo",
            "dashboard",
            "mandatory_selection_classes",
            "materialization",
            "schema",
            "selection_schema",
            "source_commit_binding",
            "toolchain",
        ),
        "dependency policy",
    )
    if (
        policy["schema"] != DEPENDENCY_POLICY_SCHEMA
        or policy["selection_schema"] != DEPENDENCY_SELECTION_SCHEMA
        or policy["authority"]
        != "dependency-materialization-only-no-build-release-install-or-flash-authority"
        or policy["mandatory_selection_classes"]
        != list(REQUIRED_DEPENDENCY_CLASSES)
        or policy["source_commit_binding"]
        != {
            "policy_path": DEPENDENCY_POLICY_RELATIVE,
            "verification": "admitted-immutable-snapshot-exact-tree-before-and-after",
        }
        or policy["materialization"]
        != {
            "builder_image_binding": "authenticated-policy-exact-name-at-sha256",
            "compiled_outputs_forbidden": True,
            "network_phase": "separate-source-fetch-only",
            "output": "source-only-exact-selection-for-later-host-sealing",
        }
    ):
        fail("dependency policy shape or authority boundary is invalid")
    builder = _exact_object(
        policy["builder"],
        (
            "dockerfile",
            "image",
            "linux_amd64_manifest_digest",
            "oci_config_digest",
            "oci_index_digest",
            "toolchain_id",
            "versions",
        ),
        "dependency policy builder",
    )
    dockerfile = _exact_object(
        builder["dockerfile"], ("bytes", "path", "sha256"), "builder Dockerfile"
    )
    versions = _exact_object(
        builder["versions"],
        ("node", "npm", "python_cryptography", "rust", "rust_target", "zig"),
        "builder versions",
    )
    if (
        not isinstance(builder["image"], str)
        or not IMMUTABLE_IMAGE.fullmatch(builder["image"])
        or builder["oci_index_digest"] != "sha256:" + builder["image"].rsplit("@sha256:", 1)[1]
        or not all(
            isinstance(builder[field], str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", builder[field])
            for field in (
                "linux_amd64_manifest_digest",
                "oci_config_digest",
                "oci_index_digest",
            )
        )
        or not isinstance(builder["toolchain_id"], str)
        or not TOKEN.fullmatch(builder["toolchain_id"])
        or dockerfile["path"]
        != "DCENT_OS_Antminer/scripts/docker/Dockerfile.s19k-hermetic"
        or isinstance(dockerfile["bytes"], bool)
        or not isinstance(dockerfile["bytes"], int)
        or dockerfile["bytes"] <= 0
        or dockerfile["bytes"] > MAX_JSON_BYTES
        or not isinstance(dockerfile["sha256"], str)
        or not HEX_64.fullmatch(dockerfile["sha256"])
        or versions["rust_target"] != "aarch64-unknown-linux-musl"
        or any(not isinstance(item, str) or not TOKEN.fullmatch(item) for item in versions.values())
    ):
        fail("dependency policy builder identity is invalid")
    toolchain = policy["toolchain"]
    if (
        not isinstance(toolchain, dict)
        or toolchain.get("toolchain_id_binding") != "authenticated-policy-exact-token"
    ):
        fail("dependency policy toolchain identity binding is invalid")
    buildroot = _exact_object(
        policy["buildroot"],
        (
            "commit",
            "downloads_destination",
            "source_archive_bytes",
            "source_archive_sha256",
            "source_destination",
            "url",
        ),
        "dependency policy Buildroot source",
    )
    if (
        not isinstance(buildroot["commit"], str)
        or not FULL_COMMIT.fullmatch(buildroot["commit"])
        or buildroot["url"] != "https://github.com/buildroot/buildroot.git"
        or buildroot["downloads_destination"] != "buildroot/dl"
        or buildroot["source_destination"] != "buildroot/source"
        or not isinstance(buildroot["source_archive_sha256"], str)
        or not HEX_64.fullmatch(buildroot["source_archive_sha256"])
        or isinstance(buildroot["source_archive_bytes"], bool)
        or not isinstance(buildroot["source_archive_bytes"], int)
        or buildroot["source_archive_bytes"] <= 0
        or buildroot["source_archive_bytes"] > MAX_DEPENDENCY_FILE_BYTES
    ):
        fail("dependency policy Buildroot source identity is invalid")
    return policy


def load_dependency_policy(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = read_regular(path, MAX_JSON_BYTES, "authenticated dependency policy")
    return _parse_dependency_policy(raw), raw


def _parse_dependency_selection(
    raw: bytes,
    *,
    policy: Mapping[str, Any] | None = None,
    expected_source_commit: str | None = None,
    expected_builder_image: str | None = None,
    expected_toolchain_id: str | None = None,
) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"dependency selection is not valid JSON: {error}")
    selection = _exact_object(
        value,
        ("schema", "source_commit", "builder_image", "toolchain_id", "inputs"),
        "dependency selection",
    )
    if raw != canonical_json(selection):
        fail("dependency selection must be canonical JSON")
    if selection["schema"] != DEPENDENCY_SELECTION_SCHEMA:
        fail("unsupported dependency-selection schema")
    if not isinstance(selection["source_commit"], str) or not FULL_COMMIT.fullmatch(
        selection["source_commit"]
    ):
        fail("dependency selection source_commit must be one full lowercase object id")
    if not isinstance(selection["builder_image"], str) or not IMMUTABLE_IMAGE.fullmatch(
        selection["builder_image"]
    ):
        fail("dependency selection builder_image must be digest-pinned")
    if not isinstance(selection["toolchain_id"], str) or not TOKEN.fullmatch(
        selection["toolchain_id"]
    ):
        fail("dependency selection toolchain_id is not a canonical token")
    if expected_source_commit is not None and selection["source_commit"] != expected_source_commit:
        fail("dependency selection does not bind the admitted source commit")
    if expected_builder_image is not None and selection["builder_image"] != expected_builder_image:
        fail("dependency selection does not bind the selected builder image")
    if expected_toolchain_id is not None and selection["toolchain_id"] != expected_toolchain_id:
        fail("dependency selection does not bind the selected toolchain")
    inputs = selection["inputs"]
    if not isinstance(inputs, list) or not inputs or len(inputs) > MAX_DEPENDENCY_FILES:
        fail("dependency selection inputs must be a non-empty bounded array")
    paths: list[str] = []
    portable: set[str] = set()
    total = 0
    for index, raw_item in enumerate(inputs):
        item = _exact_object(
            raw_item,
            ("path", "class", "sha256", "bytes", "mode"),
            f"dependency selection input {index}",
        )
        path = _safe_relative(item["path"], f"dependency selection input {index} path")
        if item["class"] not in DEPENDENCY_CLASSES:
            fail(f"dependency selection input {index} has an unsupported class")
        _validate_dependency_path(path, item["class"])
        if not isinstance(item["sha256"], str) or not HEX_64.fullmatch(item["sha256"]):
            fail(f"dependency selection input {index} has an invalid SHA-256")
        if (
            isinstance(item["bytes"], bool)
            or not isinstance(item["bytes"], int)
            or item["bytes"] < 0
            or item["bytes"] > MAX_DEPENDENCY_FILE_BYTES
        ):
            fail(f"dependency selection input {index} has an invalid byte count")
        if item["mode"] not in (0o644, 0o755):
            fail(f"dependency selection input {index} mode must be 0644 or 0755")
        total += item["bytes"]
        if total > MAX_DEPENDENCY_FILE_BYTES * 16:
            fail("dependency selection aggregate exceeds its size bound")
        folded = path.casefold()
        if folded in portable:
            fail(f"dependency selection contains a duplicate/portable collision: {path}")
        portable.add(folded)
        paths.append(path)
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")):
        fail("dependency selection inputs are not in canonical byte order")
    if policy is None:
        fail("dependency selection requires the reviewed authenticated policy")
    policy_builder = policy.get("builder")
    if (
        not isinstance(policy_builder, dict)
        or selection["builder_image"] != policy_builder.get("image")
        or selection["toolchain_id"] != policy_builder.get("toolchain_id")
    ):
        fail("dependency selection builder/toolchain differs from authenticated policy")
    observed_classes = sorted(
        {item["class"] for item in inputs}, key=lambda value: value.encode("utf-8")
    )
    if observed_classes != list(REQUIRED_DEPENDENCY_CLASSES):
        fail("dependency selection omits or adds a mandatory policy class")
    by_path = {item["path"]: item for item in inputs}
    toolchain = policy.get("toolchain")
    buildroot = policy.get("buildroot")
    cargo = policy.get("cargo")
    dashboard = policy.get("dashboard")
    if not all(isinstance(section, dict) for section in (toolchain, buildroot, cargo, dashboard)):
        fail("dependency policy source destinations are invalid")
    download_root = _safe_relative(
        toolchain.get("download_root"), "dependency policy toolchain download root"
    )
    toolchain_archive = toolchain.get("archive")
    if (
        not isinstance(toolchain_archive, str)
        or PurePosixPath(toolchain_archive).name != toolchain_archive
    ):
        fail("dependency policy toolchain archive name is invalid")
    toolchain_records = [item for item in inputs if item["class"] == "toolchain-archive"]
    if (
        len(toolchain_records) != 1
        or not toolchain_records[0]["path"].startswith(download_root + "/")
        or PurePosixPath(toolchain_records[0]["path"]).name != toolchain_archive
        or toolchain_records[0]["sha256"] != toolchain.get("sha256")
    ):
        fail("dependency selection toolchain archive differs from policy")
    amlogic = policy.get("amlogic_inputs")
    if not isinstance(amlogic, list) or len(amlogic) != 3:
        fail("dependency policy Amlogic inputs are incomplete")
    for raw_item in amlogic:
        if not isinstance(raw_item, dict):
            fail("dependency policy Amlogic input is invalid")
        item = by_path.get(raw_item.get("destination"))
        if (
            item is None
            or item["class"] != "amlogic-input"
            or item["sha256"] != raw_item.get("sha256")
            or item["bytes"] != raw_item.get("bytes")
        ):
            fail("dependency selection Amlogic input differs from policy")
    amlogic_destinations = {
        raw_item["destination"] for raw_item in amlogic if isinstance(raw_item, dict)
    }
    buildroot_source = _safe_relative(
        buildroot.get("source_destination"),
        "dependency policy Buildroot source destination",
    )
    buildroot_downloads = _safe_relative(
        buildroot.get("downloads_destination"),
        "dependency policy Buildroot download destination",
    )
    cargo_vendor = _safe_relative(
        cargo.get("vendor_destination"), "dependency policy Cargo vendor destination"
    )
    dashboard_cache = _safe_relative(
        dashboard.get("npm_cache_destination"),
        "dependency policy dashboard cache destination",
    )
    expected_buildroot_archive = f"{buildroot_source}/buildroot-source.tar"
    source_records = [item for item in inputs if item["class"] == "buildroot-source"]
    if (
        len(source_records) != 1
        or source_records[0]["path"] != expected_buildroot_archive
        or source_records[0]["sha256"] != buildroot.get("source_archive_sha256")
        or source_records[0]["bytes"] != buildroot.get("source_archive_bytes")
    ):
        fail("dependency selection must contain the one exact Buildroot Git archive")

    for item in inputs:
        path = item["path"]
        if path == toolchain_records[0]["path"]:
            expected_class = "toolchain-archive"
        elif path == expected_buildroot_archive:
            expected_class = "buildroot-source"
        elif path.startswith(buildroot_downloads + "/"):
            expected_class = "buildroot-download"
        elif path.startswith(cargo_vendor + "/"):
            expected_class = "cargo-source"
        elif path.startswith(dashboard_cache + "/"):
            expected_class = "dashboard-dependency"
        elif path in amlogic_destinations:
            expected_class = "amlogic-input"
        else:
            fail(f"dependency selection path is outside every policy destination: {path}")
        if item["class"] != expected_class:
            fail(f"dependency selection class is mislabeled for policy path: {path}")
    return selection


def _walk_regular_tree(root: Path, label: str) -> tuple[list[str], list[str]]:
    _require_directory(root, label)
    files: list[str] = []
    directories: list[str] = []
    for current_raw, names, leaves in os.walk(root, topdown=True, followlinks=False):
        current = Path(current_raw)
        names.sort(key=lambda value: value.encode("utf-8"))
        leaves.sort(key=lambda value: value.encode("utf-8"))
        for name in names:
            path = current / name
            metadata = os.lstat(path)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_ISLNK(metadata.st_mode)
                or _is_reparse(metadata)
            ):
                fail(f"{label} contains a symlink/reparse/non-directory: {path}")
            directories.append(path.relative_to(root).as_posix())
        for name in leaves:
            path = current / name
            _require_regular(path, MAX_DEPENDENCY_FILE_BYTES, f"{label} file")
            files.append(path.relative_to(root).as_posix())
    files.sort(key=lambda value: value.encode("utf-8"))
    directories.sort(key=lambda value: value.encode("utf-8"))
    return files, directories


def _expected_parent_directories(paths: Iterable[str]) -> list[str]:
    directories: set[str] = set()
    for value in paths:
        parts = PurePosixPath(value).parts[:-1]
        for length in range(1, len(parts) + 1):
            directories.add(PurePosixPath(*parts[:length]).as_posix())
    return sorted(directories, key=lambda value: value.encode("utf-8"))


def _rename_directory_no_replace(
    source: Path, destination: Path, *, strict: bool
) -> None:
    """Atomically publish a directory without replacement on Linux.

    ``os.rename`` may replace an empty destination directory.  Production
    evidence uses Linux/WSL, so require libc ``renameat2(RENAME_NOREPLACE)``
    instead of pretending the earlier existence check closes the race.
    """

    if os.name == "nt":
        if strict:
            fail("atomic no-replace directory publication requires Linux/WSL")
        if destination.exists() or destination.is_symlink():
            fail(f"refusing to replace existing evidence output: {destination}")
        os.rename(source, destination)
        return
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        if strict:
            fail("host libc lacks renameat2; cannot publish evidence no-replace")
        if destination.exists() or destination.is_symlink():
            fail(f"refusing to replace existing evidence output: {destination}")
        os.rename(source, destination)
        return
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    at_fdcwd = -100
    rename_noreplace = 1
    status = renameat2(
        at_fdcwd,
        os.fsencode(source),
        at_fdcwd,
        os.fsencode(destination),
        rename_noreplace,
    )
    if status != 0:
        error = ctypes.get_errno()
        if error in (errno.EEXIST, errno.ENOTEMPTY):
            fail(f"refusing to replace concurrently-created evidence output: {destination}")
        raise OSError(error, os.strerror(error), os.fspath(destination))


@dataclass(frozen=True)
class SourceAdmission:
    receipt: dict[str, Any]
    snapshot: Path
    tree: Path
    destroy_token: str


def _git(
    repo_root: Path,
    arguments: Sequence[str],
    *,
    gnupg_home: Path | None = None,
    gpg_binary: Path | None = None,
) -> tuple[bytes, bytes]:
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("GIT_CONFIG_") or name in ("GNUPGHOME", "GPG_TTY"):
            environment.pop(name, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "LC_ALL": "C",
        }
    )
    if gnupg_home is not None:
        environment["GNUPGHOME"] = os.fspath(gnupg_home)
    git_configuration: tuple[str, ...] = ()
    if gpg_binary is not None:
        git_configuration = (
            "-c",
            "gpg.format=openpgp",
            "-c",
            f"gpg.program={os.fspath(gpg_binary)}",
        )
    completed = subprocess.run(
        ("git", "-C", os.fspath(repo_root), *git_configuration, *arguments),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=120,
    )
    if completed.returncode:
        detail = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        fail(
            f"Git admission failed ({' '.join(arguments)}): "
            + (detail[0] if detail else f"exit {completed.returncode}")
        )
    return completed.stdout, completed.stderr


def _openpgp_signer_from_verification(stdout: bytes, stderr: bytes) -> str:
    matches = re.findall(
        rb"(?:^|\n)\[GNUPG:\] VALIDSIG ([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})(?: |$)",
        stdout + b"\n" + stderr,
    )
    identities = {"openpgp:" + match.decode("ascii").lower() for match in matches}
    if len(identities) != 1:
        fail("git verify-commit did not identify exactly one OpenPGP signing fingerprint")
    return next(iter(identities))


def _require_reviewed_commit_signer(identity: str, allowed_signers: Sequence[str]) -> None:
    allowed = set(allowed_signers)
    if not OPENPGP_SIGNER.fullmatch(identity) or identity not in allowed:
        fail("commit signature is valid but its signer is outside the reviewed policy")


def _signing_policy_identity(
    trusted_gnupg_home: Path,
    gpg_binary: Path,
    allowed_signers: Sequence[str],
) -> tuple[str, bytes]:
    trust_root = Path(os.path.abspath(os.fspath(trusted_gnupg_home)))
    binary = Path(os.path.abspath(os.fspath(gpg_binary)))
    _require_directory(trust_root, "reviewed OpenPGP trust root")
    binary_sha256, binary_bytes = hash_regular(
        binary, MAX_RECEIPT_BYTES, "reviewed OpenPGP verifier binary"
    )
    canonical_signers = sorted(set(allowed_signers), key=lambda value: value.encode("ascii"))
    if not canonical_signers or any(
        not isinstance(value, str) or not OPENPGP_SIGNER.fullmatch(value)
        for value in canonical_signers
    ):
        fail("commit signer policy requires canonical reviewed OpenPGP fingerprints")
    files, directories = _walk_regular_tree(trust_root, "reviewed OpenPGP trust root")
    if not files:
        fail("reviewed OpenPGP trust root contains no regular trust material")
    ledger = []
    for relative in files:
        digest, size = hash_regular(
            trust_root.joinpath(*PurePosixPath(relative).parts),
            MAX_RECEIPT_BYTES,
            f"OpenPGP trust material {relative}",
        )
        ledger.append({"path": relative, "sha256": digest, "bytes": size})
    policy = {
        "schema": "dcentos.s19k-git-signing-policy/v1",
        "allowed_signers": canonical_signers,
        "gpg_binary": os.fspath(binary),
        "gpg_binary_sha256": binary_sha256,
        "gpg_binary_bytes": binary_bytes,
        "trust_root": os.fspath(trust_root),
        "trust_files": ledger,
        "trust_directories": directories,
        "git_system_config": "disabled",
        "git_global_config": "disabled",
        "signature_format": "openpgp",
    }
    raw = canonical_json(policy)
    return sha256_bytes(raw), raw


def _load_source_snapshot_module(path: Path | None = None) -> Any:
    path = Path(__file__).with_name("source_snapshot.py") if path is None else path
    path = Path(os.path.abspath(os.fspath(path)))
    spec = importlib.util.spec_from_file_location("dcentos_source_snapshot", path)
    if spec is None or spec.loader is None:
        fail("cannot load source_snapshot.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_opened_python_module(raw: bytes, path: Path, purpose: str) -> Any:
    """Compile/execute already admitted bytes without reopening their path."""

    name = f"dcentos_{purpose}_{sha256_bytes(raw)}"
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader(name, loader=None, origin=os.fspath(path))
    )
    module.__file__ = os.fspath(path)
    sys.modules[name] = module
    try:
        code = compile(raw, os.fspath(path), "exec", dont_inherit=True)
        exec(code, module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _verify_admitted_source_snapshot(
    source: SourceAdmission, receipt: Mapping[str, Any]
) -> dict[str, Any]:
    """Reverify a sealed admitted snapshot without reopening any Git repository."""

    helper_relative = "DCENT_OS_Antminer/scripts/source_snapshot.py"
    helper_records = [
        item for item in receipt["source_files"] if item.get("path") == helper_relative
    ]
    if len(helper_records) != 1:
        fail("source admission does not bind exactly one snapshot verifier helper")
    helper = source.tree.joinpath(*PurePosixPath(helper_relative).parts)
    helper_raw = read_regular(
        helper, MAX_JSON_BYTES, "admitted source snapshot verifier"
    )
    helper_sha256 = sha256_bytes(helper_raw)
    helper_bytes = len(helper_raw)
    helper_record = helper_records[0]
    if (
        helper_sha256 != helper_record["sha256"]
        or helper_bytes != helper_record["bytes"]
        or helper_record["git_mode"] != "100644"
    ):
        fail("source snapshot verifier differs from signed source admission")
    descriptor_sha256, _ = hash_regular(
        source.snapshot, MAX_RECEIPT_BYTES, "admitted source snapshot descriptor"
    )
    if descriptor_sha256 != receipt["snapshot_descriptor_sha256"]:
        fail("source snapshot descriptor differs from signed source admission")
    snapshot_module = _load_opened_python_module(
        helper_raw, helper, "admitted_source_snapshot"
    )
    descriptor = snapshot_module.verify_snapshot(
        source.snapshot, receipt["source_commit"]
    )
    if (
        descriptor.get("snapshot_id") != receipt["snapshot_id"]
        or descriptor.get("commit", {}).get("tree_oid") != receipt["source_tree"]
        or sha256_bytes(canonical_json(descriptor))
        != receipt["snapshot_descriptor_sha256"]
    ):
        fail("source snapshot identity differs from signed source admission")
    retained_helper_sha256, retained_helper_bytes = hash_regular(
        helper, MAX_JSON_BYTES, "retained admitted source snapshot verifier"
    )
    if (
        retained_helper_sha256 != helper_sha256
        or retained_helper_bytes != helper_bytes
    ):
        fail("source snapshot verifier changed during verification")
    return descriptor


def authenticate_source(
    repo_root: Path,
    expected_commit: str,
    snapshot_parent: Path,
    *,
    trusted_gnupg_home: Path | None = None,
    gpg_binary: Path | None = None,
    allowed_commit_signers: Sequence[str] = (),
    after_snapshot: Callable[[], None] | None = None,
    strict_durability: bool = True,
) -> SourceAdmission:
    """Admit and materialize one exact clean, signed Git-object source tree."""

    commit = expected_commit.strip()
    if not FULL_COMMIT.fullmatch(commit):
        fail("expected source commit must be one full lowercase object id")
    root = Path(os.path.abspath(os.fspath(repo_root)))
    parent = Path(os.path.abspath(os.fspath(snapshot_parent)))
    _require_directory(root, "repository root")
    _require_directory(parent, "source-snapshot parent")
    top = Path(_git(root, ("rev-parse", "--show-toplevel"))[0].decode().strip())
    try:
        if not os.path.samefile(root, top):
            fail("repository root must be the exact Git top-level directory")
    except OSError:
        fail("repository root could not be matched to the Git top level")
    observed = _git(root, ("rev-parse", "HEAD"))[0].decode("ascii").strip().lower()
    if observed != commit:
        fail(f"Git HEAD {observed} differs from selected commit {commit}")
    if _git(root, ("status", "--porcelain=v1", "--untracked-files=all"))[0]:
        fail("production source admission requires a completely clean worktree")
    verification_home = (
        Path(os.path.abspath(os.fspath(trusted_gnupg_home)))
        if trusted_gnupg_home is not None
        else Path(os.devnull)
    )
    verification_binary = (
        Path(os.path.abspath(os.fspath(gpg_binary)))
        if gpg_binary is not None
        else Path("/usr/bin/gpg")
    )
    signature_stdout, signature_stderr = _git(
        root,
        ("verify-commit", "--raw", commit),
        gnupg_home=verification_home,
        gpg_binary=verification_binary,
    )
    if trusted_gnupg_home is None or gpg_binary is None:
        fail("signed source admission requires an explicit reviewed OpenPGP trust root and binary")
    signing_policy_id, signing_policy_raw = _signing_policy_identity(
        verification_home, verification_binary, allowed_commit_signers
    )
    commit_signer_identity = _openpgp_signer_from_verification(
        signature_stdout, signature_stderr
    )
    _require_reviewed_commit_signer(commit_signer_identity, allowed_commit_signers)
    tree = _git(root, ("rev-parse", f"{commit}^{{tree}}"))[0].decode("ascii").strip()
    if not FULL_COMMIT.fullmatch(tree):
        fail("Git returned a noncanonical tree object id")
    epoch_raw = _git(root, ("show", "-s", "--format=%ct", commit))[0].decode("ascii").strip()
    if not epoch_raw.isdecimal():
        fail("Git returned a nonnumeric source commit epoch")
    epoch = int(epoch_raw)
    if epoch < 0 or epoch > MAX_SOURCE_EPOCH:
        fail("source commit epoch is outside the uImage 32-bit timestamp range")

    if strict_durability and os.name != "nt":
        _require_private_ext4_parent(parent, "source-snapshot parent")

    source_snapshot = _load_source_snapshot_module()
    created = source_snapshot.create_snapshot(root, commit, parent)
    try:
        verified = source_snapshot.verify_against_git(root, commit, created.snapshot)
        if after_snapshot is not None:
            after_snapshot()
        if _git(root, ("rev-parse", "HEAD"))[0].decode("ascii").strip().lower() != commit:
            fail("Git HEAD changed during source admission")
        if _git(root, ("status", "--porcelain=v1", "--untracked-files=all"))[0]:
            fail("worktree changed during source admission")
        second_stdout, second_stderr = _git(
            root,
            ("verify-commit", "--raw", commit),
            gnupg_home=verification_home,
            gpg_binary=verification_binary,
        )
        if _openpgp_signer_from_verification(second_stdout, second_stderr) != commit_signer_identity:
            fail("commit signer identity changed during source admission")
        second_policy_id, second_policy_raw = _signing_policy_identity(
            verification_home, verification_binary, allowed_commit_signers
        )
        if second_policy_id != signing_policy_id or second_policy_raw != signing_policy_raw:
            fail("reviewed commit-signing policy changed during source admission")
        descriptor = source_snapshot.verify_snapshot(created.snapshot, commit)
        if descriptor["commit"]["tree_oid"] != tree:
            fail("source snapshot tree differs from authenticated Git tree")
        receipt_body: dict[str, Any] = {
            "schema": SOURCE_SCHEMA,
            "source_commit": commit,
            "source_tree": tree,
            "source_date_epoch": epoch,
            "commit_signature_verified": True,
            "commit_signer_identity": commit_signer_identity,
            "signing_policy_id": signing_policy_id,
            "clean_worktree_verified_before_and_after": True,
            "signature_verification_output_sha256": sha256_bytes(
                signature_stdout + b"\0" + signature_stderr
            ),
            "snapshot_id": verified["snapshot_id"],
            "snapshot_descriptor_sha256": verified["descriptor_sha256"],
            "source_files": [
                {
                    "path": item["path"],
                    "sha256": item["sha256"],
                    "bytes": item["size"],
                    "git_mode": item["git_mode"],
                }
                for item in descriptor["files"]
            ],
        }
        receipt_body["admission_id"] = sha256_bytes(canonical_json(receipt_body))
        return SourceAdmission(
            receipt=receipt_body,
            snapshot=created.snapshot,
            tree=created.stage / "tree",
            destroy_token=created.destroy_token,
        )
    except Exception:
        try:
            source_snapshot.destroy_snapshot(created.snapshot, created.destroy_token)
        except Exception:
            pass
        raise


@dataclass(frozen=True)
class DependencyBundle:
    stage: Path
    descriptor: Path
    inputs: Path
    destroy_token: str
    bundle_id: str


@dataclass(frozen=True)
class ReleaseInputs:
    stage: Path
    descriptor: Path
    public_key: Path
    native_owner_receipt: Path
    stock_recovery_receipt: Path
    destroy_token: str
    input_id: str


def _cleanup_created(created_files: list[Path], created_directories: list[Path]) -> None:
    for path in reversed(created_files):
        try:
            if path.exists() and not path.is_symlink():
                os.chmod(path, 0o600)
                path.unlink()
        except OSError:
            pass
    for path in sorted(created_directories, key=lambda value: len(value.parts), reverse=True):
        try:
            if path.exists() and not path.is_symlink():
                os.chmod(path, 0o700)
                path.rmdir()
        except OSError:
            pass


def seal_dependency_bundle(
    materialized_root: Path,
    selection_path: Path,
    policy_path: Path,
    stage_parent: Path,
    *,
    expected_source_commit: str | None = None,
    expected_builder_image: str | None = None,
    expected_toolchain_id: str | None = None,
    strict_durability: bool = True,
) -> DependencyBundle:
    """Copy and seal one exact source-only materializer result."""

    root = Path(os.path.abspath(os.fspath(materialized_root)))
    parent = Path(os.path.abspath(os.fspath(stage_parent)))
    _require_directory(root, "materialized dependency root")
    if strict_durability and os.name != "nt":
        _require_private_ext4_parent(parent, "dependency-bundle parent")
    else:
        _require_directory(parent, "dependency-bundle parent")
    policy, policy_raw = load_dependency_policy(policy_path)
    selection_raw = read_regular(selection_path, MAX_JSON_BYTES, "dependency selection")
    selection = _parse_dependency_selection(
        selection_raw,
        policy=policy,
        expected_source_commit=expected_source_commit,
        expected_builder_image=expected_builder_image,
        expected_toolchain_id=expected_toolchain_id,
    )
    observed_files, observed_directories = _walk_regular_tree(
        root, "materialized dependency root"
    )
    selected_paths = [item["path"] for item in selection["inputs"]]
    expected_directories = _expected_parent_directories(selected_paths)
    if observed_files != selected_paths or observed_directories != expected_directories:
        fail(
            "materialized dependency exact set of files/directories differs from selection "
            f"(missing_files={sorted(set(selected_paths) - set(observed_files))}, "
            f"extra_files={sorted(set(observed_files) - set(selected_paths))}, "
            f"missing_directories={sorted(set(expected_directories) - set(observed_directories))}, "
            f"extra_directories={sorted(set(observed_directories) - set(expected_directories))})"
        )

    stage = Path(tempfile.mkdtemp(prefix="dcentos-s19k-deps-", dir=parent))
    inputs_root = stage / "inputs"
    created_directories = [stage]
    created_files: list[Path] = []
    try:
        inputs_root.mkdir(mode=0o700)
        created_directories.append(inputs_root)
        retained_inputs: list[dict[str, Any]] = []
        for item in selection["inputs"]:
            relative = PurePosixPath(item["path"])
            destination_parent = inputs_root
            for component in relative.parts[:-1]:
                destination_parent = destination_parent / component
                if not destination_parent.exists():
                    destination_parent.mkdir(mode=0o700)
                    created_directories.append(destination_parent)
                else:
                    _require_directory(destination_parent, "dependency destination directory")
            source = root.joinpath(*relative.parts)
            destination = inputs_root.joinpath(*relative.parts)
            digest, size = copy_no_replace(
                source,
                destination,
                MAX_DEPENDENCY_FILE_BYTES,
                f"dependency {item['path']}",
                mode=item["mode"],
            )
            created_files.append(destination)
            observed_mode = stat.S_IMODE(os.lstat(source).st_mode) & 0o777
            normalized_mode = 0o755 if observed_mode & 0o111 else 0o644
            if digest != item["sha256"] or size != item["bytes"]:
                fail(f"dependency bytes disagree with selection: {item['path']}")
            if normalized_mode != item["mode"]:
                fail(f"dependency mode disagrees with selection: {item['path']}")
            retained_inputs.append(dict(item))

        final_files, final_directories = _walk_regular_tree(
            root, "materialized dependency root after sealing copy"
        )
        if final_files != selected_paths or final_directories != expected_directories:
            fail("materialized dependency exact set changed during sealing")
        for item in selection["inputs"]:
            source = root.joinpath(*PurePosixPath(item["path"]).parts)
            digest, size = hash_regular(
                source,
                MAX_DEPENDENCY_FILE_BYTES,
                f"post-copy dependency {item['path']}",
            )
            observed_mode = stat.S_IMODE(os.lstat(source).st_mode) & 0o777
            normalized_mode = 0o755 if observed_mode & 0o111 else 0o644
            if (
                digest != item["sha256"]
                or size != item["bytes"]
                or normalized_mode != item["mode"]
            ):
                fail(f"dependency changed during sealing: {item['path']}")

        selection_destination = stage / "selection.json"
        write_no_replace(selection_destination, selection_raw)
        created_files.append(selection_destination)
        policy_destination = stage / "policy.json"
        write_no_replace(policy_destination, policy_raw)
        created_files.append(policy_destination)
        descriptor_body: dict[str, Any] = {
            "schema": DEPENDENCY_BUNDLE_SCHEMA,
            "source_commit": selection["source_commit"],
            "builder_image": selection["builder_image"],
            "toolchain_id": selection["toolchain_id"],
            "selection_sha256": sha256_bytes(selection_raw),
            "dependency_policy_sha256": DEPENDENCY_POLICY_SHA256,
            "inputs": retained_inputs,
            "compiled_outputs_retained": False,
            "build_cache_reused": False,
        }
        bundle_id = sha256_bytes(canonical_json(descriptor_body))
        descriptor = dict(descriptor_body)
        descriptor["bundle_id"] = bundle_id
        descriptor_path = stage / "bundle.json"
        write_no_replace(descriptor_path, canonical_json(descriptor))
        created_files.append(descriptor_path)
        destroy_token = secrets.token_hex(32)
        owner = {
            "schema": DEPENDENCY_OWNER_SCHEMA,
            "bundle_id": bundle_id,
            "destroy_token_sha256": sha256_bytes(destroy_token.encode("ascii")),
        }
        owner_path = stage / ".dcentos-s19k-dependency-owner"
        write_no_replace(owner_path, canonical_json(owner))
        created_files.append(owner_path)
        for directory in sorted(
            created_directories[1:], key=lambda value: len(value.parts), reverse=True
        ):
            _fsync_directory(directory, strict=strict_durability)
        _fsync_directory(stage, strict=strict_durability)
        _fsync_directory(parent, strict=strict_durability)
        verify_dependency_bundle(
            descriptor_path,
            expected_source_commit=expected_source_commit,
            expected_builder_image=expected_builder_image,
            expected_toolchain_id=expected_toolchain_id,
        )
        if os.name != "nt":
            for path in created_files:
                os.chmod(path, 0o400 if path.name != ".dcentos-s19k-dependency-owner" else 0o600)
            for directory in sorted(created_directories[1:], key=lambda value: len(value.parts), reverse=True):
                os.chmod(directory, 0o500)
            os.chmod(stage, 0o500)
        return DependencyBundle(stage, descriptor_path, inputs_root, destroy_token, bundle_id)
    except Exception:
        _cleanup_created(created_files, created_directories)
        raise


def verify_dependency_bundle(
    descriptor_path: Path,
    *,
    expected_source_commit: str | None = None,
    expected_builder_image: str | None = None,
    expected_toolchain_id: str | None = None,
) -> dict[str, Any]:
    descriptor_path = Path(os.path.abspath(os.fspath(descriptor_path)))
    stage = descriptor_path.parent
    _require_directory(stage, "dependency-bundle stage")
    descriptor = load_canonical_json(
        descriptor_path, MAX_JSON_BYTES, "dependency-bundle descriptor"
    )
    descriptor = _exact_object(
        descriptor,
        (
            "schema",
            "source_commit",
            "builder_image",
            "toolchain_id",
            "selection_sha256",
            "dependency_policy_sha256",
            "inputs",
            "compiled_outputs_retained",
            "build_cache_reused",
            "bundle_id",
        ),
        "dependency-bundle descriptor",
    )
    body = dict(descriptor)
    body.pop("bundle_id")
    if (
        descriptor["schema"] != DEPENDENCY_BUNDLE_SCHEMA
        or not isinstance(descriptor["bundle_id"], str)
        or not HEX_64.fullmatch(descriptor["bundle_id"])
        or descriptor["bundle_id"] != sha256_bytes(canonical_json(body))
        or descriptor["compiled_outputs_retained"] is not False
        or descriptor["build_cache_reused"] is not False
        or descriptor["dependency_policy_sha256"] != DEPENDENCY_POLICY_SHA256
    ):
        fail("dependency-bundle descriptor is invalid or overclaims its state")
    selection_raw = read_regular(stage / "selection.json", MAX_JSON_BYTES, "retained dependency selection")
    if sha256_bytes(selection_raw) != descriptor["selection_sha256"]:
        fail("retained dependency selection differs from its descriptor")
    policy, policy_raw = load_dependency_policy(stage / "policy.json")
    if sha256_bytes(policy_raw) != descriptor["dependency_policy_sha256"]:
        fail("retained dependency policy differs from its descriptor")
    selection = _parse_dependency_selection(
        selection_raw,
        policy=policy,
        expected_source_commit=expected_source_commit,
        expected_builder_image=expected_builder_image,
        expected_toolchain_id=expected_toolchain_id,
    )
    if (
        descriptor["source_commit"] != selection["source_commit"]
        or descriptor["builder_image"] != selection["builder_image"]
        or descriptor["toolchain_id"] != selection["toolchain_id"]
        or descriptor["inputs"] != selection["inputs"]
    ):
        fail("dependency-bundle descriptor disagrees with its selection")
    owner = load_canonical_json(
        stage / ".dcentos-s19k-dependency-owner", 4096, "dependency owner"
    )
    owner = _exact_object(
        owner, ("schema", "bundle_id", "destroy_token_sha256"), "dependency owner"
    )
    if (
        owner["schema"] != DEPENDENCY_OWNER_SCHEMA
        or owner["bundle_id"] != descriptor["bundle_id"]
        or not isinstance(owner["destroy_token_sha256"], str)
        or not HEX_64.fullmatch(owner["destroy_token_sha256"])
    ):
        fail("dependency owner sentinel is invalid")
    inputs_root = stage / "inputs"
    observed_files, observed_directories = _walk_regular_tree(
        inputs_root, "sealed dependency inputs"
    )
    expected_files = [item["path"] for item in selection["inputs"]]
    if (
        observed_files != expected_files
        or observed_directories != _expected_parent_directories(expected_files)
    ):
        fail("sealed dependency bundle has missing or extra input files/directories")
    for item in selection["inputs"]:
        path = inputs_root.joinpath(*PurePosixPath(item["path"]).parts)
        digest, size = hash_regular(
            path, MAX_DEPENDENCY_FILE_BYTES, f"sealed dependency {item['path']}"
        )
        if size != item["bytes"] or digest != item["sha256"]:
            fail(f"sealed dependency changed: {item['path']}")
        observed_mode = stat.S_IMODE(os.lstat(path).st_mode) & 0o777
        normalized_mode = 0o755 if observed_mode & 0o111 else 0o644
        if normalized_mode != item["mode"]:
            fail(f"sealed dependency mode changed: {item['path']}")
    return descriptor


def destroy_dependency_bundle(descriptor_path: Path, destroy_token: str) -> None:
    if not HEX_64.fullmatch(destroy_token):
        fail("dependency destruction token is invalid")
    descriptor = verify_dependency_bundle(descriptor_path)
    stage = Path(os.path.abspath(os.fspath(descriptor_path))).parent
    owner = load_canonical_json(
        stage / ".dcentos-s19k-dependency-owner", 4096, "dependency owner"
    )
    if not secrets.compare_digest(
        owner["destroy_token_sha256"], sha256_bytes(destroy_token.encode("ascii"))
    ):
        fail("dependency destruction token does not own this stage")
    expected_files = {
        "bundle.json",
        "selection.json",
        "policy.json",
        ".dcentos-s19k-dependency-owner",
        *(f"inputs/{item['path']}" for item in descriptor["inputs"]),
    }
    observed_files, observed_directories = _walk_regular_tree(stage, "dependency cleanup stage")
    if set(observed_files) != expected_files:
        fail("dependency cleanup stage contains unowned files")
    for relative in sorted(expected_files, key=lambda value: value.count("/"), reverse=True):
        path = stage.joinpath(*PurePosixPath(relative).parts)
        os.chmod(path, 0o600)
        path.unlink()
    for relative in sorted(
        observed_directories, key=lambda value: (value.count("/"), value), reverse=True
    ):
        path = stage.joinpath(*PurePosixPath(relative).parts)
        os.chmod(path, 0o700)
        path.rmdir()
    os.chmod(stage, 0o700)
    stage.rmdir()


def _ed25519_public_key_hex(public_raw: bytes) -> str:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        public = serialization.load_pem_public_key(public_raw)
    except (ImportError, TypeError, ValueError) as error:
        fail(f"release Ed25519 key material is invalid: {error}")
    if not isinstance(public, Ed25519PublicKey):
        fail("release public key must use Ed25519")
    selected = public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return selected.hex()


def seal_release_inputs(
    public_key: Path,
    native_owner_receipt: Path,
    stock_recovery_receipt: Path,
    stage_parent: Path,
    *,
    expected_release_key_sha256: str,
    strict_durability: bool = True,
) -> ReleaseInputs:
    """Create a stable public-only input stage for both A/B builds."""

    if not HEX_64.fullmatch(expected_release_key_sha256):
        fail("expected release-key SHA-256 must be lowercase hex")
    parent = Path(os.path.abspath(os.fspath(stage_parent)))
    if strict_durability and os.name != "nt":
        _require_private_ext4_parent(parent, "release-input parent")
    else:
        _require_directory(parent, "release-input parent")
    public_raw = read_regular(public_key, MAX_KEY_BYTES, "release public key")
    if sha256_bytes(public_raw) != expected_release_key_sha256:
        fail("release public key differs from its reviewed SHA-256")
    release_public_key_hex = _ed25519_public_key_hex(public_raw)
    native_raw = read_regular(native_owner_receipt, MAX_JSON_BYTES, "native-owner receipt")
    recovery_raw = read_regular(
        stock_recovery_receipt, MAX_JSON_BYTES, "stock-recovery receipt"
    )
    for raw, label in (
        (native_raw, "native-owner receipt"),
        (recovery_raw, "stock-recovery receipt"),
    ):
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"{label} is not valid JSON: {error}")
        if not isinstance(value, dict) or raw != canonical_json(value):
            fail(f"{label} must be canonical JSON")

    stage = Path(tempfile.mkdtemp(prefix="dcentos-s19k-release-inputs-", dir=parent))
    created_files: list[Path] = []
    try:
        retained_public = stage / "trusted-release-key.pem"
        retained_native = stage / "native-owner-verification.json"
        retained_recovery = stage / "stock-recovery-verification.json"
        for path, raw, mode in (
            (retained_public, public_raw, 0o400),
            (retained_native, native_raw, 0o400),
            (retained_recovery, recovery_raw, 0o400),
        ):
            write_no_replace(path, raw, mode=mode)
            created_files.append(path)
        descriptor_body: dict[str, Any] = {
            "schema": RELEASE_INPUT_SCHEMA,
            "release_key_sha256": sha256_bytes(public_raw),
            "release_key_bytes": len(public_raw),
            "release_public_key_hex": release_public_key_hex,
            "native_owner_receipt_sha256": sha256_bytes(native_raw),
            "native_owner_receipt_bytes": len(native_raw),
            "stock_recovery_receipt_sha256": sha256_bytes(recovery_raw),
            "stock_recovery_receipt_bytes": len(recovery_raw),
            "private_key_excluded": True,
        }
        input_id = sha256_bytes(canonical_json(descriptor_body))
        descriptor = dict(descriptor_body)
        descriptor["input_id"] = input_id
        descriptor_path = stage / "release-inputs.json"
        write_no_replace(descriptor_path, canonical_json(descriptor))
        created_files.append(descriptor_path)
        destroy_token = secrets.token_hex(32)
        owner = {
            "schema": RELEASE_INPUT_OWNER_SCHEMA,
            "input_id": input_id,
            "destroy_token_sha256": sha256_bytes(destroy_token.encode("ascii")),
        }
        owner_path = stage / ".dcentos-s19k-release-input-owner"
        write_no_replace(owner_path, canonical_json(owner))
        created_files.append(owner_path)
        _fsync_directory(stage, strict=strict_durability)
        _fsync_directory(parent, strict=strict_durability)
        verify_release_inputs(
            descriptor_path,
            expected_release_key_sha256=expected_release_key_sha256,
        )
        if os.name != "nt":
            for path in created_files:
                os.chmod(
                    path,
                    0o600
                    if path.name == ".dcentos-s19k-release-input-owner"
                    else 0o400,
                )
            os.chmod(stage, 0o500)
        return ReleaseInputs(
            stage,
            descriptor_path,
            retained_public,
            retained_native,
            retained_recovery,
            destroy_token,
            input_id,
        )
    except Exception:
        _cleanup_created(created_files, [stage])
        raise


def verify_release_inputs(
    descriptor_path: Path, *, expected_release_key_sha256: str
) -> dict[str, Any]:
    if not HEX_64.fullmatch(expected_release_key_sha256):
        fail("expected release-key SHA-256 must be lowercase hex")
    descriptor_path = Path(os.path.abspath(os.fspath(descriptor_path)))
    stage = descriptor_path.parent
    _require_directory(stage, "release-input stage")
    observed, directories = _walk_regular_tree(stage, "release-input stage")
    expected_files = sorted(
        (
            ".dcentos-s19k-release-input-owner",
            "native-owner-verification.json",
            "release-inputs.json",
            "stock-recovery-verification.json",
            "trusted-release-key.pem",
        )
    )
    if observed != expected_files or directories:
        fail("release-input stage has missing, extra, or nested content")
    descriptor = load_canonical_json(descriptor_path, MAX_JSON_BYTES, "release-input descriptor")
    descriptor = _exact_object(
        descriptor,
        (
            "schema",
            "release_key_sha256",
            "release_key_bytes",
            "release_public_key_hex",
            "native_owner_receipt_sha256",
            "native_owner_receipt_bytes",
            "stock_recovery_receipt_sha256",
            "stock_recovery_receipt_bytes",
            "private_key_excluded",
            "input_id",
        ),
        "release-input descriptor",
    )
    body = dict(descriptor)
    body.pop("input_id")
    if (
        descriptor["schema"] != RELEASE_INPUT_SCHEMA
        or descriptor["input_id"] != sha256_bytes(canonical_json(body))
        or not HEX_64.fullmatch(descriptor["input_id"])
        or descriptor["release_key_sha256"] != expected_release_key_sha256
        or not isinstance(descriptor["release_public_key_hex"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", descriptor["release_public_key_hex"])
        or descriptor["private_key_excluded"] is not True
    ):
        fail("release-input descriptor is invalid or stale")
    checks = (
        (
            "trusted-release-key.pem",
            MAX_KEY_BYTES,
            descriptor["release_key_sha256"],
            descriptor["release_key_bytes"],
        ),
        (
            "native-owner-verification.json",
            MAX_JSON_BYTES,
            descriptor["native_owner_receipt_sha256"],
            descriptor["native_owner_receipt_bytes"],
        ),
        (
            "stock-recovery-verification.json",
            MAX_JSON_BYTES,
            descriptor["stock_recovery_receipt_sha256"],
            descriptor["stock_recovery_receipt_bytes"],
        ),
    )
    for name, maximum, expected_digest, expected_bytes in checks:
        digest_value, size = hash_regular(stage / name, maximum, f"release input {name}")
        if digest_value != expected_digest or size != expected_bytes:
            fail(f"release input changed: {name}")
    observed_public_key_hex = _ed25519_public_key_hex(
        read_regular(stage / "trusted-release-key.pem", MAX_KEY_BYTES, "retained public key")
    )
    if observed_public_key_hex != descriptor["release_public_key_hex"]:
        fail("release-input descriptor carries the wrong raw Ed25519 public key")
    owner = load_canonical_json(
        stage / ".dcentos-s19k-release-input-owner", 4096, "release-input owner"
    )
    owner = _exact_object(
        owner, ("schema", "input_id", "destroy_token_sha256"), "release-input owner"
    )
    if (
        owner["schema"] != RELEASE_INPUT_OWNER_SCHEMA
        or owner["input_id"] != descriptor["input_id"]
        or not HEX_64.fullmatch(owner["destroy_token_sha256"])
    ):
        fail("release-input owner sentinel is invalid")
    return descriptor


def destroy_release_inputs(
    descriptor_path: Path, destroy_token: str, *, expected_release_key_sha256: str
) -> None:
    if not HEX_64.fullmatch(destroy_token):
        fail("release-input destruction token is invalid")
    verify_release_inputs(
        descriptor_path, expected_release_key_sha256=expected_release_key_sha256
    )
    stage = Path(os.path.abspath(os.fspath(descriptor_path))).parent
    owner = load_canonical_json(
        stage / ".dcentos-s19k-release-input-owner", 4096, "release-input owner"
    )
    if not secrets.compare_digest(
        owner["destroy_token_sha256"], sha256_bytes(destroy_token.encode("ascii"))
    ):
        fail("release-input destruction token does not own this stage")
    files, directories = _walk_regular_tree(stage, "release-input cleanup stage")
    if directories or set(files) != {
        ".dcentos-s19k-release-input-owner",
        "native-owner-verification.json",
        "release-inputs.json",
        "stock-recovery-verification.json",
        "trusted-release-key.pem",
    }:
        fail("release-input cleanup stage contains unowned content")
    for relative in files:
        path = stage / relative
        os.chmod(path, 0o600)
        path.unlink()
    os.chmod(stage, 0o700)
    stage.rmdir()


def _admit_private_signing_key_path(path: Path) -> dict[str, Any]:
    """Admit private-key custody without opening or reading private bytes."""

    if os.name == "nt" or not hasattr(os, "getuid"):
        fail("production private-key custody admission requires Linux")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if Path(os.path.realpath(os.fspath(absolute))) != absolute:
        fail("private signing-key path contains a symlink or alias")
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode) or _is_reparse(metadata):
            fail("private signing-key parent traversal contains an indirect entry")
    metadata = os.lstat(absolute)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        fail("private signing key must be one direct single-link regular file")
    uid = os.getuid()
    gid = os.getgid()
    if metadata.st_uid != uid or metadata.st_gid != gid:
        fail("private signing key is not owned by the executing UID/GID")
    mode = stat.S_IMODE(metadata.st_mode)
    if mode not in (0o400, 0o600):
        fail("private signing key must have exact mode 0400 or 0600")
    if metadata.st_size <= 0 or metadata.st_size > MAX_KEY_BYTES:
        fail("private signing key is empty or oversized")
    parent = absolute.parent
    parent_metadata = os.lstat(parent)
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != uid
        or parent_metadata.st_gid != gid
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
    ):
        fail("private signing-key parent lacks exact owner/mode 0700 custody")
    filesystem, options = _linux_mount_contract(parent)
    if filesystem != "ext4" or "rw" not in options:
        fail("private signing key must reside on one writable ext4 custody mount")
    body = {
        "path": os.fspath(absolute),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": f"{mode:04o}",
        "uid": uid,
        "gid": gid,
        "nlink": metadata.st_nlink,
        "bytes": metadata.st_size,
        "parent_device": parent_metadata.st_dev,
        "parent_inode": parent_metadata.st_ino,
        "parent_mode": "0700",
        "filesystem": filesystem,
        "mount_options": sorted(options),
        "private_bytes_opened_by_host": False,
    }
    result = dict(body)
    result["custody_id"] = sha256_bytes(canonical_json(body))
    return result


def _portable_test_private_key_custody(path: Path) -> dict[str, Any]:
    """Non-production custody marker used only when strict durability is disabled."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    metadata = _require_regular(absolute, MAX_KEY_BYTES, "test private signing key")
    if metadata.st_size <= 0:
        fail("test private signing key is empty")
    body = {
        "path": os.fspath(absolute),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "bytes": metadata.st_size,
        "private_bytes_opened_by_host": False,
        "classification": "portable-test-only-not-production-custody",
    }
    result = dict(body)
    result["custody_id"] = sha256_bytes(canonical_json(body))
    return result


def _require_nonoverlapping_paths(paths: Mapping[str, Path]) -> None:
    normalized = {
        label: Path(os.path.realpath(os.fspath(Path(path).absolute())))
        for label, path in paths.items()
    }
    items = list(normalized.items())
    for index, (label, path) in enumerate(items):
        for other_label, other in items[index + 1 :]:
            try:
                common = Path(os.path.commonpath((path, other)))
            except ValueError:
                continue
            if common in (path, other):
                fail(
                    "isolated signer custody paths overlap or alias by ancestry: "
                    f"{label}, {other_label}"
                )


def validate_source_admission_receipt(value: object) -> dict[str, Any]:
    receipt = _exact_object(
        value,
        (
            "schema",
            "source_commit",
            "source_tree",
            "source_date_epoch",
            "commit_signature_verified",
            "commit_signer_identity",
            "signing_policy_id",
            "clean_worktree_verified_before_and_after",
            "signature_verification_output_sha256",
            "snapshot_id",
            "snapshot_descriptor_sha256",
            "source_files",
            "admission_id",
        ),
        "source-admission receipt",
    )
    body = dict(receipt)
    body.pop("admission_id")
    if (
        receipt["schema"] != SOURCE_SCHEMA
        or not FULL_COMMIT.fullmatch(receipt["source_commit"])
        or not FULL_COMMIT.fullmatch(receipt["source_tree"])
        or isinstance(receipt["source_date_epoch"], bool)
        or not isinstance(receipt["source_date_epoch"], int)
        or receipt["source_date_epoch"] < 0
        or receipt["source_date_epoch"] > MAX_SOURCE_EPOCH
        or receipt["commit_signature_verified"] is not True
        or not isinstance(receipt["commit_signer_identity"], str)
        or not OPENPGP_SIGNER.fullmatch(receipt["commit_signer_identity"])
        or not isinstance(receipt["signing_policy_id"], str)
        or not HEX_64.fullmatch(receipt["signing_policy_id"])
        or receipt["clean_worktree_verified_before_and_after"] is not True
        or not HEX_64.fullmatch(receipt["signature_verification_output_sha256"])
        or not HEX_64.fullmatch(receipt["snapshot_id"])
        or not HEX_64.fullmatch(receipt["snapshot_descriptor_sha256"])
        or not HEX_64.fullmatch(receipt["admission_id"])
        or receipt["admission_id"] != sha256_bytes(canonical_json(body))
    ):
        fail("source-admission receipt is invalid, stale, or overclaims admission")
    source_files = receipt["source_files"]
    if not isinstance(source_files, list) or not source_files:
        fail("source-admission receipt lacks a bounded source-file ledger")
    paths: list[str] = []
    for index, raw_item in enumerate(source_files):
        item = _exact_object(
            raw_item,
            ("path", "sha256", "bytes", "git_mode"),
            f"source-admission file {index}",
        )
        paths.append(_safe_relative(item["path"], f"source-admission file {index} path"))
        if (
            not HEX_64.fullmatch(item["sha256"])
            or isinstance(item["bytes"], bool)
            or not isinstance(item["bytes"], int)
            or item["bytes"] < 0
            or item["git_mode"] not in ("100644", "100755")
        ):
            fail(f"source-admission file {index} evidence is invalid")
    if paths != sorted(paths, key=lambda item: item.encode("utf-8")) or len(paths) != len(
        {path.casefold() for path in paths}
    ):
        fail("source-admission file ledger is unsorted or portable-colliding")
    return receipt


@dataclass(frozen=True)
class MaterializerRequest:
    materialization_id: str
    builder_image: str
    toolchain_id: str
    source_commit: str
    source_snapshot: Path
    source_tree: Path
    source_snapshot_id: str
    amlogic_kernel: Path
    amlogic_dtb: Path
    amlogic_fw_info: Path
    invocation_root: Path
    runtime_root: Path
    work_root: Path
    output_root: Path
    selection_path: Path
    log_path: Path
    inspect_before_path: Path
    inspect_after_path: Path


class DependencyMaterializerRuntime(Protocol):
    def execute(self, request: MaterializerRequest) -> Mapping[str, Any]:
        """Fetch one source-only closure and return host-inspected evidence."""


@dataclass(frozen=True)
class MaterializedDependencyBundle:
    bundle: DependencyBundle
    invocation_root: Path
    observation: dict[str, Any]
    observation_path: Path
    receipt: Path
    receipt_id: str


def _validate_materializer_observation(
    value: object, request: MaterializerRequest
) -> dict[str, Any]:
    observation = _exact_object(
        value,
        (
            "schema",
            "runtime_id",
            "materialization_id",
            "builder_image",
            "toolchain_id",
            "source_commit",
            "source_snapshot_id",
            "network_mode",
            "network_boundary_inspected",
            "read_only_rootfs",
            "privileged",
            "build_cache_reused",
            "exit_code",
            "output_relative_path",
            "selection_relative_path",
            "log_relative_path",
            "inspect_before_relative_path",
            "inspect_before_sha256",
            "inspect_after_relative_path",
            "inspect_after_sha256",
        ),
        "dependency materializer runtime observation",
    )
    expected = {
        "schema": MATERIALIZER_OBSERVATION_SCHEMA,
        "materialization_id": request.materialization_id,
        "builder_image": request.builder_image,
        "toolchain_id": request.toolchain_id,
        "source_commit": request.source_commit,
        "source_snapshot_id": request.source_snapshot_id,
        "network_mode": "unrestricted-bridge-source-fetch-intent",
        "network_boundary_inspected": "container-config-only-no-egress-proof",
        "read_only_rootfs": True,
        "privileged": False,
        "build_cache_reused": False,
        "exit_code": 0,
        "output_relative_path": "output",
        "selection_relative_path": "selection.json",
        "log_relative_path": "materializer.log",
        "inspect_before_relative_path": "inspect-before.json",
        "inspect_after_relative_path": "inspect-after.json",
    }
    for field, expected_value in expected.items():
        if observation.get(field) != expected_value:
            fail(f"dependency materializer observation disagrees on {field}")
    if not isinstance(observation["runtime_id"], str) or not TOKEN.fullmatch(
        observation["runtime_id"]
    ):
        fail("dependency materializer runtime ID is invalid")
    for field in ("inspect_before_sha256", "inspect_after_sha256"):
        if not isinstance(observation[field], str) or not HEX_64.fullmatch(
            observation[field]
        ):
            fail(f"dependency materializer {field} is invalid")
    return observation


def _verify_materialized_buildroot_archive(
    exported_source: Path, buildroot_policy: Mapping[str, Any]
) -> None:
    """Verify only the policy-pinned regular archive emitted by the fetch sandbox.

    The network-enabled materializer owns its checkout and ``.git`` metadata.
    Those bytes are deliberately never passed to a host Git executable.
    """

    exported_source = Path(os.path.abspath(os.fspath(exported_source)))
    _require_directory(exported_source, "materialized Buildroot source")
    observed_files, observed_directories = _walk_regular_tree(
        exported_source, "materialized Buildroot export"
    )
    if observed_files != ["buildroot-source.tar"] or observed_directories:
        fail("materialized Buildroot export is not one exact Git archive")
    retained_sha256, retained_bytes = hash_regular(
        exported_source / "buildroot-source.tar",
        MAX_DEPENDENCY_FILE_BYTES,
        "materialized Buildroot Git archive",
    )
    if (
        retained_sha256 != buildroot_policy.get("source_archive_sha256")
        or retained_bytes != buildroot_policy.get("source_archive_bytes")
    ):
        fail("materialized Buildroot archive differs from authenticated policy bytes")


def materialize_and_seal_dependencies(
    runtime: DependencyMaterializerRuntime,
    source: SourceAdmission,
    materializer_parent: Path,
    dependency_stage_parent: Path,
    *,
    builder_image: str,
    toolchain_id: str,
    amlogic_kernel: Path,
    amlogic_dtb: Path,
    amlogic_fw_info: Path,
    strict_durability: bool = True,
    source_verifier: Callable[[], None] | None = None,
    buildroot_verifier: Callable[[Path, Mapping[str, Any]], None] | None = None,
) -> MaterializedDependencyBundle:
    """Run the network-only phase once, inspect it, and host-seal its closure."""

    receipt = validate_source_admission_receipt(source.receipt)
    if not IMMUTABLE_IMAGE.fullmatch(builder_image):
        fail("dependency materializer builder image is not digest-pinned")
    if not TOKEN.fullmatch(toolchain_id):
        fail("dependency materializer toolchain ID is invalid")
    parent = Path(os.path.abspath(os.fspath(materializer_parent)))
    stage_parent = Path(os.path.abspath(os.fspath(dependency_stage_parent)))
    if strict_durability and os.name != "nt":
        _require_private_ext4_parent(parent, "dependency materializer parent")
        _require_private_ext4_parent(stage_parent, "dependency stage parent")
    else:
        _require_directory(parent, "dependency materializer parent")
        _require_directory(stage_parent, "dependency stage parent")
    policy_path = source.tree.joinpath(*PurePosixPath(DEPENDENCY_POLICY_RELATIVE).parts)
    policy, _ = load_dependency_policy(policy_path)
    policy_builder = policy["builder"]
    if builder_image != policy_builder["image"]:
        fail("selected builder image differs from authenticated dependency policy")
    if toolchain_id != policy_builder["toolchain_id"]:
        fail("selected toolchain ID differs from authenticated dependency policy")
    dockerfile_policy = policy_builder["dockerfile"]
    dockerfile_path = source.tree.joinpath(*PurePosixPath(dockerfile_policy["path"]).parts)
    dockerfile_sha256, dockerfile_bytes = hash_regular(
        dockerfile_path, MAX_JSON_BYTES, "authenticated builder Dockerfile"
    )
    if (
        dockerfile_sha256 != dockerfile_policy["sha256"]
        or dockerfile_bytes != dockerfile_policy["bytes"]
    ):
        fail("builder Dockerfile differs from authenticated dependency policy")

    held = {
        "vmlinux.bin": Path(os.path.abspath(os.fspath(amlogic_kernel))),
        "devicetree.dtb": Path(os.path.abspath(os.fspath(amlogic_dtb))),
        "fw-info": Path(os.path.abspath(os.fspath(amlogic_fw_info))),
    }
    policy_by_name = {item["name"]: item for item in policy["amlogic_inputs"]}
    for name, path in held.items():
        item = policy_by_name[name]
        digest, size = hash_regular(path, MAX_PACKAGE_BYTES, f"held Amlogic {name}")
        if digest != item["sha256"] or size != item["bytes"]:
            fail(f"held Amlogic {name} differs from the authenticated policy")

    def default_source_verifier() -> None:
        _verify_admitted_source_snapshot(source, receipt)

    verify_source = source_verifier or default_source_verifier
    verify_buildroot = buildroot_verifier or _verify_materialized_buildroot_archive
    invocation = Path(
        tempfile.mkdtemp(prefix="dcentos-s19k-materializer-", dir=parent)
    )
    materialization_id = f"s19k-dependencies-{secrets.token_hex(16)}"
    runtime_container_name = f"dcentos-{materialization_id}"
    owner = {
        "schema": MATERIALIZER_OWNER_SCHEMA,
        "materialization_id": materialization_id,
        "runtime_container_name": runtime_container_name,
        "classification": "network-phase-never-clean-build-evidence",
        "source_commit": receipt["source_commit"],
        "source_snapshot_id": receipt["snapshot_id"],
        "builder_image": builder_image,
        "toolchain_id": toolchain_id,
        "dependency_policy_sha256": DEPENDENCY_POLICY_SHA256,
        "install_authority_granted": False,
        "flash_authority_granted": False,
    }
    owner_raw = canonical_json(owner)
    owner_path = invocation / ".dcentos-s19k-materializer-owner"
    write_no_replace(owner_path, owner_raw)
    owner_metadata = os.lstat(owner_path)
    runtime_root = invocation / "runtime"
    runtime_root.mkdir(mode=0o700)
    _fsync_directory(runtime_root, strict=strict_durability)
    _fsync_directory(invocation, strict=strict_durability)
    _fsync_directory(parent, strict=strict_durability)
    request = MaterializerRequest(
        materialization_id=materialization_id,
        builder_image=builder_image,
        toolchain_id=toolchain_id,
        source_commit=receipt["source_commit"],
        source_snapshot=source.snapshot,
        source_tree=source.tree,
        source_snapshot_id=receipt["snapshot_id"],
        amlogic_kernel=held["vmlinux.bin"],
        amlogic_dtb=held["devicetree.dtb"],
        amlogic_fw_info=held["fw-info"],
        invocation_root=invocation,
        runtime_root=runtime_root,
        work_root=runtime_root / "work",
        output_root=runtime_root / "output",
        selection_path=runtime_root / "selection.json",
        log_path=invocation / "materializer.log",
        inspect_before_path=invocation / "inspect-before.json",
        inspect_after_path=invocation / "inspect-after.json",
    )
    try:
        verify_source()
        observation = _validate_materializer_observation(runtime.execute(request), request)
        retained_owner = read_regular(
            owner_path, 4096, "dependency materializer owner sentinel"
        )
        current_owner = os.lstat(owner_path)
        if (
            retained_owner != owner_raw
            or (current_owner.st_dev, current_owner.st_ino)
            != (owner_metadata.st_dev, owner_metadata.st_ino)
        ):
            fail("dependency materializer owner sentinel changed during execution")
        with os.scandir(runtime_root) as iterator:
            runtime_entries = {
                entry.name: entry.stat(follow_symlinks=False) for entry in iterator
            }
        if set(runtime_entries) != {"work", "output", "selection.json"}:
            fail("dependency materializer runtime root has an inexact top-level ledger")
        if (
            not stat.S_ISDIR(runtime_entries["work"].st_mode)
            or not stat.S_ISDIR(runtime_entries["output"].st_mode)
            or not stat.S_ISREG(runtime_entries["selection.json"].st_mode)
            or _is_reparse(runtime_entries["work"])
            or _is_reparse(runtime_entries["output"])
            or _is_reparse(runtime_entries["selection.json"])
        ):
            fail("dependency materializer runtime ledger changed type")
        for path, field in (
            (request.inspect_before_path, "inspect_before_sha256"),
            (request.inspect_after_path, "inspect_after_sha256"),
        ):
            raw_inspection = read_regular(
                path, MAX_JSON_BYTES, f"dependency materializer {path.name}"
            )
            try:
                inspection = json.loads(raw_inspection)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                fail(f"dependency materializer {path.name} is invalid JSON: {error}")
            if not isinstance(inspection, dict) or raw_inspection != canonical_json(inspection):
                fail(f"dependency materializer {path.name} is not canonical")
            if sha256_bytes(raw_inspection) != observation[field]:
                fail(f"dependency materializer {path.name} differs from observation")
        verify_source()
        verify_buildroot(
            request.output_root / "buildroot/source",
            policy["buildroot"],
        )
        bundle = seal_dependency_bundle(
            request.output_root,
            request.selection_path,
            policy_path,
            stage_parent,
            expected_source_commit=receipt["source_commit"],
            expected_builder_image=builder_image,
            expected_toolchain_id=toolchain_id,
            strict_durability=strict_durability,
        )
        verify_source()
        verified_bundle = verify_dependency_bundle(
            bundle.descriptor,
            expected_source_commit=receipt["source_commit"],
            expected_builder_image=builder_image,
            expected_toolchain_id=toolchain_id,
        )
        if verified_bundle["bundle_id"] != bundle.bundle_id:
            fail("fresh dependency bundle handle differs from its verified descriptor")
        log_sha256, log_bytes = hash_regular(
            request.log_path,
            MAX_RECEIPT_BYTES,
            "dependency materializer retained log",
        )
        if log_bytes == 0:
            fail("dependency materializer retained an empty log")
        observation_raw = canonical_json(observation)
        observation_path = invocation / "runtime-observation.json"
        write_no_replace(observation_path, observation_raw)
        success_body = {
            "schema": MATERIALIZER_SUCCESS_SCHEMA,
            "materialization_id": materialization_id,
            "runtime_container_name": runtime_container_name,
            "classification": "network-phase-never-clean-build-evidence",
            "source_commit": receipt["source_commit"],
            "source_snapshot_id": receipt["snapshot_id"],
            "builder_image": builder_image,
            "toolchain_id": toolchain_id,
            "dependency_policy_sha256": DEPENDENCY_POLICY_SHA256,
            "dependency_bundle_id": bundle.bundle_id,
            "runtime_observation_sha256": sha256_bytes(observation_raw),
            "materializer_log_sha256": log_sha256,
            "materializer_log_bytes": log_bytes,
            "network_mode": "unrestricted-bridge-source-fetch-intent",
            "network_boundary_inspected": "container-config-only-no-egress-proof",
            "build_cache_reused": False,
            "release_authority_granted": False,
            "install_authority_granted": False,
            "flash_authority_granted": False,
        }
        success = dict(success_body)
        success["receipt_id"] = sha256_bytes(canonical_json(success_body))
        success_path = invocation / "success.json"
        write_no_replace(success_path, canonical_json(success))
        _fsync_directory(invocation, strict=strict_durability)
        verify_materializer_receipt(
            success_path,
            bundle.descriptor,
            expected_source_commit=receipt["source_commit"],
            expected_builder_image=builder_image,
            expected_toolchain_id=toolchain_id,
        )
        return MaterializedDependencyBundle(
            bundle,
            invocation,
            observation,
            observation_path,
            success_path,
            success["receipt_id"],
        )
    except Exception as error:
        failure_body = {
            "schema": "dcentos.s19k-hermetic-materializer-failure/v1",
            "materialization_id": materialization_id,
            "classification": "network-phase-failed-never-clean-build-evidence",
            "error_type": type(error).__name__,
            "network_status": "network-enabled-source-fetch-phase",
            "build_cache_status": "not-applicable-to-build-evidence",
            "install_authority_granted": False,
            "flash_authority_granted": False,
        }
        failure = dict(failure_body)
        failure["failure_id"] = sha256_bytes(canonical_json(failure_body))
        try:
            write_no_replace(invocation / "failure.json", canonical_json(failure))
            _fsync_directory(invocation, strict=strict_durability)
        except (OSError, ProducerError):
            pass
        raise


def verify_materializer_receipt(
    receipt_path: Path,
    dependency_descriptor: Path,
    *,
    expected_source_commit: str | None = None,
    expected_builder_image: str | None = None,
    expected_toolchain_id: str | None = None,
) -> dict[str, Any]:
    """Reverify one retained network-phase receipt without granting authority."""

    receipt_path = Path(os.path.abspath(os.fspath(receipt_path)))
    invocation = receipt_path.parent
    _require_directory(invocation, "dependency materializer invocation")
    if receipt_path.name != "success.json":
        fail("dependency materializer success receipt has an unexpected name")
    receipt = _exact_object(
        load_canonical_json(
            receipt_path, MAX_JSON_BYTES, "dependency materializer success receipt"
        ),
        (
            "schema",
            "materialization_id",
            "runtime_container_name",
            "classification",
            "source_commit",
            "source_snapshot_id",
            "builder_image",
            "toolchain_id",
            "dependency_policy_sha256",
            "dependency_bundle_id",
            "runtime_observation_sha256",
            "materializer_log_sha256",
            "materializer_log_bytes",
            "network_mode",
            "network_boundary_inspected",
            "build_cache_reused",
            "release_authority_granted",
            "install_authority_granted",
            "flash_authority_granted",
            "receipt_id",
        ),
        "dependency materializer success receipt",
    )
    receipt_body = dict(receipt)
    receipt_body.pop("receipt_id")
    if (
        receipt["schema"] != MATERIALIZER_SUCCESS_SCHEMA
        or not isinstance(receipt["materialization_id"], str)
        or not TOKEN.fullmatch(receipt["materialization_id"])
        or receipt["runtime_container_name"]
        != f"dcentos-{receipt['materialization_id']}"
        or receipt["classification"] != "network-phase-never-clean-build-evidence"
        or not isinstance(receipt["source_commit"], str)
        or not FULL_COMMIT.fullmatch(receipt["source_commit"])
        or not isinstance(receipt["source_snapshot_id"], str)
        or not HEX_64.fullmatch(receipt["source_snapshot_id"])
        or not isinstance(receipt["builder_image"], str)
        or not IMMUTABLE_IMAGE.fullmatch(receipt["builder_image"])
        or not isinstance(receipt["toolchain_id"], str)
        or not TOKEN.fullmatch(receipt["toolchain_id"])
        or receipt["dependency_policy_sha256"] != DEPENDENCY_POLICY_SHA256
        or not isinstance(receipt["dependency_bundle_id"], str)
        or not HEX_64.fullmatch(receipt["dependency_bundle_id"])
        or not isinstance(receipt["runtime_observation_sha256"], str)
        or not HEX_64.fullmatch(receipt["runtime_observation_sha256"])
        or not isinstance(receipt["materializer_log_sha256"], str)
        or not HEX_64.fullmatch(receipt["materializer_log_sha256"])
        or isinstance(receipt["materializer_log_bytes"], bool)
        or not isinstance(receipt["materializer_log_bytes"], int)
        or receipt["materializer_log_bytes"] <= 0
        or receipt["materializer_log_bytes"] > MAX_RECEIPT_BYTES
        or receipt["network_mode"] != "unrestricted-bridge-source-fetch-intent"
        or receipt["network_boundary_inspected"]
        != "container-config-only-no-egress-proof"
        or receipt["build_cache_reused"] is not False
        or receipt["release_authority_granted"] is not False
        or receipt["install_authority_granted"] is not False
        or receipt["flash_authority_granted"] is not False
        or receipt["receipt_id"] != sha256_bytes(canonical_json(receipt_body))
    ):
        fail("dependency materializer success receipt is invalid or overclaims authority")
    if expected_source_commit is not None and receipt["source_commit"] != expected_source_commit:
        fail("dependency materializer receipt source commit differs from expectation")
    if expected_builder_image is not None and receipt["builder_image"] != expected_builder_image:
        fail("dependency materializer receipt builder image differs from expectation")
    if expected_toolchain_id is not None and receipt["toolchain_id"] != expected_toolchain_id:
        fail("dependency materializer receipt toolchain differs from expectation")

    observed_names: dict[str, os.stat_result] = {}
    with os.scandir(invocation) as iterator:
        for entry in iterator:
            observed_names[entry.name] = entry.stat(follow_symlinks=False)
    expected_names = {
        ".dcentos-s19k-materializer-owner",
        "runtime",
        "materializer.log",
        "inspect-before.json",
        "inspect-after.json",
        "runtime-observation.json",
        "success.json",
    }
    if set(observed_names) != expected_names:
        fail("dependency materializer invocation ledger is not exact")
    invalid_invocation_entries = [
        (
            name,
            oct(observed_names[name].st_mode),
            observed_names[name].st_nlink,
            _is_reparse(observed_names[name]),
        )
        for name in sorted(expected_names - {"runtime"})
        if not stat.S_ISREG(observed_names[name].st_mode)
        or _is_reparse(observed_names[name])
        or (os.name != "nt" and observed_names[name].st_nlink != 1)
    ]
    if not stat.S_ISDIR(observed_names["runtime"].st_mode) or invalid_invocation_entries:
        fail(
            "dependency materializer invocation ledger changed type: "
            f"{invalid_invocation_entries!r}"
        )
    runtime_root = invocation / "runtime"
    with os.scandir(runtime_root) as iterator:
        runtime_entries = {
            entry.name: entry.stat(follow_symlinks=False) for entry in iterator
        }
    if set(runtime_entries) != {"work", "output", "selection.json"}:
        fail("dependency materializer runtime ledger is not exact")
    if (
        not stat.S_ISDIR(runtime_entries["work"].st_mode)
        or not stat.S_ISDIR(runtime_entries["output"].st_mode)
        or not stat.S_ISREG(runtime_entries["selection.json"].st_mode)
        or _is_reparse(runtime_entries["work"])
        or _is_reparse(runtime_entries["output"])
        or _is_reparse(runtime_entries["selection.json"])
        or (os.name != "nt" and runtime_entries["selection.json"].st_nlink != 1)
    ):
        fail("dependency materializer runtime ledger changed type")

    owner = _exact_object(
        load_canonical_json(
            invocation / ".dcentos-s19k-materializer-owner",
            4096,
            "dependency materializer owner",
        ),
        (
            "schema",
            "materialization_id",
            "runtime_container_name",
            "classification",
            "source_commit",
            "source_snapshot_id",
            "builder_image",
            "toolchain_id",
            "dependency_policy_sha256",
            "install_authority_granted",
            "flash_authority_granted",
        ),
        "dependency materializer owner",
    )
    if owner != {
        "schema": MATERIALIZER_OWNER_SCHEMA,
        "materialization_id": receipt["materialization_id"],
        "runtime_container_name": f"dcentos-{receipt['materialization_id']}",
        "classification": "network-phase-never-clean-build-evidence",
        "source_commit": receipt["source_commit"],
        "source_snapshot_id": receipt["source_snapshot_id"],
        "builder_image": receipt["builder_image"],
        "toolchain_id": receipt["toolchain_id"],
        "dependency_policy_sha256": DEPENDENCY_POLICY_SHA256,
        "install_authority_granted": False,
        "flash_authority_granted": False,
    }:
        fail("dependency materializer owner and success receipt disagree")

    observation_raw = read_regular(
        invocation / "runtime-observation.json",
        MAX_JSON_BYTES,
        "dependency materializer runtime observation",
    )
    if sha256_bytes(observation_raw) != receipt["runtime_observation_sha256"]:
        fail("dependency materializer runtime observation differs from receipt")
    try:
        observation = json.loads(observation_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"dependency materializer runtime observation is invalid JSON: {error}")
    observation = _exact_object(
        observation,
        (
            "schema",
            "runtime_id",
            "materialization_id",
            "builder_image",
            "toolchain_id",
            "source_commit",
            "source_snapshot_id",
            "network_mode",
            "network_boundary_inspected",
            "read_only_rootfs",
            "privileged",
            "build_cache_reused",
            "exit_code",
            "output_relative_path",
            "selection_relative_path",
            "log_relative_path",
            "inspect_before_relative_path",
            "inspect_before_sha256",
            "inspect_after_relative_path",
            "inspect_after_sha256",
        ),
        "dependency materializer runtime observation",
    )
    if observation_raw != canonical_json(observation):
        fail("dependency materializer runtime observation is noncanonical")
    expected_observation = {
        "schema": MATERIALIZER_OBSERVATION_SCHEMA,
        "materialization_id": receipt["materialization_id"],
        "builder_image": receipt["builder_image"],
        "toolchain_id": receipt["toolchain_id"],
        "source_commit": receipt["source_commit"],
        "source_snapshot_id": receipt["source_snapshot_id"],
        "network_mode": "unrestricted-bridge-source-fetch-intent",
        "network_boundary_inspected": "container-config-only-no-egress-proof",
        "read_only_rootfs": True,
        "privileged": False,
        "build_cache_reused": False,
        "exit_code": 0,
        "output_relative_path": "output",
        "selection_relative_path": "selection.json",
        "log_relative_path": "materializer.log",
        "inspect_before_relative_path": "inspect-before.json",
        "inspect_after_relative_path": "inspect-after.json",
    }
    for field, expected_value in expected_observation.items():
        if observation.get(field) != expected_value:
            fail(f"dependency materializer retained observation disagrees on {field}")
    if not isinstance(observation["runtime_id"], str) or not TOKEN.fullmatch(
        observation["runtime_id"]
    ):
        fail("dependency materializer retained runtime ID is invalid")

    for name, field in (
        ("inspect-before.json", "inspect_before_sha256"),
        ("inspect-after.json", "inspect_after_sha256"),
    ):
        raw = read_regular(
            invocation / name, MAX_JSON_BYTES, f"dependency materializer {name}"
        )
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"dependency materializer {name} is invalid JSON: {error}")
        if (
            not isinstance(value, dict)
            or raw != canonical_json(value)
            or sha256_bytes(raw) != observation[field]
        ):
            fail(f"dependency materializer {name} differs from observation")
    log_sha256, log_bytes = hash_regular(
        invocation / "materializer.log",
        MAX_RECEIPT_BYTES,
        "dependency materializer log",
    )
    if (
        log_sha256 != receipt["materializer_log_sha256"]
        or log_bytes != receipt["materializer_log_bytes"]
    ):
        fail("dependency materializer log differs from receipt")

    dependency = verify_dependency_bundle(
        dependency_descriptor,
        expected_source_commit=receipt["source_commit"],
        expected_builder_image=receipt["builder_image"],
        expected_toolchain_id=receipt["toolchain_id"],
    )
    if dependency["bundle_id"] != receipt["dependency_bundle_id"]:
        fail("dependency materializer receipt and sealed bundle disagree")
    return receipt


@dataclass(frozen=True)
class BuildRequest:
    label: str
    build_id: str
    build_root_id: str
    builder_image: str
    toolchain_id: str
    source_commit: str
    source_date_epoch: int
    source_snapshot: Path
    source_tree: Path
    source_snapshot_id: str
    dependency_stage: Path
    dependency_bundle_id: str
    release_input_stage: Path
    release_input_id: str
    expected_release_key_sha256: str
    manifest_public_key_hex: str
    mutable_paths: Mapping[str, Path]


class OfflineBuildRuntime(Protocol):
    def execute(self, request: BuildRequest) -> Mapping[str, Any]:
        """Execute one build and return an independently inspected observation."""


@dataclass(frozen=True)
class IsolatedSignerRequest:
    signing_id: str
    builder_image: str
    dependency_stage: Path
    source_stage: Path
    public_stage: Path
    private_key: Path
    private_key_custody: Mapping[str, Any]
    output_parent: Path
    log_path: Path
    inspect_before_path: Path
    inspect_after_path: Path
    expected_release_key_sha256: str
    verifier_sha256: str
    signer_sha256: str
    host_preflight_id: str


class IsolatedSignerRuntime(Protocol):
    def execute(self, request: IsolatedSignerRequest) -> Mapping[str, Any]:
        """Run one separately inspected, network-none post-A/B signer."""


@dataclass(frozen=True)
class ExecutedBuildPair:
    build_a: ValidatedBuildResult
    build_b: ValidatedBuildResult
    build_roots: tuple[Path, Path]
    build_root_destroy_tokens: tuple[str, str]
    publication_capability: str


def _validate_runtime_observation(
    value: object, request: BuildRequest
) -> dict[str, Any]:
    observation = _exact_object(
        value,
        (
            "schema",
            "runtime_id",
            "build_id",
            "build_root_id",
            "builder_image",
            "source_snapshot_id",
            "dependency_bundle_id",
            "release_input_id",
            "network_mode",
            "network_boundary_inspected",
            "read_only_rootfs",
            "privileged",
            "build_cache_reused",
            "exit_code",
            "package_relative_path",
            "build_log_relative_path",
        ),
        f"build {request.label} runtime observation",
    )
    expected = {
        "schema": RUNTIME_OBSERVATION_SCHEMA,
        "build_id": request.build_id,
        "build_root_id": request.build_root_id,
        "builder_image": request.builder_image,
        "source_snapshot_id": request.source_snapshot_id,
        "dependency_bundle_id": request.dependency_bundle_id,
        "release_input_id": request.release_input_id,
        "network_mode": "none",
        "network_boundary_inspected": True,
        "read_only_rootfs": True,
        "privileged": False,
        "build_cache_reused": False,
        "exit_code": 0,
        "package_relative_path": f"result/{INNER_PACKAGE_NAME}",
        "build_log_relative_path": "logs/build.log",
    }
    for field, expected_value in expected.items():
        if observation.get(field) != expected_value:
            fail(f"build {request.label} runtime observation disagrees on {field}")
    if not isinstance(observation["runtime_id"], str) or not TOKEN.fullmatch(
        observation["runtime_id"]
    ):
        fail(f"build {request.label} runtime ID is invalid")
    return observation


def _create_fresh_build_root(
    parent: Path, label: str
) -> tuple[Path, str, str, str, dict[str, Path]]:
    build_id = f"s19k-hermetic-{label}-{secrets.token_hex(16)}"
    build_root_id = f"s19k-clean-root-{label}-{secrets.token_hex(16)}"
    runtime_container_name = f"dcentos-{build_id}"
    destroy_token = secrets.token_hex(32)
    root = Path(tempfile.mkdtemp(prefix=f"dcentos-s19k-build-{label}-", dir=parent))
    mutable: dict[str, Path] = {}
    try:
        for role in MUTABLE_ROOT_ROLES:
            path = root / role
            path.mkdir(mode=0o700)
            mutable[role] = path
        owner = {
            "schema": BUILD_OWNER_SCHEMA,
            "build_id": build_id,
            "build_root_id": build_root_id,
            "runtime_container_name": runtime_container_name,
            "destroy_token_sha256": sha256_bytes(destroy_token.encode("ascii")),
            "classification": "mutable-root-never-clean-evidence",
            "mutable_roots": [f"{build_root_id}:{role}" for role in MUTABLE_ROOT_ROLES],
        }
        write_no_replace(root / ".dcentos-s19k-build-owner", canonical_json(owner))
        _fsync_directory(root, strict=os.name != "nt")
        _fsync_directory(parent, strict=os.name != "nt")
        for path in mutable.values():
            if any(path.iterdir()):
                fail(f"new build {label} mutable root did not start empty: {path}")
        return root, build_id, build_root_id, destroy_token, mutable
    except Exception:
        try:
            files, directories = _walk_regular_tree(root, f"failed build {label} allocation")
            if set(files).issubset({".dcentos-s19k-build-owner"}):
                for relative in files:
                    (root / relative).unlink()
                for relative in sorted(
                    directories,
                    key=lambda value: (value.count("/"), value),
                    reverse=True,
                ):
                    (root / relative).rmdir()
                root.rmdir()
        except (OSError, ProducerError):
            pass
        raise


def _write_build_failure(
    root: Path,
    request: BuildRequest,
    error: BaseException,
    *,
    strict_durability: bool,
) -> None:
    """Durably retain a conservative, nonresumable failure classification.

    A failed runtime cannot prove that it stayed offline or avoided caches, so
    those facts are recorded as unknown instead of being hard-coded false.
    The build-root owner was already fsynced before execution and independently
    classifies the mutable root as never being clean evidence; this receipt is
    supplemental evidence for caught failures, not the crash-safety boundary.
    """

    body = {
        "schema": BUILD_FAILURE_SCHEMA,
        "label": request.label,
        "build_id": request.build_id,
        "build_root_id": request.build_root_id,
        "classification": "failed-not-resumable-as-clean",
        "error_type": type(error).__name__,
        "network_status": "not-proven-unused",
        "cache_status": "not-proven-fresh",
        "clean_build": False,
        "persistent_image_evidence_verified": False,
        "install_authority_granted": False,
        "flash_authority_granted": False,
        "mutation_authority_granted": False,
    }
    failure = dict(body)
    failure["failure_id"] = sha256_bytes(canonical_json(body))
    path = root / "failure.json"
    if not path.exists() and not path.is_symlink():
        try:
            write_no_replace(path, canonical_json(failure))
            _fsync_directory(root, strict=strict_durability)
        except (OSError, ProducerError):
            pass


def _execute_one_build(
    runtime: OfflineBuildRuntime,
    request: BuildRequest,
    build_root: Path,
    result_parent: Path,
    *,
    verify_source: Callable[[], None],
    verify_dependencies: Callable[[], None],
    verify_release_input_stage: Callable[[], None],
    strict_durability: bool,
) -> ValidatedBuildResult:
    label = request.label
    try:
        verify_source()
        verify_dependencies()
        verify_release_input_stage()
        observation = _validate_runtime_observation(runtime.execute(request), request)
        verify_source()
        verify_dependencies()
        verify_release_input_stage()
        package = request.mutable_paths["result"] / INNER_PACKAGE_NAME
        log = request.mutable_paths["logs"] / "build.log"
        result_files, result_dirs = _walk_regular_tree(
            request.mutable_paths["result"], f"build {label} runtime result"
        )
        log_files, log_dirs = _walk_regular_tree(
            request.mutable_paths["logs"], f"build {label} runtime logs"
        )
        if result_files != [INNER_PACKAGE_NAME] or result_dirs:
            fail(f"build {label} runtime result has missing or extra content")
        if log_files != ["build.log"] or log_dirs:
            fail(f"build {label} runtime log stage has missing or extra content")
        package_digest, package_bytes = hash_regular(
            package, MAX_PACKAGE_BYTES, f"build {label} runtime package"
        )
        log_raw = read_regular(log, MAX_RECEIPT_BYTES, f"build {label} runtime log")
        observation_raw = canonical_json(observation)
        expanded_log = (
            RUNTIME_LOG_PREFIX
            + observation_raw
            + INNER_LOG_PREFIX
            + log_raw
        )
        result_stage = Path(
            tempfile.mkdtemp(prefix=f"dcentos-s19k-result-{label}-", dir=result_parent)
        )
        try:
            incomplete = result_stage / ".dcentos-s19k-result-incomplete"
            write_no_replace(
                incomplete,
                canonical_json(
                    {
                        "schema": "dcentos.s19k-hermetic-result-incomplete/v1",
                        "build_id": request.build_id,
                        "build_root_id": request.build_root_id,
                        "classification": "never-resumable-as-clean",
                    }
                ),
            )
            _fsync_directory(result_stage, strict=strict_durability)
            retained_digest, retained_bytes = copy_no_replace(
                package,
                result_stage / "package.tar",
                MAX_PACKAGE_BYTES,
                f"build {label} package",
            )
            if retained_digest != package_digest or retained_bytes != package_bytes:
                fail(f"build {label} retained package identity changed")
            receipt = {
                "schema": BUILD_ATTESTATION_SCHEMA,
                "build_id": request.build_id,
                "build_root_id": request.build_root_id,
                "clean_build": True,
                "build_cache_reused": False,
                "network_used": False,
                "source_commit": request.source_commit,
                "source_date_epoch": request.source_date_epoch,
                "build_target": BUILD_TARGET,
                "build_arch": BUILD_ARCH,
                "toolchain_id": request.toolchain_id,
                "package_name": f"build-{label}.unsigned.tar",
                "package_sha256": retained_digest,
                "package_bytes": retained_bytes,
            }
            write_no_replace(result_stage / "receipt.json", canonical_json(receipt))
            write_no_replace(result_stage / "build.log", expanded_log)
            owner = {
                "schema": BUILD_RESULT_SCHEMA,
                "build_id": request.build_id,
                "build_root_id": request.build_root_id,
                "builder_image": request.builder_image,
                "toolchain_id": request.toolchain_id,
                "source_commit": request.source_commit,
                "source_date_epoch": request.source_date_epoch,
                "source_snapshot_id": request.source_snapshot_id,
                "dependency_bundle_id": request.dependency_bundle_id,
                "release_input_id": request.release_input_id,
                "runtime_id": observation["runtime_id"],
                "runtime_observation_sha256": sha256_bytes(observation_raw),
                "inner_build_log_sha256": sha256_bytes(log_raw),
                "network_boundary": "oci-network-none-inspected",
                "network_used": False,
                "started_empty": True,
                "source_snapshot_verified_before_after": True,
                "dependency_bundle_verified_before_after": True,
                "result_publication": "opened-regular-file-hash-no-replace-fsync",
                "mutable_roots": [
                    f"{request.build_root_id}:{role}" for role in MUTABLE_ROOT_ROLES
                ],
            }
            write_no_replace(result_stage / "result-owner.json", canonical_json(owner))
            incomplete.unlink()
            _fsync_directory(result_stage, strict=strict_durability)
            _fsync_directory(result_parent, strict=strict_durability)
            return validate_build_result(
                result_stage,
                label,
                source_commit=request.source_commit,
                source_date_epoch=request.source_date_epoch,
                toolchain_id=request.toolchain_id,
            )
        except Exception:
            # The poison sentinel remains on any incomplete stage.  Even after
            # its final removal, only the two-build coordinator can mint the
            # process-local publication capability.
            raise
    except Exception as error:
        _write_build_failure(
            build_root,
            request,
            error,
            strict_durability=strict_durability,
        )
        raise


def execute_two_offline_builds(
    runtime: OfflineBuildRuntime,
    source: SourceAdmission,
    dependency_bundle: DependencyBundle,
    release_inputs: ReleaseInputs,
    build_parent: Path,
    *,
    expected_release_key_sha256: str,
    strict_durability: bool = True,
    source_verifier: Callable[[], None] | None = None,
) -> ExecutedBuildPair:
    """Allocate and execute A/B in nonshared roots, then seal both results."""

    receipt = validate_source_admission_receipt(source.receipt)
    parent = Path(os.path.abspath(os.fspath(build_parent)))
    if strict_durability and os.name != "nt":
        _require_private_ext4_parent(parent, "build parent")
    else:
        _require_directory(parent, "build parent")
    dependency = verify_dependency_bundle(
        dependency_bundle.descriptor,
        expected_source_commit=receipt["source_commit"],
    )
    release = verify_release_inputs(
        release_inputs.descriptor,
        expected_release_key_sha256=expected_release_key_sha256,
    )
    if dependency_bundle.bundle_id != dependency["bundle_id"]:
        fail("dependency bundle handle differs from its verified descriptor")
    if release_inputs.input_id != release["input_id"]:
        fail("release-input handle differs from its verified descriptor")

    def default_source_verifier() -> None:
        _verify_admitted_source_snapshot(source, receipt)

    verify_source = source_verifier or default_source_verifier

    def verify_dependencies() -> None:
        verify_dependency_bundle(
            dependency_bundle.descriptor,
            expected_source_commit=receipt["source_commit"],
            expected_builder_image=dependency["builder_image"],
            expected_toolchain_id=dependency["toolchain_id"],
        )

    def verify_release_input_stage() -> None:
        verify_release_inputs(
            release_inputs.descriptor,
            expected_release_key_sha256=expected_release_key_sha256,
        )

    result_parent = parent / "sealed-results"
    if not result_parent.exists():
        result_parent.mkdir(mode=0o700)
    _require_directory(result_parent, "sealed-result parent")
    allocations = [
        _create_fresh_build_root(parent, label) for label in ("a", "b")
    ]
    if allocations[0][0] == allocations[1][0] or allocations[0][2] == allocations[1][2]:
        fail("A/B build-root allocation reused an identity")
    results: list[ValidatedBuildResult] = []
    for label, allocation in zip(("a", "b"), allocations):
        root, build_id, build_root_id, _, mutable = allocation
        request = BuildRequest(
            label=label,
            build_id=build_id,
            build_root_id=build_root_id,
            builder_image=dependency["builder_image"],
            toolchain_id=dependency["toolchain_id"],
            source_commit=receipt["source_commit"],
            source_date_epoch=receipt["source_date_epoch"],
            source_snapshot=source.snapshot,
            source_tree=source.tree,
            source_snapshot_id=receipt["snapshot_id"],
            dependency_stage=dependency_bundle.stage,
            dependency_bundle_id=dependency["bundle_id"],
            release_input_stage=release_inputs.stage,
            release_input_id=release["input_id"],
            expected_release_key_sha256=expected_release_key_sha256,
            manifest_public_key_hex=release["release_public_key_hex"],
            mutable_paths=mutable,
        )
        results.append(
            _execute_one_build(
                runtime,
                request,
                root,
                result_parent,
                verify_source=verify_source,
                verify_dependencies=verify_dependencies,
                verify_release_input_stage=verify_release_input_stage,
                strict_durability=strict_durability,
            )
        )
    build_roots = (allocations[0][0], allocations[1][0])
    destroy_tokens = (allocations[0][3], allocations[1][3])
    publication_capability = _issue_build_pair_capability(
        results[0], results[1], build_roots
    )
    return ExecutedBuildPair(
        results[0],
        results[1],
        build_roots,
        destroy_tokens,
        publication_capability,
    )


def _linux_openat2_directory(parent_fd: int, name: str) -> int:
    """Open one child directory without crossing links or mount boundaries."""

    if os.name == "nt" or "/" in name or name in ("", ".", ".."):
        fail("descriptor-relative cleanup received an invalid child name")

    class OpenHow(ctypes.Structure):
        _fields_ = [
            ("flags", ctypes.c_uint64),
            ("mode", ctypes.c_uint64),
            ("resolve", ctypes.c_uint64),
        ]

    # openat2 is syscall 437 on the Linux architectures supported by the
    # release host contract (x86_64 and aarch64).  RESOLVE_NO_XDEV also rejects
    # bind mounts even when they share st_dev with their parent filesystem.
    how = OpenHow(
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0,
        0x01 | 0x02 | 0x04 | 0x08,
    )
    libc = ctypes.CDLL(None, use_errno=True)
    descriptor = libc.syscall(
        ctypes.c_long(437),
        ctypes.c_int(parent_fd),
        ctypes.c_char_p(os.fsencode(name)),
        ctypes.byref(how),
        ctypes.c_size_t(ctypes.sizeof(how)),
    )
    if descriptor < 0:
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.EINVAL):
            fail("build cleanup requires Linux openat2 containment support")
        if error == errno.EXDEV:
            fail(f"build cleanup refuses a nested mount boundary: {name}")
        raise OSError(error, os.strerror(error), name)
    return int(descriptor)


def _destroy_linux_tree_at(directory_fd: int, root_device: int) -> None:
    try:
        os.fchmod(directory_fd, 0o700)
    except OSError:
        pass
    for name in sorted(os.listdir(directory_fd), key=os.fsencode):
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            child_fd = _linux_openat2_directory(directory_fd, name)
            try:
                opened = os.fstat(child_fd)
                if (
                    opened.st_dev != root_device
                    or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
                ):
                    fail(f"build cleanup directory changed during traversal: {name}")
                _destroy_linux_tree_at(child_fd, root_device)
                current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                    fail(f"build cleanup directory changed before removal: {name}")
            finally:
                os.close(child_fd)
            os.rmdir(name, dir_fd=directory_fd)
        elif stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
            # unlinkat never follows the final component.  A concurrent swap
            # can at worst remove a different leaf in the already-owned root;
            # it cannot redirect traversal outside that root.
            os.unlink(name, dir_fd=directory_fd)
        else:
            fail(f"build cleanup refuses a special filesystem object: {name}")


def destroy_build_root(
    root: Path, destroy_token: str, *, strict_cleanup: bool = True
) -> None:
    """Remove exactly one capability-owned mutable build root.

    Enumeration never follows links and the root must carry the matching
    owner sentinel.  No glob, parent recursion, or caller-computed broad path
    participates in deletion.
    """

    if not HEX_64.fullmatch(destroy_token):
        fail("build-root destruction token is invalid")
    root = Path(os.path.abspath(os.fspath(root)))
    root_metadata = _require_directory(root, "build cleanup root")
    if not root.name.startswith("dcentos-s19k-build-") or root.parent == root:
        fail("build cleanup target is not an owned S19k build-root pathname")
    owner = load_canonical_json(
        root / ".dcentos-s19k-build-owner", 4096, "build-root owner"
    )
    owner = _exact_object(
        owner,
        (
            "schema",
            "build_id",
            "build_root_id",
            "runtime_container_name",
            "destroy_token_sha256",
            "classification",
            "mutable_roots",
        ),
        "build-root owner",
    )
    if (
        owner["schema"] != BUILD_OWNER_SCHEMA
        or not isinstance(owner["build_id"], str)
        or not TOKEN.fullmatch(owner["build_id"])
        or not isinstance(owner["build_root_id"], str)
        or not TOKEN.fullmatch(owner["build_root_id"])
        or owner["runtime_container_name"] != f"dcentos-{owner['build_id']}"
        or owner["classification"] != "mutable-root-never-clean-evidence"
        or owner["mutable_roots"]
        != [f"{owner['build_root_id']}:{role}" for role in MUTABLE_ROOT_ROLES]
        or not HEX_64.fullmatch(owner["destroy_token_sha256"])
    ):
        fail("build-root owner sentinel is invalid")
    if not secrets.compare_digest(
        owner["destroy_token_sha256"], sha256_bytes(destroy_token.encode("ascii"))
    ):
        fail("build-root destruction token does not own this root")

    if os.name != "nt":
        if os.path.ismount(root):
            fail("build cleanup refuses a build root that is itself a mount point")
        parent_fd = os.open(
            root.parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        root_fd: int | None = None
        try:
            root_fd = _linux_openat2_directory(parent_fd, root.name)
            opened = os.fstat(root_fd)
            if (opened.st_dev, opened.st_ino) != (
                root_metadata.st_dev,
                root_metadata.st_ino,
            ):
                fail("build cleanup root changed after authority validation")
            sentinel_fd = os.open(
                ".dcentos-s19k-build-owner",
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=root_fd,
            )
            try:
                sentinel_metadata = os.fstat(sentinel_fd)
                if not stat.S_ISREG(sentinel_metadata.st_mode) or sentinel_metadata.st_size > 4096:
                    fail("build cleanup owner changed type or size")
                retained = bytearray()
                while len(retained) <= 4096:
                    chunk = os.read(sentinel_fd, min(4097 - len(retained), 4096))
                    if not chunk:
                        break
                    retained.extend(chunk)
                if bytes(retained) != canonical_json(owner):
                    fail("build cleanup owner changed after authority validation")
            finally:
                os.close(sentinel_fd)
            _destroy_linux_tree_at(root_fd, opened.st_dev)
            current = os.stat(root.name, dir_fd=parent_fd, follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                fail("build cleanup root changed before final removal")
            os.rmdir(root.name, dir_fd=parent_fd)
        finally:
            if root_fd is not None:
                os.close(root_fd)
            os.close(parent_fd)
        return

    if strict_cleanup:
        fail("production build-root cleanup requires Linux openat2 containment")

    # Portable fallback exists only for workstation tests.  Production CLI
    # never selects it and Windows reparse points remain fail-closed.
    files: list[Path] = []
    directories: list[Path] = []

    def visit(directory: Path) -> None:
        with os.scandir(directory) as iterator:
            entries = sorted(iterator, key=lambda item: os.fsencode(item.name))
        for entry in entries:
            path = Path(entry.path)
            metadata = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(metadata.st_mode):
                files.append(path)
            elif _is_reparse(metadata):
                fail(f"build cleanup refuses a non-symlink reparse point: {path}")
            elif stat.S_ISDIR(metadata.st_mode):
                directories.append(path)
                visit(path)
            elif stat.S_ISREG(metadata.st_mode):
                files.append(path)
            else:
                fail(f"build cleanup refuses a special filesystem object: {path}")

    visit(root)
    sentinel = root / ".dcentos-s19k-build-owner"
    if sentinel not in files:
        fail("build cleanup enumeration lost its owner sentinel")
    for path in sorted(files, key=lambda value: len(value.parts), reverse=True):
        metadata = os.lstat(path)
        if not stat.S_ISLNK(metadata.st_mode):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        path.unlink()
    for path in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
        path.rmdir()
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    root.rmdir()


class DockerOfflineBuildRuntime:
    """OCI runtime adapter with a host-inspected ``--network none`` boundary."""

    SOURCE_MOUNTS = {
        "/dcent/source-snapshot": "source_snapshot",
        "/dcent/dependencies": "dependency_stage",
        "/dcent/release-inputs": "release_input_stage",
    }
    MUTABLE_MOUNTS = {
        "source-exec": "/dcent/work/source",
        "cargo-home": "/dcent/work/cargo-home",
        "cargo-target": "/dcent/work/cargo-target",
        "buildroot-output": "/dcent/work/buildroot-output",
        "tmp": "/dcent/work/tmp",
        "dashboard": "/dcent/work/dashboard",
        "result": "/dcent/work/result",
        "logs": "/dcent/work/logs",
    }
    WORKING_DIRECTORY = "/dcent"
    HOSTNAME = "dcent-s19k-build"
    DOMAINNAME = "hermetic.invalid"
    DRIVER = (
        "/dcent/source-snapshot/tree/DCENT_OS_Antminer/scripts/"
        "s19k_hermetic_build_inner.sh"
    )

    @staticmethod
    def _build_environment(request: BuildRequest) -> dict[str, str]:
        return {
            "PATH": (
                "/usr/local/cargo/bin:/opt/zig:/usr/local/sbin:/usr/local/bin:"
                "/usr/sbin:/usr/bin:/sbin:/bin"
            ),
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": "/dcent/work/cargo-home",
            "CARGO_HOME": "/dcent/work/cargo-home",
            "CARGO_TARGET_DIR": "/dcent/work/cargo-target",
            "RUSTUP_HOME": "/usr/local/rustup",
            "RUST_VERSION": "1.90.0",
            "TMPDIR": "/dcent/work/tmp",
            "BASH_ENV": "/dev/null",
            "ENV": "/dev/null",
            "PYTHONHOME": "",
            "PYTHONPATH": "/nonexistent",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "NODE_OPTIONS": "",
            "NPM_CONFIG_USERCONFIG": "/dev/null",
            "RUSTC_WRAPPER": "",
            "RUSTFLAGS": "",
            "CARGO_ENCODED_RUSTFLAGS": "",
            "MAKEFLAGS": "",
            "MFLAGS": "",
            "LD_PRELOAD": "",
            "LD_LIBRARY_PATH": "",
            "SOURCE_DATE_EPOCH": str(request.source_date_epoch),
            "DCENT_SOURCE_COMMIT": request.source_commit,
            "DCENT_SOURCE_COMMIT_EPOCH": str(request.source_date_epoch),
            "DCENT_SOURCE_TREE_STATE": "exact_git_object_snapshot",
            "DCENT_BUILD_TARGET": BUILD_TARGET,
            "DCENT_BUILD_ARCH": BUILD_ARCH,
            "DCENT_TOOLCHAIN_ID": request.toolchain_id,
            "DCENT_RELEASE_CAPSULE_MODE": "1",
            "DCENT_CAPSULE_PROVENANCE_VERIFIED": "1",
            "DCENT_PROVENANCE_SOURCE_SNAPSHOT": "/dcent/source-snapshot/snapshot.json",
            "DCENT_PROVENANCE_HELPER": (
                "/dcent/work/source/DCENT_OS_Antminer/scripts/source_snapshot.py"
            ),
            "DCENT_S19K_UNSIGNED_INTERMEDIATE": "1",
            "DCENT_RELEASE_PUBKEY_FILE": (
                "/dcent/release-inputs/trusted-release-key.pem"
            ),
            "DCENT_MANIFEST_PUBLIC_KEY_HEX": request.manifest_public_key_hex,
            "DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256": (
                request.expected_release_key_sha256
            ),
            "DCENT_S19K_NATIVE_OWNER_RECEIPT": (
                "/dcent/release-inputs/native-owner-verification.json"
            ),
            "DCENT_S19K_STOCK_RECOVERY_RECEIPT": (
                "/dcent/release-inputs/stock-recovery-verification.json"
            ),
            "DCENT_HERMETIC_BUILD_ID": request.build_id,
            "DCENT_HERMETIC_BUILD_ROOT_ID": request.build_root_id,
            "DCENT_HERMETIC_BUILDER_IMAGE": request.builder_image,
            "DCENT_HERMETIC_DEPENDENCY_BUNDLE_ID": request.dependency_bundle_id,
            "DCENT_HERMETIC_RELEASE_INPUT_ID": request.release_input_id,
            "DCENT_HERMETIC_EXPECTED_PACKAGE": (
                f"/dcent/work/result/{INNER_PACKAGE_NAME}"
            ),
        }

    @staticmethod
    def _config_environment(config: Mapping[str, Any]) -> dict[str, str]:
        raw_environment = config.get("Env")
        if not isinstance(raw_environment, list):
            fail("Docker inspect lacks the container environment")
        parsed: dict[str, str] = {}
        for raw in raw_environment:
            if not isinstance(raw, str) or "=" not in raw:
                fail("Docker inspect contains a malformed environment entry")
            name, value = raw.split("=", 1)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name in parsed:
                fail("Docker inspect contains an ambiguous environment entry")
            parsed[name] = value
        return parsed

    def __init__(
        self,
        docker_binary: str = "docker",
        *,
        timeout_seconds: int = 8 * 60 * 60,
        docker_identity: Mapping[str, Any] | None = None,
    ):
        if os.name == "nt":
            fail("hermetic Docker builds must execute inside Linux/WSL")
        if not docker_binary or any(character in docker_binary for character in "\0\r\n"):
            fail("Docker binary name is unsafe")
        self.docker_binary = docker_binary
        self.docker_identity = dict(docker_identity) if docker_identity is not None else None
        self.timeout_seconds = timeout_seconds
        uid = os.getuid()
        gid = os.getgid()
        if uid < 1000 or gid < 1000:
            fail("hermetic Docker execution requires host UID/GID >=1000")
        self.container_user = f"{uid}:{gid}"

    def _verify_preflight_docker_identity(self) -> None:
        identity = getattr(self, "docker_identity", None)
        if identity is None:
            return
        if set(identity) != {"path", "sha256", "bytes"}:
            fail("preflight Docker client identity has an invalid key set")
        binary = Path(os.path.abspath(os.fspath(self.docker_binary)))
        if os.fspath(binary) != identity["path"]:
            fail("runtime Docker client path differs from host preflight")
        digest, size = hash_regular(binary, MAX_PACKAGE_BYTES, "preflight Docker client")
        if digest != identity["sha256"] or size != identity["bytes"]:
            fail("runtime Docker client bytes differ from host preflight")

    def _run(
        self,
        arguments: Sequence[str],
        *,
        timeout: int = 120,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        completed = subprocess.run(
            (self.docker_binary, *arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
            env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
        )
        if check and completed.returncode:
            detail = completed.stderr.decode("utf-8", "replace").strip().splitlines()
            fail(
                f"Docker runtime failed ({' '.join(arguments[:3])}): "
                + (detail[0] if detail else f"exit {completed.returncode}")
            )
        return completed

    @staticmethod
    def _mount_argument(source: Path, destination: str, *, readonly: bool) -> str:
        absolute = os.fspath(Path(os.path.abspath(os.fspath(source))))
        if any(character in absolute for character in "\0\r\n,"):
            fail(f"Docker mount source is unsafe: {absolute!r}")
        suffix = ",readonly" if readonly else ""
        return f"type=bind,source={absolute},target={destination}{suffix}"

    def _inspect(self, container: str) -> dict[str, Any]:
        raw = self._run(("inspect", container)).stdout
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"Docker inspect returned invalid JSON: {error}")
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            fail("Docker inspect did not return exactly one container")
        return value[0]

    def _stop_and_verify_container(self, container: str) -> None:
        """Stop a retained container and prove it is no longer executing."""

        try:
            self._run(("kill", container), timeout=60, check=False)
        except BaseException:
            # A timed-out kill still may have reached the daemon.  The only
            # acceptable outcome is proven stopped state or proven absence.
            pass
        try:
            inspected = self._inspect(container)
        except BaseException as error:
            try:
                listed = self._run(
                    (
                        "container",
                        "ls",
                        "--all",
                        "--no-trunc",
                        "--filter",
                        f"id={container}",
                        "--format",
                        "{{.ID}}",
                    ),
                    timeout=60,
                ).stdout.decode("utf-8", "strict")
            except BaseException as absence_error:
                raise ProducerError(
                    f"unable to prove retained Docker container {container} stopped"
                ) from absence_error
            observed_ids = listed.splitlines()
            if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in observed_ids):
                raise ProducerError(
                    f"unable to prove retained Docker container {container} stopped"
                ) from error
            if observed_ids:
                raise ProducerError(
                    f"unable to prove retained Docker container {container} stopped"
                ) from error
            return
        state = inspected.get("State")
        if not isinstance(state, dict) or state.get("Running") is not False:
            fail(f"unable to prove retained Docker container {container} stopped")

    def _run_attached_to_new_log(self, container: str, log_path: Path) -> int:
        """Stream bounded container output to one no-replace, fsynced log."""

        if log_path.exists() or log_path.is_symlink():
            fail(f"refusing to replace existing output: {log_path}")
        descriptor = os.open(
            log_path,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        process: subprocess.Popen[bytes] | None = None
        selector = selectors.DefaultSelector()
        total = 0
        deadline = time.monotonic() + self.timeout_seconds
        try:
            header = b"[container-output-stdout-stderr-merged]\n"
            os.write(descriptor, header)
            total += len(header)
            process = subprocess.Popen(
                (self.docker_binary, "start", "--attach", container),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env={"PATH": os.environ.get("PATH", ""), "LC_ALL": "C"},
                bufsize=0,
            )
            if process.stdout is None:
                fail("Docker attach did not provide an output stream")
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    process.kill()
                    self._run(("kill", container), check=False)
                    fail("offline Docker build exceeded its bounded runtime")
                events = selector.select(min(1.0, remaining))
                if not events:
                    if process.poll() is not None:
                        chunk = os.read(process.stdout.fileno(), 1024 * 1024)
                        if not chunk:
                            break
                    else:
                        continue
                else:
                    chunk = os.read(process.stdout.fileno(), 1024 * 1024)
                    if not chunk:
                        if process.poll() is not None:
                            break
                        continue
                if total + len(chunk) > MAX_RECEIPT_BYTES:
                    process.kill()
                    self._run(("kill", container), check=False)
                    fail("offline Docker build log exceeded its bounded size")
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        fail("short write while retaining Docker build log")
                    view = view[written:]
                total += len(chunk)
            return_code = process.wait(timeout=30)
            os.fsync(descriptor)
            return return_code
        finally:
            selector.close()
            if process is not None:
                if process.stdout is not None:
                    process.stdout.close()
                if process.poll() is None:
                    process.kill()
                    try:
                        process.wait(timeout=30)
                    except subprocess.TimeoutExpired:
                        pass
            os.close(descriptor)

    def _verify_image(
        self, builder_image: str, builder_policy: Mapping[str, Any]
    ) -> str:
        raw = self._run(("image", "inspect", builder_image)).stdout
        try:
            values = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"Docker image inspection returned invalid JSON: {error}")
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            fail("Docker image inspection did not return one exact image")
        inspected = values[0]
        repo_digests = inspected.get("RepoDigests")
        descriptor = inspected.get("Descriptor")
        config = inspected.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        admitted_ids = {
            builder_policy.get("oci_index_digest"),
            builder_policy.get("oci_config_digest"),
        }
        descriptor_valid = descriptor in (None, {}) or (
            isinstance(descriptor, dict)
            and (
                (
                    descriptor.get("mediaType")
                    == "application/vnd.oci.image.index.v1+json"
                    and descriptor.get("digest") == builder_policy.get("oci_index_digest")
                )
                or (
                    descriptor.get("mediaType")
                    == "application/vnd.oci.image.manifest.v1+json"
                    and descriptor.get("digest")
                    == builder_policy.get("linux_amd64_manifest_digest")
                )
            )
        )
        if (
            not isinstance(repo_digests, list)
            or builder_image not in repo_digests
            or builder_image != builder_policy.get("image")
            or inspected.get("Id") not in admitted_ids
            or inspected.get("Os") != "linux"
            or inspected.get("Architecture") != "amd64"
            or not descriptor_valid
            or not isinstance(labels, dict)
            or labels.get("org.dcentral.dcentos.authority")
            != "build-only-no-release-install-or-flash-authority"
            or labels.get("org.dcentral.dcentos.rust-target")
            != builder_policy.get("versions", {}).get("rust_target")
            or labels.get("org.dcentral.dcentos.zig-version")
            != builder_policy.get("versions", {}).get("zig")
        ):
            fail("local builder image differs from its authenticated OCI policy")
        return str(inspected["Id"])

    def _verify_container_boundary(
        self,
        inspected: Mapping[str, Any],
        request: BuildRequest,
        admitted_image_id: str | None = None,
    ) -> None:
        config = inspected.get("Config")
        host = inspected.get("HostConfig")
        mounts = inspected.get("Mounts")
        networks = (inspected.get("NetworkSettings") or {}).get("Networks")
        if not isinstance(config, dict) or not isinstance(host, dict) or not isinstance(
            mounts, list
        ) or not isinstance(networks, dict):
            fail("Docker inspect lacks Config/HostConfig/Mounts/network evidence")
        security = host.get("SecurityOpt") or []
        cap_drop = host.get("CapDrop") or []
        restart = host.get("RestartPolicy") or {}
        log_config = host.get("LogConfig") or {}
        if (
            inspected.get("Image")
            != (admitted_image_id or request.builder_image.rsplit("@", 1)[1])
            or
            config.get("Image") != request.builder_image
            or config.get("User") != self.container_user
            or config.get("WorkingDir") != self.WORKING_DIRECTORY
            or config.get("Hostname") != self.HOSTNAME
            or config.get("Domainname") != self.DOMAINNAME
            or config.get("Entrypoint") != ["/bin/sh"]
            or config.get("Cmd") != [self.DRIVER]
            or config.get("OpenStdin") is not False
            or config.get("Tty") is not False
            or host.get("NetworkMode") != "none"
            or set(networks) != {"none"}
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapAdd") not in (None, [])
            or "ALL" not in cap_drop
            or not any(str(value).startswith("no-new-privileges") for value in security)
            or host.get("Devices") not in (None, [])
            or host.get("PidsLimit") != 8192
            or host.get("PublishAllPorts") is not False
            or host.get("PortBindings") not in (None, {})
            or host.get("Links") not in (None, [])
            or host.get("ExtraHosts") not in (None, [])
            or host.get("VolumesFrom") not in (None, [])
            or host.get("IpcMode") != "none"
            or host.get("PidMode") not in (None, "", "private")
            or host.get("UTSMode") not in (None, "", "private")
            or restart.get("Name") not in (None, "", "no")
            or log_config.get("Type") != "none"
        ):
            fail("Docker inspect does not prove the required offline least-privilege boundary")
        if self._config_environment(config) != self._build_environment(request):
            fail("Docker build environment is not the exact reviewed environment")
        expected_sources: dict[str, tuple[Path, bool]] = {
            "/dcent/source-snapshot": (request.source_snapshot.parent, False),
            "/dcent/dependencies": (request.dependency_stage, False),
            "/dcent/release-inputs": (request.release_input_stage, False),
        }
        for role, destination in self.MUTABLE_MOUNTS.items():
            expected_sources[destination] = (request.mutable_paths[role], True)
        observed_destinations: dict[str, bool] = {}
        run_tmpfs_seen = False
        for item in mounts:
            if not isinstance(item, dict):
                fail("Docker build container contains a malformed mount")
            destination = item.get("Destination")
            mount_type = item.get("Type")
            if mount_type == "tmpfs" and destination == "/run":
                if run_tmpfs_seen or item.get("RW") is not True:
                    fail("Docker build container has an invalid /run tmpfs")
                run_tmpfs_seen = True
                continue
            if mount_type != "bind" or destination not in expected_sources:
                fail("Docker build container contains an unapproved mount type")
            if destination in observed_destinations:
                fail(f"Docker build container repeats mount destination {destination!r}")
            expected_source, expected_rw = expected_sources[destination]
            source = item.get("Source")
            if (
                not isinstance(source, str)
                or not os.path.isabs(source)
                or item.get("Propagation") != "rprivate"
                or item.get("RW") is not expected_rw
            ):
                fail(f"Docker bind mount metadata is invalid for {destination}")
            try:
                if not os.path.samefile(source, expected_source):
                    fail(f"Docker bind mount source is substituted for {destination}")
            except OSError:
                fail(f"Docker bind mount source cannot be identified for {destination}")
            observed_destinations[destination] = expected_rw
        expected_destinations = {
            destination: writable
            for destination, (_, writable) in expected_sources.items()
        }
        if observed_destinations != expected_destinations:
            fail("Docker build container mount set or read/write policy is not exact")
        tmpfs = host.get("Tmpfs")
        if not isinstance(tmpfs, dict) or set(tmpfs) != {"/run"}:
            fail("Docker build container tmpfs set is not exact")
        options = tmpfs["/run"]
        if not isinstance(options, str) or set(options.split(",")) != {
            "rw",
            "noexec",
            "nosuid",
            "nodev",
            "size=16777216",
        }:
            fail("Docker build container /run tmpfs policy is invalid")

    def execute(self, request: BuildRequest) -> Mapping[str, Any]:
        self._verify_preflight_docker_identity()
        if not IMMUTABLE_IMAGE.fullmatch(request.builder_image):
            fail("build request builder image is not digest-pinned")
        policy, _ = load_dependency_policy(request.dependency_stage / "policy.json")
        if (
            request.builder_image != policy["builder"]["image"]
            or request.toolchain_id != policy["builder"]["toolchain_id"]
        ):
            fail("offline build request differs from authenticated builder policy")
        admitted_image_id = self._verify_image(request.builder_image, policy["builder"])
        runtime_name = f"dcentos-{request.build_id}"
        command: list[str] = [
            "create",
            "--pull=never",
            "--name",
            runtime_name,
            "--hostname",
            self.HOSTNAME,
            "--domainname",
            self.DOMAINNAME,
            "--network",
            "none",
            "--read-only",
            "--user",
            self.container_user,
            "--workdir",
            self.WORKING_DIRECTORY,
            "--privileged=false",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "8192",
            "--ipc",
            "none",
            "--publish-all=false",
            "--restart",
            "no",
            "--log-driver",
            "none",
            "--entrypoint",
            "/bin/sh",
            "--tmpfs",
            "/run:rw,noexec,nosuid,nodev,size=16777216",
        ]
        readonly_sources = {
            "/dcent/source-snapshot": request.source_snapshot.parent,
            "/dcent/dependencies": request.dependency_stage,
            "/dcent/release-inputs": request.release_input_stage,
        }
        for destination, source in readonly_sources.items():
            command.extend(
                ("--mount", self._mount_argument(source, destination, readonly=True))
            )
        for role, destination in self.MUTABLE_MOUNTS.items():
            command.extend(
                (
                    "--mount",
                    self._mount_argument(request.mutable_paths[role], destination, readonly=False),
                )
            )
        environment = self._build_environment(request)
        for name, value in sorted(environment.items()):
            if any(character in value for character in "\0\r\n"):
                fail(f"build environment {name} is unsafe")
            command.extend(("--env", f"{name}={value}"))
        command.extend((request.builder_image, self.DRIVER))
        created: str | None = None
        try:
            created_value = self._run(command).stdout.decode("ascii", "strict").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", created_value):
                fail("Docker create did not return one full container ID")
            created = created_value
            inspected_before = self._inspect(created)
            self._verify_container_boundary(inspected_before, request, admitted_image_id)
            attach_exit_code = self._run_attached_to_new_log(
                created, request.mutable_paths["logs"] / "build.log"
            )
            inspected_after = self._inspect(created)
            self._verify_container_boundary(inspected_after, request, admitted_image_id)
            state = inspected_after.get("State")
            if (
                not isinstance(state, dict)
                or state.get("Running") is not False
                or state.get("OOMKilled") is not False
                or state.get("ExitCode") != 0
                or attach_exit_code != 0
            ):
                fail(
                    f"offline build {request.label} failed; container {created} and owned root retained"
                )
        except BaseException:
            # A failed `docker create --name ...` may mean that an unrelated
            # container already owns the unpredictable name. Never resolve or
            # signal by name: cleanup authority begins only after this
            # invocation receives one canonical container ID from create.
            if created is None:
                raise
            try:
                self._stop_and_verify_container(created)
            except BaseException as stop_error:
                raise ProducerError(
                    "offline build failed and container stop could not be proven: "
                    f"{created}"
                ) from stop_error
            raise
        self._run(("rm", created))
        return {
            "schema": RUNTIME_OBSERVATION_SCHEMA,
            "runtime_id": created,
            "build_id": request.build_id,
            "build_root_id": request.build_root_id,
            "builder_image": request.builder_image,
            "source_snapshot_id": request.source_snapshot_id,
            "dependency_bundle_id": request.dependency_bundle_id,
            "release_input_id": request.release_input_id,
            "network_mode": "none",
            "network_boundary_inspected": True,
            "read_only_rootfs": True,
            "privileged": False,
            "build_cache_reused": False,
            "exit_code": 0,
            "package_relative_path": f"result/{INNER_PACKAGE_NAME}",
            "build_log_relative_path": "logs/build.log",
        }


class DockerIsolatedSignerRuntime(DockerOfflineBuildRuntime):
    """Separately inspected network-none runtime with the sole private-key mount."""

    HOSTNAME = "dcent-s19k-signer"
    DOMAINNAME = "signer.invalid"
    WORKING_DIRECTORY = "/dcent"
    SIGNER = (
        "/dcent/source-snapshot/tree/DCENT_OS_Antminer/scripts/"
        "s19k_hermetic_release_signer.py"
    )
    VERIFIER = (
        "/dcent/source-snapshot/tree/DCENT_OS_Antminer/scripts/"
        "s19k_persistent_image_verify.py"
    )

    @staticmethod
    def _environment() -> dict[str, str]:
        return {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": "/run",
            "TMPDIR": "/run",
            "BASH_ENV": "/dev/null",
            "ENV": "/dev/null",
            "PYTHONHOME": "",
            "PYTHONPATH": "/nonexistent",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "LD_PRELOAD": "",
            "LD_LIBRARY_PATH": "",
        }

    @classmethod
    def _command(cls, request: IsolatedSignerRequest) -> list[str]:
        return [
            cls.SIGNER,
            "--build-a",
            "/dcent/public/build-a.unsigned.tar",
            "--build-b",
            "/dcent/public/build-b.unsigned.tar",
            "--build-a-receipt",
            "/dcent/public/build-a.json",
            "--build-b-receipt",
            "/dcent/public/build-b.json",
            "--public-key",
            "/dcent/public/trusted-release-key.pem",
            "--native-owner-receipt",
            "/dcent/public/native-owner-verification.json",
            "--stock-recovery-receipt",
            "/dcent/public/stock-recovery-verification.json",
            "--private-key",
            "/dcent/private/release.pem",
            "--output-stage",
            "/dcent/output/signed",
            "--expected-release-key-sha256",
            request.expected_release_key_sha256,
            "--verifier",
            cls.VERIFIER,
        ]

    def _verify_signer_boundary(
        self,
        inspected: Mapping[str, Any],
        request: IsolatedSignerRequest,
        admitted_image_id: str,
    ) -> None:
        config = inspected.get("Config")
        host = inspected.get("HostConfig")
        mounts = inspected.get("Mounts")
        networks = (inspected.get("NetworkSettings") or {}).get("Networks")
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(mounts, list)
            or not isinstance(networks, dict)
        ):
            fail("Docker signer inspect lacks exact boundary evidence")
        security = host.get("SecurityOpt") or []
        restart = host.get("RestartPolicy") or {}
        log_config = host.get("LogConfig") or {}
        if (
            inspected.get("Image") != admitted_image_id
            or config.get("Image") != request.builder_image
            or config.get("User") != self.container_user
            or config.get("WorkingDir") != self.WORKING_DIRECTORY
            or config.get("Hostname") != self.HOSTNAME
            or config.get("Domainname") != self.DOMAINNAME
            or config.get("Entrypoint") != ["/usr/bin/python3"]
            or config.get("Cmd") != self._command(request)
            or config.get("OpenStdin") is not False
            or config.get("Tty") is not False
            or self._config_environment(config) != self._environment()
            or host.get("NetworkMode") != "none"
            or set(networks) != {"none"}
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapAdd") not in (None, [])
            or "ALL" not in (host.get("CapDrop") or [])
            or not any(str(value).startswith("no-new-privileges") for value in security)
            or host.get("Devices") not in (None, [])
            or host.get("PidsLimit") != 256
            or host.get("PublishAllPorts") is not False
            or host.get("PortBindings") not in (None, {})
            or host.get("Links") not in (None, [])
            or host.get("ExtraHosts") not in (None, [])
            or host.get("VolumesFrom") not in (None, [])
            or host.get("IpcMode") != "none"
            or host.get("PidMode") not in (None, "", "private")
            or host.get("UTSMode") not in (None, "", "private")
            or restart.get("Name") not in (None, "", "no")
            or log_config.get("Type") != "none"
        ):
            fail("Docker inspect does not prove the isolated signer boundary")
        expected = {
            "/dcent/source-snapshot": (request.source_stage, False),
            "/dcent/public": (request.public_stage, False),
            "/dcent/private/release.pem": (request.private_key, False),
            "/dcent/output": (request.output_parent, True),
        }
        observed: dict[str, bool] = {}
        run_seen = False
        for item in mounts:
            if not isinstance(item, dict):
                fail("Docker signer contains malformed mount evidence")
            destination = item.get("Destination")
            if item.get("Type") == "tmpfs" and destination == "/run":
                if run_seen or item.get("RW") is not True:
                    fail("Docker signer /run tmpfs is invalid")
                run_seen = True
                continue
            if item.get("Type") != "bind" or destination not in expected:
                fail("Docker signer contains an unapproved mount")
            source, writable = expected[destination]
            if (
                destination in observed
                or item.get("RW") is not writable
                or item.get("Propagation") != "rprivate"
                or not isinstance(item.get("Source"), str)
            ):
                fail("Docker signer bind metadata is invalid")
            try:
                if not os.path.samefile(item["Source"], source):
                    fail("Docker signer bind source was substituted")
            except OSError:
                fail("Docker signer bind source cannot be reidentified")
            observed[destination] = writable
        if observed != {destination: writable for destination, (_, writable) in expected.items()}:
            fail("Docker signer mount ledger is not exact")
        tmpfs = host.get("Tmpfs")
        if not isinstance(tmpfs, dict) or tmpfs != {
            "/run": "rw,noexec,nosuid,nodev,size=16777216"
        }:
            fail("Docker signer tmpfs policy is not exact")

    def execute(self, request: IsolatedSignerRequest) -> Mapping[str, Any]:
        self._verify_preflight_docker_identity()
        if _admit_private_signing_key_path(request.private_key) != dict(
            request.private_key_custody
        ):
            fail("private signing-key custody changed before isolated runtime")
        policy, _ = load_dependency_policy(request.dependency_stage / "policy.json")
        if request.builder_image != policy["builder"]["image"]:
            fail("isolated signer image differs from authenticated builder policy")
        admitted_image_id = self._verify_image(request.builder_image, policy["builder"])
        runtime_name = f"dcentos-{request.signing_id}"
        command = [
            "create",
            "--pull=never",
            "--name",
            runtime_name,
            "--hostname",
            self.HOSTNAME,
            "--domainname",
            self.DOMAINNAME,
            "--network",
            "none",
            "--read-only",
            "--user",
            self.container_user,
            "--workdir",
            self.WORKING_DIRECTORY,
            "--privileged=false",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "256",
            "--ipc",
            "none",
            "--publish-all=false",
            "--restart",
            "no",
            "--log-driver",
            "none",
            "--entrypoint",
            "/usr/bin/python3",
            "--tmpfs",
            "/run:rw,noexec,nosuid,nodev,size=16777216",
        ]
        for destination, source, readonly in (
            ("/dcent/source-snapshot", request.source_stage, True),
            ("/dcent/public", request.public_stage, True),
            ("/dcent/private/release.pem", request.private_key, True),
            ("/dcent/output", request.output_parent, False),
        ):
            command.extend(("--mount", self._mount_argument(source, destination, readonly=readonly)))
        for name, value in sorted(self._environment().items()):
            command.extend(("--env", f"{name}={value}"))
        command.extend((request.builder_image, *self._command(request)))
        created: str | None = None
        try:
            created_value = self._run(command).stdout.decode("ascii", "strict").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", created_value):
                fail("Docker signer create did not return one full container ID")
            created = created_value
            before = self._inspect(created)
            before_raw = canonical_json(before)
            write_no_replace(request.inspect_before_path, before_raw)
            self._verify_signer_boundary(before, request, admitted_image_id)
            exit_code = self._run_attached_to_new_log(created, request.log_path)
            after = self._inspect(created)
            after_raw = canonical_json(after)
            write_no_replace(request.inspect_after_path, after_raw)
            self._verify_signer_boundary(after, request, admitted_image_id)
            state = after.get("State")
            if (
                not isinstance(state, dict)
                or state.get("Running") is not False
                or state.get("OOMKilled") is not False
                or state.get("ExitCode") != 0
                or exit_code != 0
            ):
                fail(f"isolated signer failed; container {created} retained")
        except BaseException:
            if created is None:
                raise
            try:
                self._stop_and_verify_container(created)
            except BaseException as stop_error:
                raise ProducerError(
                    "isolated signer failed and stopped state could not be proven"
                ) from stop_error
            raise
        self._run(("rm", created))
        output = request.output_parent / "signed"
        files, directories = _walk_regular_tree(output, "isolated signer output")
        if files != ["dcentos-sysupgrade-am3-s19kpro.tar", "signing-receipt.json"] or directories:
            fail("isolated signer output ledger is not exact")
        package = output / "dcentos-sysupgrade-am3-s19kpro.tar"
        receipt = output / "signing-receipt.json"
        package_sha256, package_bytes = hash_regular(
            package, MAX_PACKAGE_BYTES, "isolated signed package"
        )
        receipt_sha256, receipt_bytes = hash_regular(
            receipt, MAX_JSON_BYTES, "isolated signing receipt"
        )
        log_sha256, log_bytes = hash_regular(
            request.log_path, MAX_RECEIPT_BYTES, "isolated signer log"
        )
        return {
            "schema": SIGNER_RUNTIME_SCHEMA,
            "runtime_id": created,
            "signing_id": request.signing_id,
            "builder_image": request.builder_image,
            "network_mode": "none",
            "network_boundary_inspected_before_after": True,
            "read_only_rootfs": True,
            "privileged": False,
            "private_key_custody_id": request.private_key_custody["custody_id"],
            "host_preflight_id": request.host_preflight_id,
            "verifier_sha256": request.verifier_sha256,
            "signer_sha256": request.signer_sha256,
            "inspect_before_sha256": sha256_bytes(before_raw),
            "inspect_after_sha256": sha256_bytes(after_raw),
            "log_sha256": log_sha256,
            "log_bytes": log_bytes,
            "signed_package_sha256": package_sha256,
            "signed_package_bytes": package_bytes,
            "signing_receipt_sha256": receipt_sha256,
            "signing_receipt_bytes": receipt_bytes,
            "container_removed_after_stop_proof": True,
            "install_authority_granted": False,
            "flash_authority_granted": False,
            "mutation_authority_granted": False,
        }


class DockerDependencyMaterializer(DockerOfflineBuildRuntime):
    """OCI adapter for the one permitted network-enabled source-fetch phase."""

    READ_ONLY_MOUNTS = {
        "/dcent/source-snapshot": "source_snapshot_parent",
        "/dcent/held/vmlinux.bin": "amlogic_kernel",
        "/dcent/held/devicetree.dtb": "amlogic_dtb",
        "/dcent/held/fw-info": "amlogic_fw_info",
    }
    INVOCATION_DESTINATION = "/dcent/materializer"
    HOSTNAME = "dcent-s19k-fetch"
    DOMAINNAME = "materializer.invalid"
    DRIVER = (
        "/dcent/source-snapshot/tree/DCENT_OS_Antminer/scripts/"
        "s19k_hermetic_materialize_inner.sh"
    )

    def __init__(
        self,
        docker_binary: str = "docker",
        *,
        timeout_seconds: int = 8 * 60 * 60,
        docker_identity: Mapping[str, Any] | None = None,
    ) -> None:
        super().__init__(
            docker_binary,
            timeout_seconds=timeout_seconds,
            docker_identity=docker_identity,
        )

    @staticmethod
    def _materializer_environment(request: MaterializerRequest) -> dict[str, str]:
        return {
            "PATH": (
                "/usr/local/cargo/bin:/opt/zig:/usr/local/sbin:/usr/local/bin:"
                "/usr/sbin:/usr/bin:/sbin:/bin"
            ),
            "TZ": "UTC",
            "LC_ALL": "C",
            "LANG": "C",
            "HOME": "/dcent/materializer/work/git-home",
            "TMPDIR": "/dcent/materializer/work/tmp",
            "CARGO_HOME": "/usr/local/cargo",
            "RUSTUP_HOME": "/usr/local/rustup",
            "RUST_VERSION": "1.90.0",
            "BASH_ENV": "/dev/null",
            "ENV": "/dev/null",
            "PYTHONHOME": "",
            "PYTHONPATH": "/nonexistent",
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            "NODE_OPTIONS": "",
            "RUSTC_WRAPPER": "",
            "RUSTFLAGS": "",
            "MAKEFLAGS": "",
            "DCENT_MATERIALIZER_SOURCE_STAGE": "/dcent/source-snapshot",
            "DCENT_MATERIALIZER_SOURCE_COMMIT": request.source_commit,
            "DCENT_MATERIALIZER_BUILDER_IMAGE": request.builder_image,
            "DCENT_MATERIALIZER_TOOLCHAIN_ID": request.toolchain_id,
            "DCENT_MATERIALIZER_AMLOGIC_KERNEL": "/dcent/held/vmlinux.bin",
            "DCENT_MATERIALIZER_AMLOGIC_DTB": "/dcent/held/devicetree.dtb",
            "DCENT_MATERIALIZER_AMLOGIC_FW_INFO": "/dcent/held/fw-info",
            "DCENT_MATERIALIZER_WORK_ROOT": "/dcent/materializer/work",
            "DCENT_MATERIALIZER_OUTPUT_ROOT": "/dcent/materializer/output",
            "DCENT_MATERIALIZER_SELECTION": "/dcent/materializer/selection.json",
            "DCENT_MATERIALIZER_NETWORK_MODE": "source-fetch-only",
        }

    @staticmethod
    def _config_environment(config: Mapping[str, Any]) -> dict[str, str]:
        raw_environment = config.get("Env")
        if not isinstance(raw_environment, list):
            fail("Docker inspect lacks the materializer environment")
        parsed: dict[str, str] = {}
        for raw in raw_environment:
            if not isinstance(raw, str) or "=" not in raw:
                fail("Docker inspect contains a malformed environment entry")
            name, value = raw.split("=", 1)
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) or name in parsed:
                fail("Docker inspect contains an ambiguous environment entry")
            parsed[name] = value
        return parsed

    def _verify_materializer_boundary(
        self,
        inspected: Mapping[str, Any],
        request: MaterializerRequest,
        admitted_image_id: str | None = None,
    ) -> None:
        config = inspected.get("Config")
        host = inspected.get("HostConfig")
        mounts = inspected.get("Mounts")
        networks = (inspected.get("NetworkSettings") or {}).get("Networks")
        if (
            not isinstance(config, dict)
            or not isinstance(host, dict)
            or not isinstance(mounts, list)
            or not isinstance(networks, dict)
        ):
            fail("Docker inspect lacks materializer boundary evidence")
        security = host.get("SecurityOpt") or []
        cap_drop = host.get("CapDrop") or []
        restart = host.get("RestartPolicy") or {}
        log_config = host.get("LogConfig") or {}
        if (
            inspected.get("Image")
            != (admitted_image_id or request.builder_image.rsplit("@", 1)[1])
            or
            config.get("Image") != request.builder_image
            or config.get("User") != self.container_user
            or config.get("WorkingDir") != self.INVOCATION_DESTINATION
            or config.get("Hostname") != self.HOSTNAME
            or config.get("Domainname") != self.DOMAINNAME
            or config.get("Entrypoint") != ["/bin/sh"]
            or config.get("Cmd") != [self.DRIVER]
            or config.get("OpenStdin") is not False
            or config.get("Tty") is not False
            or host.get("NetworkMode") != "bridge"
            or set(networks) != {"bridge"}
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or host.get("CapAdd") not in (None, [])
            or "ALL" not in cap_drop
            or not any(str(value).startswith("no-new-privileges") for value in security)
            or host.get("Devices") not in (None, [])
            or host.get("PidsLimit") != 8192
            or host.get("PublishAllPorts") is not False
            or host.get("PortBindings") not in (None, {})
            or host.get("Links") not in (None, [])
            or host.get("ExtraHosts") not in (None, [])
            or host.get("VolumesFrom") not in (None, [])
            or host.get("IpcMode") != "none"
            or host.get("PidMode") not in (None, "", "private")
            or host.get("UTSMode") not in (None, "", "private")
            or restart.get("Name") not in (None, "", "no")
            or log_config.get("Type") != "none"
        ):
            fail("Docker inspect does not prove the source-fetch least-privilege boundary")

        environment = self._config_environment(config)
        expected_environment = self._materializer_environment(request)
        if environment != expected_environment:
            fail("Docker materializer environment is not the exact reviewed environment")

        expected_sources: dict[str, tuple[Path, bool]] = {
            "/dcent/source-snapshot": (request.source_snapshot.parent, False),
            "/dcent/held/vmlinux.bin": (request.amlogic_kernel, False),
            "/dcent/held/devicetree.dtb": (request.amlogic_dtb, False),
            "/dcent/held/fw-info": (request.amlogic_fw_info, False),
            self.INVOCATION_DESTINATION: (request.runtime_root, True),
        }
        observed_destinations: dict[str, bool] = {}
        run_tmpfs_seen = False
        for item in mounts:
            if not isinstance(item, dict):
                fail("Docker materializer contains a malformed mount")
            destination = item.get("Destination")
            mount_type = item.get("Type")
            if mount_type == "tmpfs" and destination == "/run":
                if run_tmpfs_seen or item.get("RW") is not True:
                    fail("Docker materializer has an invalid /run tmpfs")
                run_tmpfs_seen = True
                continue
            if mount_type != "bind" or destination not in expected_sources:
                fail("Docker materializer contains an unapproved mount")
            if destination in observed_destinations:
                fail(f"Docker materializer repeats mount destination {destination!r}")
            expected_source, expected_rw = expected_sources[destination]
            source = item.get("Source")
            if (
                not isinstance(source, str)
                or not os.path.isabs(source)
                or item.get("Propagation") != "rprivate"
                or item.get("RW") is not expected_rw
            ):
                fail(f"Docker materializer bind metadata is invalid for {destination}")
            try:
                if not os.path.samefile(source, expected_source):
                    fail(f"Docker materializer bind source is substituted for {destination}")
            except OSError:
                fail(f"Docker materializer bind source cannot be identified for {destination}")
            observed_destinations[destination] = expected_rw
        if observed_destinations != {
            destination: writable
            for destination, (_, writable) in expected_sources.items()
        }:
            fail("Docker materializer mount set or read/write policy is not exact")
        tmpfs = host.get("Tmpfs")
        if not isinstance(tmpfs, dict) or set(tmpfs) != {"/run"}:
            fail("Docker materializer tmpfs set is not exact")
        options = tmpfs["/run"]
        if not isinstance(options, str) or set(options.split(",")) != {
            "rw",
            "noexec",
            "nosuid",
            "nodev",
            "size=16777216",
        }:
            fail("Docker materializer /run tmpfs policy is invalid")

    def execute(self, request: MaterializerRequest) -> Mapping[str, Any]:
        self._verify_preflight_docker_identity()
        if not IMMUTABLE_IMAGE.fullmatch(request.builder_image):
            fail("materializer request builder image is not digest-pinned")
        policy_path = request.source_tree.joinpath(
            *PurePosixPath(DEPENDENCY_POLICY_RELATIVE).parts
        )
        policy, _ = load_dependency_policy(policy_path)
        if (
            request.builder_image != policy["builder"]["image"]
            or request.toolchain_id != policy["builder"]["toolchain_id"]
        ):
            fail("materializer request differs from authenticated builder policy")
        admitted_image_id = self._verify_image(request.builder_image, policy["builder"])
        runtime_name = f"dcentos-{request.materialization_id}"
        command: list[str] = [
            "create",
            "--pull=never",
            "--name",
            runtime_name,
            "--hostname",
            self.HOSTNAME,
            "--domainname",
            self.DOMAINNAME,
            "--network",
            "bridge",
            "--read-only",
            "--user",
            self.container_user,
            "--workdir",
            self.INVOCATION_DESTINATION,
            "--privileged=false",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--pids-limit",
            "8192",
            "--ipc",
            "none",
            "--publish-all=false",
            "--restart",
            "no",
            "--log-driver",
            "none",
            "--entrypoint",
            "/bin/sh",
            "--tmpfs",
            "/run:rw,noexec,nosuid,nodev,size=16777216",
        ]
        readonly_sources = {
            "/dcent/source-snapshot": request.source_snapshot.parent,
            "/dcent/held/vmlinux.bin": request.amlogic_kernel,
            "/dcent/held/devicetree.dtb": request.amlogic_dtb,
            "/dcent/held/fw-info": request.amlogic_fw_info,
        }
        for destination, source in readonly_sources.items():
            command.extend(("--mount", self._mount_argument(source, destination, readonly=True)))
        command.extend(
            (
                "--mount",
                self._mount_argument(
                    request.runtime_root,
                    self.INVOCATION_DESTINATION,
                    readonly=False,
                ),
            )
        )
        for name, value in sorted(self._materializer_environment(request).items()):
            if any(character in value for character in "\0\r\n"):
                fail(f"materializer environment {name} is unsafe")
            command.extend(("--env", f"{name}={value}"))
        command.extend((request.builder_image, self.DRIVER))
        created: str | None = None
        try:
            created_value = self._run(command).stdout.decode("ascii", "strict").strip()
            if not re.fullmatch(r"[0-9a-f]{64}", created_value):
                fail("Docker create did not return one full materializer container ID")
            created = created_value
            inspected_before = self._inspect(created)
            inspected_before_raw = canonical_json(inspected_before)
            write_no_replace(request.inspect_before_path, inspected_before_raw)
            _fsync_directory(request.invocation_root, strict=True)
            self._verify_materializer_boundary(
                inspected_before, request, admitted_image_id
            )
            attach_exit_code = self._run_attached_to_new_log(created, request.log_path)
            inspected_after = self._inspect(created)
            inspected_after_raw = canonical_json(inspected_after)
            write_no_replace(request.inspect_after_path, inspected_after_raw)
            _fsync_directory(request.invocation_root, strict=True)
            self._verify_materializer_boundary(inspected_after, request, admitted_image_id)
            state = inspected_after.get("State")
            if (
                not isinstance(state, dict)
                or state.get("Running") is not False
                or state.get("OOMKilled") is not False
                or state.get("ExitCode") != 0
                or attach_exit_code != 0
            ):
                fail(
                    f"dependency materializer failed; container {created} and owned root retained"
                )
        except BaseException:
            if created is None:
                raise
            try:
                self._stop_and_verify_container(created)
            except BaseException as stop_error:
                raise ProducerError(
                    "dependency materializer failed and container stop could not be proven: "
                    f"{created}"
                ) from stop_error
            raise
        self._run(("rm", created))
        return {
            "schema": MATERIALIZER_OBSERVATION_SCHEMA,
            "runtime_id": created,
            "materialization_id": request.materialization_id,
            "builder_image": request.builder_image,
            "toolchain_id": request.toolchain_id,
            "source_commit": request.source_commit,
            "source_snapshot_id": request.source_snapshot_id,
            "network_mode": "unrestricted-bridge-source-fetch-intent",
            "network_boundary_inspected": "container-config-only-no-egress-proof",
            "read_only_rootfs": True,
            "privileged": False,
            "build_cache_reused": False,
            "exit_code": 0,
            "output_relative_path": "output",
            "selection_relative_path": "selection.json",
            "log_relative_path": "materializer.log",
            "inspect_before_relative_path": "inspect-before.json",
            "inspect_before_sha256": sha256_bytes(inspected_before_raw),
            "inspect_after_relative_path": "inspect-after.json",
            "inspect_after_sha256": sha256_bytes(inspected_after_raw),
        }


@dataclass(frozen=True)
class ValidatedBuildResult:
    label: str
    stage: Path
    package: Path
    receipt: Path
    log: Path
    receipt_value: dict[str, Any]
    owner_value: dict[str, Any]
    runtime_observation: dict[str, Any]


def _validate_build_receipt_shape(
    value: object,
    *,
    label: str,
    package_sha256: str,
    package_bytes: int,
    source_commit: str,
    source_date_epoch: int,
    toolchain_id: str,
) -> dict[str, Any]:
    receipt = _exact_object(value, BUILD_RECEIPT_KEYS, f"build {label} attestation")
    if receipt["schema"] != BUILD_ATTESTATION_SCHEMA:
        fail(f"build {label} attestation schema is invalid")
    for field in ("build_id", "build_root_id"):
        if not isinstance(receipt[field], str) or not TOKEN.fullmatch(receipt[field]):
            fail(f"build {label} {field} is not a canonical token")
    expected = {
        "clean_build": True,
        "build_cache_reused": False,
        "network_used": False,
        "source_commit": source_commit,
        "source_date_epoch": source_date_epoch,
        "build_target": BUILD_TARGET,
        "build_arch": BUILD_ARCH,
        "toolchain_id": toolchain_id,
        "package_name": f"build-{label}.unsigned.tar",
        "package_sha256": package_sha256,
        "package_bytes": package_bytes,
    }
    for field, expected_value in expected.items():
        if receipt.get(field) != expected_value:
            fail(f"build {label} attestation disagrees on {field}")
    return receipt


def validate_build_result(
    stage: Path,
    label: str,
    *,
    source_commit: str,
    source_date_epoch: int,
    toolchain_id: str,
) -> ValidatedBuildResult:
    if label not in ("a", "b"):
        fail("build label must be a or b")
    stage = Path(os.path.abspath(os.fspath(stage)))
    _require_directory(stage, f"build {label} result stage")
    observed_files, observed_directories = _walk_regular_tree(stage, f"build {label} result stage")
    expected = ["build.log", "package.tar", "receipt.json", "result-owner.json"]
    if observed_files != expected or observed_directories:
        fail(f"build {label} result stage has missing, extra, or nested content")
    owner = load_canonical_json(stage / "result-owner.json", 4096, f"build {label} owner")
    owner = _exact_object(
        owner,
        (
            "schema",
            "build_id",
            "build_root_id",
            "builder_image",
            "toolchain_id",
            "source_commit",
            "source_date_epoch",
            "source_snapshot_id",
            "dependency_bundle_id",
            "release_input_id",
            "runtime_id",
            "runtime_observation_sha256",
            "inner_build_log_sha256",
            "network_boundary",
            "network_used",
            "started_empty",
            "source_snapshot_verified_before_after",
            "dependency_bundle_verified_before_after",
            "result_publication",
            "mutable_roots",
        ),
        f"build {label} owner",
    )
    if owner["network_used"] is not False:
        fail(f"build {label} owner cannot claim network_used=false")
    if (
        owner["schema"] != BUILD_RESULT_SCHEMA
        or not isinstance(owner["build_id"], str)
        or not TOKEN.fullmatch(owner["build_id"])
        or not isinstance(owner["build_root_id"], str)
        or not TOKEN.fullmatch(owner["build_root_id"])
        or not isinstance(owner["builder_image"], str)
        or not IMMUTABLE_IMAGE.fullmatch(owner["builder_image"])
        or owner["toolchain_id"] != toolchain_id
        or owner["source_commit"] != source_commit
        or owner["source_date_epoch"] != source_date_epoch
        or owner["network_boundary"] != "oci-network-none-inspected"
        or owner["started_empty"] is not True
        or owner["source_snapshot_verified_before_after"] is not True
        or owner["dependency_bundle_verified_before_after"] is not True
        or owner["result_publication"] != "opened-regular-file-hash-no-replace-fsync"
        or not isinstance(owner["source_snapshot_id"], str)
        or not HEX_64.fullmatch(owner["source_snapshot_id"])
        or not isinstance(owner["dependency_bundle_id"], str)
        or not HEX_64.fullmatch(owner["dependency_bundle_id"])
        or not isinstance(owner["release_input_id"], str)
        or not HEX_64.fullmatch(owner["release_input_id"])
        or not isinstance(owner["runtime_id"], str)
        or not TOKEN.fullmatch(owner["runtime_id"])
        or not isinstance(owner["runtime_observation_sha256"], str)
        or not HEX_64.fullmatch(owner["runtime_observation_sha256"])
        or not isinstance(owner["inner_build_log_sha256"], str)
        or not HEX_64.fullmatch(owner["inner_build_log_sha256"])
        or owner["mutable_roots"]
        != [f"{owner['build_root_id']}:{role}" for role in MUTABLE_ROOT_ROLES]
    ):
        fail(f"build {label} owner does not prove the isolated offline boundary")
    package_raw = read_regular(stage / "package.tar", MAX_PACKAGE_BYTES, f"build {label} package")
    receipt_path = stage / "receipt.json"
    receipt = load_canonical_json(receipt_path, MAX_JSON_BYTES, f"build {label} attestation")
    receipt = _validate_build_receipt_shape(
        receipt,
        label=label,
        package_sha256=sha256_bytes(package_raw),
        package_bytes=len(package_raw),
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        toolchain_id=toolchain_id,
    )
    if receipt["build_id"] != owner["build_id"] or receipt["build_root_id"] != owner["build_root_id"]:
        fail(f"build {label} owner and attestation identities disagree")
    expanded_log = read_regular(
        stage / "build.log", MAX_RECEIPT_BYTES, f"build {label} expanded log"
    )
    if not expanded_log.startswith(RUNTIME_LOG_PREFIX):
        fail(f"build {label} expanded log lacks its runtime-observation prefix")
    retained = expanded_log[len(RUNTIME_LOG_PREFIX) :]
    marker = retained.find(INNER_LOG_PREFIX)
    if marker < 0 or retained.find(INNER_LOG_PREFIX, marker + 1) >= 0:
        fail(f"build {label} expanded log has an invalid inner-log boundary")
    observation_raw = retained[:marker]
    inner_log = retained[marker + len(INNER_LOG_PREFIX) :]
    try:
        observation_value = json.loads(observation_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"build {label} runtime observation in log is invalid JSON: {error}")
    observation = _exact_object(
        observation_value,
        (
            "schema",
            "runtime_id",
            "build_id",
            "build_root_id",
            "builder_image",
            "source_snapshot_id",
            "dependency_bundle_id",
            "release_input_id",
            "network_mode",
            "network_boundary_inspected",
            "read_only_rootfs",
            "privileged",
            "build_cache_reused",
            "exit_code",
            "package_relative_path",
            "build_log_relative_path",
        ),
        f"build {label} retained runtime observation",
    )
    if observation_raw != canonical_json(observation):
        fail(f"build {label} retained runtime observation is noncanonical")
    expected_observation = {
        "schema": RUNTIME_OBSERVATION_SCHEMA,
        "runtime_id": owner["runtime_id"],
        "build_id": owner["build_id"],
        "build_root_id": owner["build_root_id"],
        "builder_image": owner["builder_image"],
        "source_snapshot_id": owner["source_snapshot_id"],
        "dependency_bundle_id": owner["dependency_bundle_id"],
        "release_input_id": owner["release_input_id"],
        "network_mode": "none",
        "network_boundary_inspected": True,
        "read_only_rootfs": True,
        "privileged": False,
        "build_cache_reused": False,
        "exit_code": 0,
        "package_relative_path": f"result/{INNER_PACKAGE_NAME}",
        "build_log_relative_path": "logs/build.log",
    }
    if observation != expected_observation:
        fail(f"build {label} retained runtime observation is not exactly bound")
    if (
        sha256_bytes(observation_raw) != owner["runtime_observation_sha256"]
        or sha256_bytes(inner_log) != owner["inner_build_log_sha256"]
    ):
        fail(f"build {label} owner does not bind the complete expanded log")
    return ValidatedBuildResult(
        label,
        stage,
        stage / "package.tar",
        receipt_path,
        stage / "build.log",
        receipt,
        owner,
        observation,
    )


def _directory_identity(path: Path, label: str) -> dict[str, Any]:
    absolute = Path(os.path.abspath(os.fspath(path)))
    metadata = _require_directory(absolute, label)
    return {
        "path": os.fspath(absolute),
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def _validated_result_binding(result: ValidatedBuildResult) -> dict[str, Any]:
    limits = {
        "build.log": MAX_RECEIPT_BYTES,
        "package.tar": MAX_PACKAGE_BYTES,
        "receipt.json": MAX_JSON_BYTES,
        "result-owner.json": MAX_JSON_BYTES,
    }
    files = []
    for name in sorted(limits):
        raw = read_regular(result.stage / name, limits[name], f"bound build {result.label} {name}")
        files.append({"path": name, "sha256": sha256_bytes(raw), "bytes": len(raw)})
    return {
        "label": result.label,
        "stage": _directory_identity(result.stage, f"build {result.label} bound stage"),
        "build_id": result.receipt_value["build_id"],
        "build_root_id": result.receipt_value["build_root_id"],
        "runtime_id": result.owner_value["runtime_id"],
        "source_snapshot_id": result.owner_value["source_snapshot_id"],
        "dependency_bundle_id": result.owner_value["dependency_bundle_id"],
        "release_input_id": result.owner_value["release_input_id"],
        "files": files,
    }


def _build_pair_capability_body(
    build_a: ValidatedBuildResult,
    build_b: ValidatedBuildResult,
    build_roots: tuple[Path, Path],
) -> dict[str, Any]:
    if build_a.label != "a" or build_b.label != "b":
        fail("coordinator build pair labels are invalid")
    if (
        build_a.receipt_value["build_id"] == build_b.receipt_value["build_id"]
        or build_a.receipt_value["build_root_id"]
        == build_b.receipt_value["build_root_id"]
    ):
        fail("A/B coordinator results reused a build or root identity")
    if (
        build_a.receipt_value["package_sha256"]
        != build_b.receipt_value["package_sha256"]
        or build_a.receipt_value["package_bytes"]
        != build_b.receipt_value["package_bytes"]
    ):
        fail("A/B coordinator package bytes differ")
    if len(build_roots) != 2:
        fail("coordinator build pair does not contain exactly two roots")
    root_values = [
        _directory_identity(root, f"build {label} capability root")
        for label, root in zip(("a", "b"), build_roots)
    ]
    if (root_values[0]["device"], root_values[0]["inode"]) == (
        root_values[1]["device"],
        root_values[1]["inode"],
    ):
        fail("A/B build roots physically alias")

    mutable_values: list[dict[str, Any]] = []
    physical_by_label: dict[str, set[tuple[int, int]]] = {"a": set(), "b": set()}
    for label, root, result in zip(("a", "b"), build_roots, (build_a, build_b)):
        absolute_root = Path(os.path.abspath(os.fspath(root)))
        for role in MUTABLE_ROOT_ROLES:
            value = _directory_identity(
                absolute_root / role, f"build {label} mutable root {role}"
            )
            identity = (value["device"], value["inode"])
            if identity in physical_by_label[label]:
                fail(f"build {label} mutable roots physically alias")
            physical_by_label[label].add(identity)
            mutable_values.append(
                {
                    "label": label,
                    "role": role,
                    "build_root_id": result.receipt_value["build_root_id"],
                    **value,
                }
            )
    if physical_by_label["a"] & physical_by_label["b"]:
        fail("A/B builds physically reused mutable storage")

    a_binding = _validated_result_binding(build_a)
    b_binding = _validated_result_binding(build_b)
    if (
        a_binding["source_snapshot_id"] != b_binding["source_snapshot_id"]
        or a_binding["dependency_bundle_id"] != b_binding["dependency_bundle_id"]
        or a_binding["release_input_id"] != b_binding["release_input_id"]
    ):
        fail("A/B builds did not consume the same sealed read-only inputs")
    return {
        "schema": BUILD_PAIR_CAPABILITY_SCHEMA,
        "build_a": a_binding,
        "build_b": b_binding,
        "build_roots": root_values,
        "mutable_roots": mutable_values,
        "classification": "one-process-one-use-publication-capability",
    }


def _issue_build_pair_capability(
    build_a: ValidatedBuildResult,
    build_b: ValidatedBuildResult,
    build_roots: tuple[Path, Path],
) -> str:
    body = _build_pair_capability_body(build_a, build_b, build_roots)
    capability = secrets.token_hex(32)
    if capability in _ISSUED_BUILD_PAIR_CAPABILITIES:
        fail("publication capability collision")
    _ISSUED_BUILD_PAIR_CAPABILITIES[capability] = canonical_json(body)
    return capability


def _consume_build_pair_capability(
    pair: ExecutedBuildPair,
    *,
    source_commit: str,
    source_date_epoch: int,
    toolchain_id: str,
) -> tuple[ValidatedBuildResult, ValidatedBuildResult]:
    if not isinstance(pair, ExecutedBuildPair):
        fail("publication requires an executed coordinator build pair")
    capability = pair.publication_capability
    if not isinstance(capability, str) or not HEX_64.fullmatch(capability):
        fail("coordinator build-pair capability is invalid")
    expected = _ISSUED_BUILD_PAIR_CAPABILITIES.pop(capability, None)
    if expected is None:
        fail("coordinator build-pair capability is unknown, consumed, or from another process")
    a = validate_build_result(
        pair.build_a.stage,
        "a",
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        toolchain_id=toolchain_id,
    )
    b = validate_build_result(
        pair.build_b.stage,
        "b",
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        toolchain_id=toolchain_id,
    )
    observed = canonical_json(_build_pair_capability_body(a, b, pair.build_roots))
    if not secrets.compare_digest(expected, observed):
        fail("coordinator build-pair capability binding changed before publication")
    return a, b


def _load_admitted_python_component(
    source: SourceAdmission,
    receipt: Mapping[str, Any],
    relative: str,
    purpose: str,
) -> Any:
    records = [item for item in receipt["source_files"] if item.get("path") == relative]
    if len(records) != 1:
        fail(f"source admission does not bind exactly one {purpose}")
    path = source.tree.joinpath(*PurePosixPath(relative).parts)
    raw = read_regular(path, MAX_JSON_BYTES, f"admitted {purpose}")
    record = records[0]
    if (
        sha256_bytes(raw) != record.get("sha256")
        or len(raw) != record.get("bytes")
        or record.get("git_mode") not in ("100644", "100755")
    ):
        fail(f"admitted {purpose} differs from signed source admission")
    module = _load_opened_python_module(raw, path, purpose.replace("-", "_"))
    retained_sha256, retained_bytes = hash_regular(
        path, MAX_JSON_BYTES, f"retained admitted {purpose}"
    )
    if retained_sha256 != sha256_bytes(raw) or retained_bytes != len(raw):
        fail(f"admitted {purpose} changed during module admission")
    return module


def _load_persistent_verifier(
    source: SourceAdmission, receipt: Mapping[str, Any]
) -> Any:
    return _load_admitted_python_component(
        source,
        receipt,
        "DCENT_OS_Antminer/scripts/s19k_persistent_image_verify.py",
        "persistent-image-verifier",
    )


def _load_release_signer(source: SourceAdmission, receipt: Mapping[str, Any]) -> Any:
    return _load_admitted_python_component(
        source,
        receipt,
        "DCENT_OS_Antminer/scripts/s19k_hermetic_release_signer.py",
        "post-ab-release-signer",
    )


def publish_verified_evidence(
    pair: ExecutedBuildPair,
    release_inputs: ReleaseInputs,
    private_key: Path,
    output: Path,
    *,
    source_commit: str,
    source_date_epoch: int,
    toolchain_id: str,
    expected_release_key_sha256: str,
    strict_durability: bool = True,
    source: SourceAdmission | None = None,
    host_preflight: Mapping[str, Any] | None = None,
    dependency_stage: Path | None = None,
    verifier: Any | None = None,
    signer_runtime: IsolatedSignerRuntime | None = None,
) -> dict[str, Any]:
    """Consume one capability, sign equal unsigned A/B, and publish v4 evidence.

    Raw result-stage paths are intentionally not accepted.  The one-use
    capability exists only in the process that executed both offline builds,
    preventing copied or self-authored stage receipts from entering v4.
    """

    if not FULL_COMMIT.fullmatch(source_commit):
        fail("source_commit must be a full lowercase object id")
    if source_date_epoch < 0 or source_date_epoch > MAX_SOURCE_EPOCH:
        fail("source_date_epoch is outside the uImage 32-bit timestamp range")
    if not TOKEN.fullmatch(toolchain_id):
        fail("toolchain_id is not a canonical token")
    if not HEX_64.fullmatch(expected_release_key_sha256):
        fail("expected release-key SHA-256 must be lowercase hex")
    if not isinstance(release_inputs, ReleaseInputs):
        fail("publication requires one sealed release-input handle")
    if not isinstance(host_preflight, Mapping):
        fail("publication requires the fresh bound host-preflight report")
    host_preflight_raw = canonical_json(dict(host_preflight))
    release = verify_release_inputs(
        release_inputs.descriptor,
        expected_release_key_sha256=expected_release_key_sha256,
    )
    if release_inputs.input_id != release["input_id"]:
        fail("release-input handle differs from its verified descriptor")
    a, b = _consume_build_pair_capability(
        pair,
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        toolchain_id=toolchain_id,
    )
    if (
        a.owner_value["release_input_id"] != release["input_id"]
        or b.owner_value["release_input_id"] != release["input_id"]
    ):
        fail("A/B build pair is not bound to the supplied release inputs")
    if a.stage == b.stage:
        fail("build A and B must have distinct result stages")
    if a.receipt_value["build_id"] == b.receipt_value["build_id"] or a.receipt_value[
        "build_root_id"
    ] == b.receipt_value["build_root_id"]:
        fail("build A and B must have distinct build and root identities")
    owner_a = a.owner_value
    owner_b = b.owner_value
    if (
        owner_a["source_snapshot_id"] != owner_b["source_snapshot_id"]
        or owner_a["dependency_bundle_id"] != owner_b["dependency_bundle_id"]
    ):
        fail("build A and B did not consume the same sealed read-only inputs")
    if set(owner_a["mutable_roots"]) & set(owner_b["mutable_roots"]):
        fail("build A and B reused mutable state")
    package_a = read_regular(a.package, MAX_PACKAGE_BYTES, "build A package")
    package_b = read_regular(b.package, MAX_PACKAGE_BYTES, "build B package")
    if package_a != package_b:
        fail("build A and B package bytes differ")
    key_raw = read_regular(
        release_inputs.public_key, MAX_KEY_BYTES, "trusted release key"
    )
    if sha256_bytes(key_raw) != expected_release_key_sha256:
        fail("trusted release key differs from the reviewed out-of-band SHA-256")
    native_raw = read_regular(
        release_inputs.native_owner_receipt, MAX_JSON_BYTES, "native-owner receipt"
    )
    recovery_raw = read_regular(
        release_inputs.stock_recovery_receipt, MAX_JSON_BYTES, "stock-recovery receipt"
    )

    output = Path(os.path.abspath(os.fspath(output)))
    parent = output.parent
    if strict_durability and os.name != "nt":
        _require_private_ext4_parent(parent, "evidence output parent")
    else:
        _require_directory(parent, "evidence output parent")
    if output.exists() or output.is_symlink():
        fail(f"refusing to replace existing evidence output: {output}")
    verifier_sha256 = ""
    signer_sha256 = ""
    if verifier is None:
        if source is None:
            fail("default verifier loading requires the admitted source handle")
        source_receipt = validate_source_admission_receipt(source.receipt)
        _verify_admitted_source_snapshot(source, source_receipt)
        verifier = _load_persistent_verifier(source, source_receipt)
        verifier_record = next(
            item
            for item in source_receipt["source_files"]
            if item["path"]
            == "DCENT_OS_Antminer/scripts/s19k_persistent_image_verify.py"
        )
        signer_record = next(
            item
            for item in source_receipt["source_files"]
            if item["path"]
            == "DCENT_OS_Antminer/scripts/s19k_hermetic_release_signer.py"
        )
        verifier_sha256 = verifier_record["sha256"]
        signer_sha256 = signer_record["sha256"]
    elif source is not None:
        fail("production publication does not accept a caller-selected verifier")
    else:
        verifier_path = Path(__file__).with_name("s19k_persistent_image_verify.py")
        signer_path = Path(__file__).with_name("s19k_hermetic_release_signer.py")
        verifier_sha256, _ = hash_regular(
            verifier_path, MAX_JSON_BYTES, "test verifier component"
        )
        signer_sha256, _ = hash_regular(
            signer_path, MAX_JSON_BYTES, "test signer component"
        )
    for component, method in (
        (verifier, "verify_evidence"),
        (verifier, "validate_unsigned_build_pair"),
    ):
        if not callable(getattr(component, method, None)):
            fail(f"admitted release component lacks {method}")
    if signer_runtime is None or dependency_stage is None:
        fail("publication requires a separately inspected isolated signer runtime")

    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=parent))
    published = False
    try:
        write_no_replace(staging / "build-a.unsigned.tar", package_a)
        write_no_replace(staging / "build-b.unsigned.tar", package_b)
        write_no_replace(staging / "build-a.json", canonical_json(a.receipt_value))
        write_no_replace(staging / "build-b.json", canonical_json(b.receipt_value))
        write_no_replace(staging / "host-preflight.json", host_preflight_raw)
        write_no_replace(staging / "trusted-release-key.pem", key_raw)
        write_no_replace(staging / "native-owner-verification.json", native_raw)
        write_no_replace(staging / "stock-recovery-verification.json", recovery_raw)
        observed, directories = _walk_regular_tree(staging, "pending evidence stage")
        if observed != sorted(EVIDENCE_PUBLIC_FILES) or directories:
            fail("pending evidence stage differs from the exact public signer input set")
        if read_regular(staging / "build-a.unsigned.tar", MAX_PACKAGE_BYTES, "retained build A") != read_regular(
            staging / "build-b.unsigned.tar", MAX_PACKAGE_BYTES, "retained build B"
        ):
            fail("retained build A and B packages differ")

        try:
            verifier.validate_unsigned_build_pair(
                package_a,
                package_b,
                canonical_json(a.receipt_value),
                canonical_json(b.receipt_value),
                key_raw,
                native_raw,
                recovery_raw,
                expected_release_key_sha256=expected_release_key_sha256,
            )
        except Exception as error:
            fail(f"public A/B inputs refused before private-key custody: {error}")

        private_custody = (
            _admit_private_signing_key_path(private_key)
            if strict_durability
            else _portable_test_private_key_custody(private_key)
        )
        signing_invocation = Path(
            tempfile.mkdtemp(prefix=f".{output.name}.signer-", dir=parent)
        )
        signing_output_parent = signing_invocation / "output"
        signing_output_parent.mkdir(mode=0o700)
        host_preflight_id = host_preflight.get("preflight_id")
        if not isinstance(host_preflight_id, str) or not HEX_64.fullmatch(
            host_preflight_id
        ):
            fail("fresh host preflight lacks a canonical identity")
        signing_id = f"s19k-sign-{secrets.token_hex(16)}"
        signing_request = IsolatedSignerRequest(
            signing_id=signing_id,
            builder_image=owner_a["builder_image"],
            dependency_stage=Path(dependency_stage),
            source_stage=(source.snapshot.parent if source is not None else Path(__file__).parent),
            public_stage=staging,
            private_key=Path(private_key),
            private_key_custody=private_custody,
            output_parent=signing_output_parent,
            log_path=signing_invocation / "signer.log",
            inspect_before_path=signing_invocation / "inspect-before.json",
            inspect_after_path=signing_invocation / "inspect-after.json",
            expected_release_key_sha256=expected_release_key_sha256,
            verifier_sha256=verifier_sha256,
            signer_sha256=signer_sha256,
            host_preflight_id=host_preflight_id,
        )
        _require_nonoverlapping_paths(
            {
                "source": signing_request.source_stage,
                "dependencies": signing_request.dependency_stage,
                "public-inputs": signing_request.public_stage,
                "private-key": signing_request.private_key,
                "signer-output": signing_request.output_parent,
            }
        )
        try:
            signer_observation = dict(signer_runtime.execute(signing_request))
        except Exception as error:
            fail(f"isolated post-A/B signer refused: {error}")
        signed_name = "dcentos-sysupgrade-am3-s19kpro.tar"
        signing_receipt_name = "signing-receipt.json"
        signed_stage = signing_output_parent / "signed"
        signed_source = signed_stage / signed_name
        receipt_source = signed_stage / signing_receipt_name
        copy_no_replace(
            signed_source,
            staging / signed_name,
            MAX_PACKAGE_BYTES,
            "post-A/B signed package",
        )
        copy_no_replace(
            receipt_source,
            staging / signing_receipt_name,
            MAX_JSON_BYTES,
            "post-A/B signing receipt",
        )
        signing_files, signing_directories = _walk_regular_tree(
            signing_invocation, "isolated signing invocation"
        )
        expected_signing_files = [
            "inspect-after.json",
            "inspect-before.json",
            f"output/signed/{signed_name}",
            f"output/signed/{signing_receipt_name}",
            "signer.log",
        ]
        if signing_files != expected_signing_files or signing_directories != [
            "output",
            "output/signed",
        ]:
            fail("isolated signer invocation ledger is not exact")
        signer_observation = _exact_object(
            signer_observation,
            (
                "schema",
                "runtime_id",
                "signing_id",
                "builder_image",
                "network_mode",
                "network_boundary_inspected_before_after",
                "read_only_rootfs",
                "privileged",
                "private_key_custody_id",
                "host_preflight_id",
                "verifier_sha256",
                "signer_sha256",
                "inspect_before_sha256",
                "inspect_after_sha256",
                "log_sha256",
                "log_bytes",
                "signed_package_sha256",
                "signed_package_bytes",
                "signing_receipt_sha256",
                "signing_receipt_bytes",
                "container_removed_after_stop_proof",
                "install_authority_granted",
                "flash_authority_granted",
                "mutation_authority_granted",
            ),
            "isolated signer runtime observation",
        )
        if (
            signer_observation["schema"] != SIGNER_RUNTIME_SCHEMA
            or signer_observation["signing_id"] != signing_id
            or signer_observation["builder_image"] != owner_a["builder_image"]
            or signer_observation["network_mode"] != "none"
            or signer_observation["network_boundary_inspected_before_after"] is not True
            or signer_observation["read_only_rootfs"] is not True
            or signer_observation["privileged"] is not False
            or signer_observation["private_key_custody_id"] != private_custody["custody_id"]
            or signer_observation["host_preflight_id"] != host_preflight_id
            or signer_observation["verifier_sha256"] != verifier_sha256
            or signer_observation["signer_sha256"] != signer_sha256
            or signer_observation["container_removed_after_stop_proof"] is not True
            or signer_observation["install_authority_granted"] is not False
            or signer_observation["flash_authority_granted"] is not False
            or signer_observation["mutation_authority_granted"] is not False
        ):
            fail("isolated signer runtime observation does not prove exact custody")
        for path, digest_field, bytes_field, maximum, label in (
            (signing_request.inspect_before_path, "inspect_before_sha256", None, MAX_RECEIPT_BYTES, "signer inspect-before"),
            (signing_request.inspect_after_path, "inspect_after_sha256", None, MAX_RECEIPT_BYTES, "signer inspect-after"),
            (signing_request.log_path, "log_sha256", "log_bytes", MAX_RECEIPT_BYTES, "signer log"),
            (signed_source, "signed_package_sha256", "signed_package_bytes", MAX_PACKAGE_BYTES, "signed package"),
            (receipt_source, "signing_receipt_sha256", "signing_receipt_bytes", MAX_JSON_BYTES, "signing receipt"),
        ):
            digest_value, byte_count = hash_regular(path, maximum, label)
            if digest_value != signer_observation[digest_field] or (
                bytes_field is not None
                and byte_count != signer_observation[bytes_field]
            ):
                fail(f"isolated {label} differs from runtime observation")
        write_no_replace(
            staging / "signer-runtime.json", canonical_json(signer_observation)
        )
        for source_path, destination_name, maximum, label in (
            (signing_request.inspect_before_path, "signer-inspect-before.json", MAX_RECEIPT_BYTES, "signer inspect-before evidence"),
            (signing_request.inspect_after_path, "signer-inspect-after.json", MAX_RECEIPT_BYTES, "signer inspect-after evidence"),
            (signing_request.log_path, "signer.log", MAX_RECEIPT_BYTES, "signer log evidence"),
        ):
            copy_no_replace(
                source_path,
                staging / destination_name,
                maximum,
                label,
            )
        for relative in signing_files:
            path = signing_invocation.joinpath(*PurePosixPath(relative).parts)
            os.chmod(path, 0o600)
            path.unlink()
        for relative in reversed(signing_directories):
            path = signing_invocation.joinpath(*PurePosixPath(relative).parts)
            os.chmod(path, 0o700)
            path.rmdir()
        os.chmod(signing_invocation, 0o700)
        signing_invocation.rmdir()

        observed, directories = _walk_regular_tree(staging, "complete verifier inputs")
        if observed != sorted(EVIDENCE_INPUT_FILES) or directories:
            fail("complete evidence stage differs from exact v4 verifier inputs")
        verification = verifier.verify_evidence(
            staging, expected_release_key_sha256=expected_release_key_sha256
        )
        verifier._write_verification_receipt(staging, verification)
        verification_raw = read_regular(
            staging / "verification.json", MAX_JSON_BYTES, "persistent-image verification"
        )
        if verification_raw != canonical_json(verification):
            fail("persistent-image verifier retained noncanonical output")
        recomputed = verifier.verify_evidence(
            staging, expected_release_key_sha256=expected_release_key_sha256
        )
        if recomputed != verification:
            fail("persistent-image verification changed on immediate recomputation")
        if (
            not isinstance(verification.get("verification_id"), str)
            or not HEX_64.fullmatch(verification["verification_id"])
        ):
            fail("persistent-image verifier did not emit a canonical verification ID")
        observed, directories = _walk_regular_tree(staging, "verified evidence stage")
        if observed != sorted(EVIDENCE_FINAL_FILES) or directories:
            fail("verified evidence stage differs from the exact final file ledger")
        _fsync_directory(staging, strict=strict_durability)
        _rename_directory_no_replace(staging, output, strict=strict_durability)
        published = True
        _fsync_directory(parent, strict=strict_durability)
        final_observed, final_directories = _walk_regular_tree(output, "published evidence")
        if final_observed != sorted(EVIDENCE_FINAL_FILES) or final_directories:
            fail("published evidence exact ledger changed")
        result: dict[str, Any] = {
            "schema": PRODUCER_RESULT_SCHEMA,
            "source_commit": source_commit,
            "source_date_epoch": source_date_epoch,
            "toolchain_id": toolchain_id,
            "build_a_id": a.receipt_value["build_id"],
            "build_b_id": b.receipt_value["build_id"],
            "package_sha256": verification["package_sha256"],
            "package_bytes": verification["package_bytes"],
            "unsigned_package_sha256": sha256_bytes(package_a),
            "unsigned_package_bytes": len(package_a),
            "post_ab_signing_id": verification["post_ab_signing_id"],
            "verification_id": verification["verification_id"],
            "evidence_files": [
                {
                    "path": name,
                    "sha256": sha256_bytes(
                        read_regular(
                            output / name,
                            MAX_PACKAGE_BYTES if name.endswith(".tar") else MAX_RECEIPT_BYTES,
                            f"published {name}",
                        )
                    ),
                    "bytes": os.lstat(output / name).st_size,
                }
                for name in EVIDENCE_FINAL_FILES
            ],
            "persistent_image_evidence_verified": True,
            "production_ready": False,
            "install_authority_granted": False,
            "flash_authority_granted": False,
            "mutation_authority_granted": False,
            "live_hardware_contact_status": (
                "not-proven-absent-during-unrestricted-source-fetch-bridge"
            ),
        }
        result["producer_result_id"] = sha256_bytes(canonical_json(result))
        return result
    except Exception:
        if not published:
            # Staging is invocation-owned and contains no unenumerated children;
            # remove only its exact observed files.  A malformed/unreadable stage
            # is deliberately retained for operator recovery instead of broad
            # recursive deletion.
            try:
                files, directories = _walk_regular_tree(staging, "failed evidence stage")
                if not directories and set(files).issubset(EVIDENCE_FINAL_FILES):
                    for relative in files:
                        (staging / relative).unlink()
                    staging.rmdir()
            except (OSError, ProducerError):
                pass
        raise


def parser() -> argparse.ArgumentParser:
    top = argparse.ArgumentParser(description=__doc__)
    commands = top.add_subparsers(dest="command", required=True)
    materializer_verify = commands.add_parser("verify-materializer")
    materializer_verify.add_argument("--receipt", type=Path, required=True)
    materializer_verify.add_argument(
        "--dependency-descriptor", type=Path, required=True
    )
    materializer_verify.add_argument("--expected-source-commit")
    materializer_verify.add_argument("--expected-builder-image")
    materializer_verify.add_argument("--expected-toolchain-id")
    seal = commands.add_parser("seal-dependencies")
    seal.add_argument("--materialized-root", type=Path, required=True)
    seal.add_argument("--selection", type=Path, required=True)
    seal.add_argument("--policy", type=Path, required=True)
    seal.add_argument("--stage-parent", type=Path, required=True)
    seal.add_argument("--expected-source-commit", required=True)
    seal.add_argument("--expected-builder-image", required=True)
    seal.add_argument("--expected-toolchain-id", required=True)
    verify = commands.add_parser("verify-dependencies")
    verify.add_argument("--descriptor", type=Path, required=True)
    verify.add_argument("--expected-source-commit")
    verify.add_argument("--expected-builder-image")
    verify.add_argument("--expected-toolchain-id")
    destroy = commands.add_parser("destroy-dependencies")
    destroy.add_argument("--descriptor", type=Path, required=True)
    destroy.add_argument("--token", required=True)
    release_seal = commands.add_parser("seal-release-inputs")
    release_seal.add_argument("--public-key", type=Path, required=True)
    release_seal.add_argument("--native-owner-receipt", type=Path, required=True)
    release_seal.add_argument("--stock-recovery-receipt", type=Path, required=True)
    release_seal.add_argument("--stage-parent", type=Path, required=True)
    release_seal.add_argument("--expected-release-key-sha256", required=True)
    release_verify = commands.add_parser("verify-release-inputs")
    release_verify.add_argument("--descriptor", type=Path, required=True)
    release_verify.add_argument("--expected-release-key-sha256", required=True)
    release_destroy = commands.add_parser("destroy-release-inputs")
    release_destroy.add_argument("--descriptor", type=Path, required=True)
    release_destroy.add_argument("--token", required=True)
    release_destroy.add_argument("--expected-release-key-sha256", required=True)
    build_destroy = commands.add_parser("destroy-build-root")
    build_destroy.add_argument("--root", type=Path, required=True)
    build_destroy.add_argument("--token", required=True)
    commands.add_parser(
        "produce",
        help=(
            "fail closed: production orchestration is import-only and requires "
            "one typed out-of-band TrustedCampaignPin"
        ),
    )
    return top


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "verify-materializer":
            result = verify_materializer_receipt(
                args.receipt,
                args.dependency_descriptor,
                expected_source_commit=args.expected_source_commit,
                expected_builder_image=args.expected_builder_image,
                expected_toolchain_id=args.expected_toolchain_id,
            )
        elif args.command == "seal-dependencies":
            if os.name == "nt":
                fail("production dependency sealing must run inside Linux/WSL")
            bundle = seal_dependency_bundle(
                args.materialized_root,
                args.selection,
                args.policy,
                args.stage_parent,
                expected_source_commit=args.expected_source_commit,
                expected_builder_image=args.expected_builder_image,
                expected_toolchain_id=args.expected_toolchain_id,
            )
            result = {
                "stage": os.fspath(bundle.stage),
                "descriptor": os.fspath(bundle.descriptor),
                "inputs": os.fspath(bundle.inputs),
                "destroy_token": bundle.destroy_token,
                "bundle_id": bundle.bundle_id,
            }
        elif args.command == "verify-dependencies":
            result = verify_dependency_bundle(
                args.descriptor,
                expected_source_commit=args.expected_source_commit,
                expected_builder_image=args.expected_builder_image,
                expected_toolchain_id=args.expected_toolchain_id,
            )
        elif args.command == "destroy-dependencies":
            destroy_dependency_bundle(args.descriptor, args.token)
            result = {"destroyed": True}
        elif args.command == "seal-release-inputs":
            if os.name == "nt":
                fail("production release-input sealing must run inside Linux/WSL")
            sealed = seal_release_inputs(
                args.public_key,
                args.native_owner_receipt,
                args.stock_recovery_receipt,
                args.stage_parent,
                expected_release_key_sha256=args.expected_release_key_sha256,
            )
            result = {
                "stage": os.fspath(sealed.stage),
                "descriptor": os.fspath(sealed.descriptor),
                "destroy_token": sealed.destroy_token,
                "input_id": sealed.input_id,
            }
        elif args.command == "verify-release-inputs":
            result = verify_release_inputs(
                args.descriptor,
                expected_release_key_sha256=args.expected_release_key_sha256,
            )
        elif args.command == "destroy-release-inputs":
            destroy_release_inputs(
                args.descriptor,
                args.token,
                expected_release_key_sha256=args.expected_release_key_sha256,
            )
            result = {"destroyed": True}
        elif args.command == "destroy-build-root":
            destroy_build_root(args.root, args.token)
            result = {"destroyed": True}
        elif args.command == "produce":
            fail(
                "production produce is import-only until one typed out-of-band "
                "TrustedCampaignPin admits source authority, its validator is loaded "
                "from once-opened pinned bytes, and an approved dependency bundle and "
                "dedicated signer boundary are joined; caller-selected CLI policy "
                "leaves are forbidden"
            )
        else:
            fail(f"unsupported producer command: {args.command}")
        print(canonical_json(result).decode("ascii"), end="")
        return 0
    except (
        OSError,
        ProducerError,
        subprocess.SubprocessError,
        TypeError,
        ValueError,
    ) as error:
        print(f"S19K_HERMETIC_IMAGE_REFUSED: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
