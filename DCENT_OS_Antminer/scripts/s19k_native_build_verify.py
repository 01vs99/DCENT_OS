#!/usr/bin/env python3
"""Project an exact-snapshot capsule build into an S19k native-owner receipt.

Version 4 deliberately refuses mutable-checkout build claims. It consumes the
existing schema-v4 binary build receipt, checks that its complete source
inventory is the exact content of one authenticated Git commit, validates the
target-specific Cargo dependency closure, binds the resulting AArch64 ELF, and
requires the same canonical Ed25519 manifest public-key pin in both recorded
build environments.
It also records the real network boundary: Cargo compilation uses `--offline`,
but builder bootstrap and the preceding locked dependency fetch may use a live
network namespace. Network activity is not measured, so non-use is unproven.

The receipt remains a post-build consistency record. It does not prove that a
compiler consumed the declared inputs, that two builds are reproducible, or
that release, installation, live-contact, or mutation authority exists.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import tempfile
from typing import Any, Mapping, NoReturn, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent.parent
SCHEMA = "dcentos.s19k-native-release-link-candidate/v4"
CLAIM = (
    "exact-snapshot-capsule-linked-manifest-key-pinned-network-enabled-bootstrap-"
    "candidate-not-build-causality-reproducibility-signed-release-live-or-install-"
    "authority-proof"
)
TARGET = "aarch64-unknown-linux-musl"
PROFILE = "release"
BUILD_VARIANT = "amlogic"
CARGO_COMMAND = (
    "cargo build --release --locked --offline --target "
    "aarch64-unknown-linux-musl"
)
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
CAPSULE_RECEIPT_SCHEMA = 4
CAPSULE_RECEIPT_CLAIM = (
    "declared-release-capsule-and-post-build-snapshot-consistency-"
    "not-build-causality-or-reproducibility-proof"
)
ZIG_VERSION = "0.13.0"
ZIG_ARCHIVE_SHA256 = (
    "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea"
)
BUILDER_PACKAGE_RESOLUTION = "official-zig-0.13.0-sha256-d45312e6"
RUSTFLAGS = (
    "-C link-arg=-s -C target-cpu=cortex-a53 "
    "-C target-feature=+crt-static"
)
ADOPTED_ROUTE_ARTIFACT_SHA256S = {
    "fbd730e5c189cc69d5a191fd3bffdba3f2401e171d24e36e3d86b0d38dc0967b",
    "9570a9fcd8e8a2cff6f3d21902f6354666c5b337b7b260641e5b0baf9260b4d6",
}
SEMANTIC_SOURCE_PATHS = (
    "DCENT_OS_Antminer/dcentrald/dcentrald-common/src/s19k_bm1366_nopic_beta.rs",
    "DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs",
    "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining.rs",
    "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining/s19k_native_identity.rs",
    "DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/i2c.rs",
    "DCENT_OS_Antminer/dcentrald/rust-toolchain.toml",
    "DCENT_OS_Antminer/dcentrald/.cargo/config.toml",
    "DCENT_OS_Antminer/dcentrald/Cargo.lock",
    "DCENT_OS_Antminer/dcentrald/zig-cc-aarch64.sh",
    "DCENT_OS_Antminer/dcentrald/zig-ar-aarch64.sh",
    "DCENT_OS_Antminer/scripts/s19k_aarch64_compile_check.sh",
    "DCENT_OS_Antminer/scripts/s19k_native_build_verify.py",
)
AARCH64_COMPILE_CONTRACT = {
    "status": "exact-snapshot-capsule-bound",
    "target": TARGET,
    "rust_toolchain": "1.90.0",
    "zig_version": ZIG_VERSION,
    "zig_archive_sha256": ZIG_ARCHIVE_SHA256,
    "cargo_locked": True,
    "cargo_offline": True,
    "immutable_builder_required": True,
    "fresh_result_root_required": True,
    "release_link_required": True,
}
NETWORK_CONTRACT = {
    "scope": "entire-capsule-invocation",
    "builder_materialization_network": "permitted",
    "dependency_prefetch_network": "permitted",
    "compile_container_network_namespace": "enabled",
    "cargo_locked": True,
    "cargo_compile_offline_flag": True,
    "network_observation": "not-measured",
    "network_nonuse_proven": False,
}
LOCAL_PACKAGE_MANIFESTS = {
    "dcent-schema": "projects/dcent-schema/Cargo.toml",
    "dcentrald": "DCENT_OS_Antminer/dcentrald/dcentrald/Cargo.toml",
    "dcentrald-api": "DCENT_OS_Antminer/dcentrald/dcentrald-api/Cargo.toml",
    "dcentrald-api-grpc": "DCENT_OS_Antminer/dcentrald/dcentrald-api-grpc/Cargo.toml",
    "dcentrald-api-types": "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/Cargo.toml",
    "dcentrald-asic": "DCENT_OS_Antminer/dcentrald/dcentrald-asic/Cargo.toml",
    "dcentrald-autotuner": "DCENT_OS_Antminer/dcentrald/dcentrald-autotuner/Cargo.toml",
    "dcentrald-bridge": "DCENT_OS_Antminer/dcentrald/dcentrald-bridge/Cargo.toml",
    "dcentrald-chip-analysis": (
        "DCENT_OS_Antminer/dcentrald/dcentrald-chip-analysis/Cargo.toml"
    ),
    "dcentrald-common": "DCENT_OS_Antminer/dcentrald/dcentrald-common/Cargo.toml",
    "dcentrald-diagnostics": (
        "DCENT_OS_Antminer/dcentrald/dcentrald-diagnostics/Cargo.toml"
    ),
    "dcentrald-fabric-lease": (
        "DCENT_OS_Antminer/dcentrald/dcentrald-fabric-lease/Cargo.toml"
    ),
    "dcentrald-hal": "DCENT_OS_Antminer/dcentrald/dcentrald-hal/Cargo.toml",
    "dcentrald-silicon-profiles": (
        "DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/Cargo.toml"
    ),
    "dcentrald-stratum": "DCENT_OS_Antminer/dcentrald/dcentrald-stratum/Cargo.toml",
    "dcentrald-thermal": "DCENT_OS_Antminer/dcentrald/dcentrald-thermal/Cargo.toml",
}
COMPILE_ENVIRONMENT = {
    "AR_aarch64_unknown_linux_musl": "/usr/local/bin/zig-ar",
    "CARGO_BUILD_JOBS": "2",
    "CARGO_BUILD_PROFILE": "release",
    "CARGO_INCREMENTAL": "0",
    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER": "rust-lld",
    "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS": "-C linker=rust-lld",
    "CARGO_TARGET_DIR": "/cargo-target",
    "CC_aarch64_unknown_linux_musl": "/usr/local/bin/zig-cc-target-musl",
    "DCENT_BUILDER_KIND": "docker-cross",
    "DCENT_BUILDER_PACKAGE_RESOLUTION": BUILDER_PACKAGE_RESOLUTION,
    "RUSTFLAGS": RUSTFLAGS,
}
RECEIPT_KEYS = {
    "schema",
    "claim",
    "classification",
    "target_triple",
    "cargo_profile",
    "cargo_command",
    "artifact",
    "semantic_source_files",
    "semantic_source_files_sha256",
    "aarch64_compile_contract",
    "compile_contract_sha256",
    "capsule_build_receipt",
    "capsule_build_receipt_sha256",
    "local_dependency_closure",
    "manifest_public_key_hex",
    "manifest_public_key_sha256",
    "network_nonuse_proven",
    "network_contract",
    "release_authority_granted",
    "installation_authority_granted",
    "live_hardware_contacted",
    "verification_id",
}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GIT_HEX = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
DIGEST_REFERENCE = re.compile(r"(?:[^/@]+/)*[^/@]+@sha256:[0-9a-f]{64}\Z")


class NativeBuildError(ValueError):
    """Native build evidence is absent, unsafe, stale, or overclaimed."""


def fail(message: str) -> NoReturn:
    raise NativeBuildError(message)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex64(value: Any, label: str) -> str:
    if not isinstance(value, str) or HEX64.fullmatch(value) is None:
        fail(f"{label} is not a canonical SHA-256 identity")
    return value


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        fail(f"cannot inspect {label}: {error}")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        fail(f"{label} must be a regular non-symlink file")
    if before.st_size <= 0 or before.st_size > maximum:
        fail(f"{label} has an invalid byte count")
    data = path.read_bytes()
    after = path.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )
    if identity_before != identity_after or len(data) != before.st_size:
        fail(f"{label} changed while it was read")
    return data


def _json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict ASCII JSON: {error}")
    if not isinstance(value, dict) or data != canonical_json(value):
        fail(f"{label} is not a canonical JSON object")
    return value


def _artifact(path: Path) -> tuple[bytes, dict[str, Any]]:
    data = _read_regular(path, MAX_ARTIFACT_BYTES, "native release artifact")
    if (
        len(data) < 64
        or data[:7] != b"\x7fELF\x02\x01\x01"
        or struct.unpack_from("<H", data, 18)[0] != 183
        or struct.unpack_from("<H", data, 16)[0] not in (2, 3)
    ):
        fail("native release artifact is not an AArch64 executable/shared ELF")
    sha256 = digest(data)
    if sha256 in ADOPTED_ROUTE_ARTIFACT_SHA256S:
        fail("native release artifact reuses an older adopted-route binary")
    return data, {"path": "dcentrald", "sha256": sha256, "bytes": len(data)}


def _load_binary_receipt_module() -> Any:
    path = SCRIPT_DIR / "binary_build_receipt.py"
    spec = importlib.util.spec_from_file_location("s19k_binary_build_receipt", path)
    if spec is None or spec.loader is None:
        fail("cannot load capsule binary-build receipt verifier")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as error:
        fail(f"cannot initialize capsule binary-build receipt verifier: {error}")
    return module


def _safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        fail(f"{label} is not a canonical relative POSIX path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or any(
        part in ("", ".", "..") for part in path.parts
    ):
        fail(f"{label} is not a canonical relative POSIX path")
    return value


def _source_inventory(capsule: Mapping[str, Any]) -> list[dict[str, Any]]:
    inventory = capsule.get("source_inventory")
    if not isinstance(inventory, list) or not inventory:
        fail("capsule build receipt lacks a source inventory")
    result: list[dict[str, Any]] = []
    previous = ""
    accumulator = hashlib.sha256()
    for index, item in enumerate(inventory):
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
            fail(f"capsule source inventory item {index} is malformed")
        path = _safe_relative(item.get("path"), f"capsule source path {index}")
        size = item.get("size")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            fail(f"capsule source size {path} is invalid")
        sha256 = _hex64(item.get("sha256"), f"capsule source SHA-256 {path}")
        if path <= previous:
            fail("capsule source inventory is not uniquely sorted")
        previous = path
        accumulator.update(f"{path}\0{size}\0{sha256}\n".encode("utf-8"))
        result.append({"path": path, "size": size, "sha256": sha256})
    if capsule.get("source_inventory_sha256") != accumulator.hexdigest():
        fail("capsule source inventory digest is stale")
    return result


def _run(repo_root: Path, *arguments: str, input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            arguments,
            cwd=repo_root,
            input=input_data,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"command failed while verifying capsule source: {arguments[0]}: {error}")
    return result.stdout


def _verify_inventory_against_git(
    repo_root: Path, commit: str, inventory: Sequence[Mapping[str, Any]]
) -> str:
    if not isinstance(commit, str) or GIT_HEX.fullmatch(commit) is None:
        fail("capsule source commit is not an exact Git object id")
    observed_commit = _run(repo_root, "git", "rev-parse", f"{commit}^{{commit}}")
    if observed_commit.decode("ascii").strip() != commit:
        fail("capsule source commit is not available as the exact Git object")
    root_tree = _run(repo_root, "git", "rev-parse", f"{commit}^{{tree}}")
    root_tree_text = root_tree.decode("ascii").strip()
    if GIT_HEX.fullmatch(root_tree_text) is None:
        fail("capsule source tree identity is invalid")
    listing = _run(repo_root, "git", "ls-tree", "-r", "-z", "--full-tree", commit)
    objects: dict[str, tuple[str, str]] = {}
    try:
        entries = [entry for entry in listing.split(b"\0") if entry]
        for entry in entries:
            header, raw_path = entry.split(b"\t", 1)
            mode, object_type, oid = header.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
            objects[path] = (mode, oid if object_type == "blob" else "")
    except (UnicodeDecodeError, ValueError) as error:
        fail(f"Git tree listing is malformed: {error}")
    requested: list[tuple[str, Mapping[str, Any]]] = []
    for item in inventory:
        path = str(item["path"])
        entry = objects.get(path)
        if entry is None or entry[0] not in ("100644", "100755") or not entry[1]:
            fail(f"capsule source inventory path is absent/non-regular in Git: {path}")
        requested.append((entry[1], item))
    try:
        process = subprocess.Popen(
            ("git", "cat-file", "--batch"),
            cwd=repo_root,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as error:
        fail(f"cannot start Git object reader: {error}")
    assert process.stdin is not None and process.stdout is not None
    try:
        for start in range(0, len(requested), 32):
            chunk = requested[start : start + 32]
            process.stdin.write(
                b"".join(oid.encode("ascii") + b"\n" for oid, _ in chunk)
            )
            process.stdin.flush()
            for expected_oid, item in chunk:
                header = process.stdout.readline(256)
                fields = header.rstrip(b"\n").split(b" ")
                if len(fields) != 3:
                    fail("Git object reader returned a malformed header")
                oid, object_type, raw_size = fields
                if oid.decode("ascii") != expected_oid or object_type != b"blob":
                    fail("Git object reader returned a different object")
                size = int(raw_size)
                data = process.stdout.read(size)
                terminator = process.stdout.read(1)
                if len(data) != size or terminator != b"\n":
                    fail("Git object reader truncated a source blob")
                if size != item["size"] or digest(data) != item["sha256"]:
                    fail(f"capsule source inventory disagrees with Git: {item['path']}")
        process.stdin.close()
        returncode = process.wait(timeout=30)
        if returncode:
            fail("Git object reader failed while verifying source inventory")
    except BaseException:
        if process.poll() is None:
            process.kill()
        process.wait()
        raise
    finally:
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    return root_tree_text


def _context_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, dict) or set(value) not in (
        {"path", "sha256", "size", "lines"},
        {"path", "sha256", "size", "lines", "entries"},
    ):
        fail(f"capsule {label} has an invalid exact schema")
    lines = value.get("lines")
    if not isinstance(lines, list) or not lines or any(
        not isinstance(line, str) or "\n" in line or "\r" in line for line in lines
    ):
        fail(f"capsule {label} lines are invalid")
    data = ("\n".join(lines) + "\n").encode("utf-8")
    if value.get("size") != len(data) or value.get("sha256") != digest(data):
        fail(f"capsule {label} byte identity is stale")
    return data


def _validate_capsule_build_receipt(
    capsule: Mapping[str, Any], artifact: Mapping[str, Any], repo_root: Path
) -> tuple[list[dict[str, Any]], str, str]:
    binary_receipt = _load_binary_receipt_module()
    try:
        binary_receipt.validate_v4_receipt_shape(capsule, "S19k capsule build receipt")
        binary_receipt.require_immutable_docker_builder(capsule.get("builder"))
    except Exception as error:
        fail(f"capsule build receipt failed schema-v4 admission: {error}")
    binary = capsule.get("binary")
    if (
        not isinstance(binary, dict)
        or set(binary) != {"name", "path", "sha256", "size"}
        or binary.get("name") != "dcentrald"
        or binary.get("sha256") != artifact["sha256"]
        or binary.get("size") != artifact["bytes"]
        or not str(binary.get("path", "")).endswith("/dcentrald")
    ):
        fail("capsule build receipt does not bind the exact dcentrald artifact")
    git = capsule.get("git")
    if (
        not isinstance(git, dict)
        or set(git) != {"commit", "source_kind"}
        or git.get("source_kind") != "exact-git-object-snapshot"
    ):
        fail("capsule build receipt is not sourced from an exact Git snapshot")
    if (
        capsule.get("schema_version") != CAPSULE_RECEIPT_SCHEMA
        or capsule.get("claim") != CAPSULE_RECEIPT_CLAIM
        or capsule.get("target_triple") != TARGET
        or capsule.get("profile") != PROFILE
        or capsule.get("build_variant") != BUILD_VARIANT
    ):
        fail("capsule build receipt target/profile/environment is not exact")
    builder = capsule["builder"]
    if (
        builder.get("package_resolution") != BUILDER_PACKAGE_RESOLUTION
        or DIGEST_REFERENCE.fullmatch(str(builder.get("base_reference", ""))) is None
        or re.fullmatch(r"sha256:[0-9a-f]{64}", str(builder.get("image_id", "")))
        is None
    ):
        fail("capsule build receipt builder is not immutable and pinned")
    manifest_public_key_hex = _manifest_key_contract(capsule, builder)
    toolchain = capsule.get("toolchain_context")
    _context_bytes(toolchain, "toolchain context")
    lines = toolchain["lines"]
    required_lines = {
        "release: 1.90.0",
        f"builder_base_reference={builder['base_reference']}",
        f"builder_image_id={builder['image_id']}",
        f"builder_package_resolution={BUILDER_PACKAGE_RESOLUTION}",
        f"zig_version={ZIG_VERSION}",
        f"zig_archive_sha256={ZIG_ARCHIVE_SHA256}",
    }
    if not required_lines.issubset(set(lines)) or not any(
        line.startswith("cargo 1.90.0 ") for line in lines
    ):
        fail("capsule toolchain context is not the pinned Rust/Zig/builder contract")
    inventory = _source_inventory(capsule)
    root_tree = _verify_inventory_against_git(repo_root, git["commit"], inventory)
    return inventory, root_tree, manifest_public_key_hex


def _manifest_key_contract(
    capsule: Mapping[str, Any], builder: Mapping[str, Any]
) -> str:
    """Return the one key pin shared by generic and compile environments."""
    build_environment = capsule.get("build_environment")
    if (
        not isinstance(build_environment, dict)
        or set(build_environment)
        != {"DCENT_MANIFEST_KEY_ID", "DCENT_MANIFEST_PUBLIC_KEY_HEX"}
    ):
        fail("capsule build manifest-key environment is not exact")
    manifest_key_id = build_environment.get("DCENT_MANIFEST_KEY_ID")
    manifest_public_key_hex = build_environment.get(
        "DCENT_MANIFEST_PUBLIC_KEY_HEX"
    )
    if manifest_key_id != "":
        fail("capsule manifest key ID policy is not the exact empty value")
    if (
        not isinstance(manifest_public_key_hex, str)
        or HEX64.fullmatch(manifest_public_key_hex) is None
    ):
        fail("capsule manifest public key is not canonical lowercase 64-hex")
    compile_environment = capsule.get("compile_environment")
    _context_bytes(compile_environment, "compile environment")
    entries = compile_environment.get("entries")
    expected_environment = {
        **COMPILE_ENVIRONMENT,
        "DCENT_BUILDER_BASE_REFERENCE": builder.get("base_reference"),
        "DCENT_BUILDER_IMAGE_ID": builder.get("image_id"),
        "DCENT_MANIFEST_KEY_ID": manifest_key_id,
        "DCENT_MANIFEST_PUBLIC_KEY_HEX": manifest_public_key_hex,
    }
    if entries != dict(sorted(expected_environment.items())):
        fail("capsule compile environment is not the exact sanitized AArch64 contract")
    return manifest_public_key_hex


CAPSULE_WORKSPACE_MOUNT = "/src"
CAPSULE_SCHEMA_MOUNT = "/dcent-schema"
HOST_WORKSPACE_PREFIX = "DCENT_OS_Antminer/dcentrald"
HOST_SCHEMA_PREFIX = "projects/dcent-schema"


def _admit_capsule_metadata_layout(
    metadata: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Translate the exact read-only container mounts the capsule builder
    uses (/src workspace, /dcent-schema path dependency) to their repository
    layout before the workspace/manifest checks run. Any local package
    outside those two mounts fails closed; every other layout passes
    through unchanged and is judged by the existing host-path rules."""
    if metadata.get("workspace_root") != CAPSULE_WORKSPACE_MOUNT:
        return metadata
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        fail("Cargo metadata capsule layout lacks a package list")
    translated: list[Mapping[str, Any]] = []
    for package in packages:
        if not isinstance(package, dict) or package.get("source") is not None:
            translated.append(package)
            continue
        manifest = package.get("manifest_path")
        if not isinstance(manifest, str) or "\\" in manifest:
            fail("Cargo package manifest_path is invalid")
        if manifest == CAPSULE_WORKSPACE_MOUNT or manifest.startswith(
            CAPSULE_WORKSPACE_MOUNT + "/"
        ):
            rest = manifest[len(CAPSULE_WORKSPACE_MOUNT) :].lstrip("/")
            host = (
                f"{HOST_WORKSPACE_PREFIX}/{rest}"
                if rest
                else HOST_WORKSPACE_PREFIX
            )
        elif manifest.startswith(CAPSULE_SCHEMA_MOUNT + "/"):
            host = (
                f"{HOST_SCHEMA_PREFIX}/"
                f"{manifest[len(CAPSULE_SCHEMA_MOUNT) + 1 :]}"
            )
        else:
            fail(
                "Cargo capsule local package escapes the admitted /src and "
                "/dcent-schema mounts"
            )
        rewritten = dict(package)
        rewritten["manifest_path"] = host
        translated.append(rewritten)
    adjusted = dict(metadata)
    adjusted["workspace_root"] = HOST_WORKSPACE_PREFIX
    adjusted["packages"] = translated
    return adjusted


def _repo_root_from_metadata(metadata: Mapping[str, Any]) -> PurePosixPath:
    workspace = metadata.get("workspace_root")
    if not isinstance(workspace, str) or "\\" in workspace:
        fail("Cargo metadata workspace_root is invalid")
    path = PurePosixPath(workspace)
    suffix = PurePosixPath("DCENT_OS_Antminer/dcentrald")
    if tuple(path.parts[-len(suffix.parts) :]) != suffix.parts:
        fail("Cargo metadata workspace_root is not the capsule dcentrald workspace")
    return PurePosixPath(*path.parts[: -len(suffix.parts)])


def _normalize_manifest(path_value: Any, repo_root: PurePosixPath) -> str:
    if not isinstance(path_value, str) or "\\" in path_value:
        fail("Cargo package manifest_path is invalid")
    path = PurePosixPath(path_value)
    try:
        relative = path.relative_to(repo_root)
    except ValueError:
        fail("Cargo local package escapes the authenticated source snapshot")
    return _safe_relative(relative.as_posix(), "Cargo local manifest path")


def _dependency_closure(metadata_data: bytes) -> dict[str, Any]:
    try:
        metadata = json.loads(metadata_data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"Cargo metadata is invalid JSON: {error}")
    if not isinstance(metadata, dict) or metadata.get("version") != 1:
        fail("Cargo metadata schema is not format-version 1")
    metadata = _admit_capsule_metadata_layout(metadata)
    packages = metadata.get("packages")
    resolve = metadata.get("resolve")
    if not isinstance(packages, list) or not isinstance(resolve, dict):
        fail("Cargo metadata lacks packages/resolve graph")
    by_id: dict[str, Mapping[str, Any]] = {}
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("id"), str):
            fail("Cargo metadata contains a malformed package")
        by_id[package["id"]] = package
    root_id = next(
        (
            package_id
            for package_id, package in by_id.items()
            if package.get("name") == "dcentrald" and package.get("source") is None
        ),
        None,
    )
    nodes = resolve.get("nodes")
    if root_id is None or not isinstance(nodes, list):
        fail("Cargo metadata lacks the local dcentrald root/resolve nodes")
    node_by_id = {
        node.get("id"): node
        for node in nodes
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    pending = [root_id]
    reached: set[str] = set()
    while pending:
        package_id = pending.pop()
        if package_id in reached:
            continue
        reached.add(package_id)
        node = node_by_id.get(package_id)
        if not isinstance(node, dict):
            fail("Cargo metadata resolve graph omits a reached package")
        deps = node.get("deps")
        if not isinstance(deps, list):
            fail("Cargo metadata dependency list is malformed")
        for dependency in deps:
            if not isinstance(dependency, dict) or not isinstance(
                dependency.get("pkg"), str
            ):
                fail("Cargo metadata dependency edge is malformed")
            kinds = dependency.get("dep_kinds")
            if not isinstance(kinds, list) or not kinds:
                fail("Cargo metadata dependency edge lacks dependency kinds")
            if all(
                isinstance(kind, dict) and kind.get("kind") == "dev" for kind in kinds
            ):
                continue
            pending.append(dependency["pkg"])
    repository_root = _repo_root_from_metadata(metadata)
    local: list[dict[str, str]] = []
    for package_id in reached:
        package = by_id.get(package_id)
        if package is None:
            fail("Cargo metadata resolve graph references an unknown package")
        if package.get("source") is not None:
            continue
        name = package.get("name")
        version = package.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            fail("Cargo local package name/version is invalid")
        manifest = _normalize_manifest(package.get("manifest_path"), repository_root)
        local.append(
            {
                "name": name,
                "version": version,
                "manifest_path": manifest,
                "package_root": str(PurePosixPath(manifest).parent),
            }
        )
    local.sort(key=lambda item: item["manifest_path"])
    observed = {item["name"]: item["manifest_path"] for item in local}
    if observed != LOCAL_PACKAGE_MANIFESTS or len(local) != len(observed):
        fail(
            "Cargo local dependency closure is not the exact 16-package "
            "S19k AArch64 production closure"
        )
    root_package = next(item for item in local if item["name"] == "dcentrald")
    return {
        "cargo_metadata_sha256": digest(metadata_data),
        "target_triple": TARGET,
        "root_package_id": (
            f"{root_package['name']} {root_package['version']} "
            f"({root_package['package_root']})"
        ),
        "packages": local,
        "external_local_paths_inside_snapshot": True,
    }


def _semantic_sources(inventory: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_path = {item["path"]: item for item in inventory}
    result = []
    for path in SEMANTIC_SOURCE_PATHS:
        item = by_path.get(path)
        if item is None:
            fail(f"capsule source inventory omits semantic owner source: {path}")
        result.append(
            {"path": path, "sha256": item["sha256"], "bytes": item["size"]}
        )
    return result


def make_receipt(
    artifact_path: Path,
    *,
    capsule_build_receipt: Mapping[str, Any],
    cargo_metadata_data: bytes,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    _, artifact = _artifact(artifact_path)
    inventory, _, manifest_public_key_hex = _validate_capsule_build_receipt(
        capsule_build_receipt, artifact, repo_root
    )
    cargo_identity = capsule_build_receipt.get("cargo_metadata")
    if (
        not isinstance(cargo_identity, dict)
        or set(cargo_identity) != {"path", "sha256", "size"}
        or cargo_identity.get("sha256") != digest(cargo_metadata_data)
        or cargo_identity.get("size") != len(cargo_metadata_data)
    ):
        fail("Cargo metadata bytes do not match the capsule build receipt")
    source_files = _semantic_sources(inventory)
    closure = _dependency_closure(cargo_metadata_data)
    capsule_copy = json.loads(canonical_json(capsule_build_receipt).decode("ascii"))
    result: dict[str, Any] = {
        "schema": SCHEMA,
        "claim": CLAIM,
        "classification": "exact-snapshot-capsule-linked-manifest-key-pinned-candidate",
        "target_triple": TARGET,
        "cargo_profile": PROFILE,
        "cargo_command": CARGO_COMMAND,
        "artifact": artifact,
        "semantic_source_files": source_files,
        "semantic_source_files_sha256": digest(canonical_json(source_files)),
        "aarch64_compile_contract": AARCH64_COMPILE_CONTRACT,
        "compile_contract_sha256": digest(canonical_json(AARCH64_COMPILE_CONTRACT)),
        "capsule_build_receipt": capsule_copy,
        "capsule_build_receipt_sha256": digest(canonical_json(capsule_copy)),
        "local_dependency_closure": closure,
        "manifest_public_key_hex": manifest_public_key_hex,
        "manifest_public_key_sha256": digest(bytes.fromhex(manifest_public_key_hex)),
        "network_nonuse_proven": False,
        "network_contract": NETWORK_CONTRACT,
        "release_authority_granted": False,
        "installation_authority_granted": False,
        "live_hardware_contacted": False,
    }
    result["verification_id"] = digest(canonical_json(result))
    return result


def verify_receipt(
    receipt_path: Path,
    artifact_path: Path,
    *,
    repo_root: Path = REPO_ROOT,
    require_clean: bool = False,
    source: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    del require_clean  # v2 authority is an immutable Git snapshot, never checkout state.
    data = _read_regular(receipt_path, MAX_JSON_BYTES, "native build receipt")
    value = _json_bytes(data, "native build receipt")
    if set(value) != RECEIPT_KEYS:
        fail("native build receipt key set is not exact")
    observed_id = _hex64(value.get("verification_id"), "native build verification_id")
    unsigned = dict(value)
    del unsigned["verification_id"]
    if observed_id != digest(canonical_json(unsigned)):
        fail("native build verification_id does not match canonical contents")
    _, artifact = _artifact(artifact_path)
    if value.get("artifact") != artifact:
        fail("native build receipt does not bind exact artifact bytes")
    capsule = value.get("capsule_build_receipt")
    if not isinstance(capsule, dict):
        fail("native build receipt lacks the capsule build receipt")
    inventory, _, manifest_public_key_hex = _validate_capsule_build_receipt(
        capsule, artifact, repo_root
    )
    source_files = _semantic_sources(inventory)
    if (
        value.get("semantic_source_files") != source_files
        or value.get("semantic_source_files_sha256")
        != digest(canonical_json(source_files))
        or value.get("capsule_build_receipt_sha256")
        != digest(canonical_json(capsule))
    ):
        fail("native build receipt does not bind the exact capsule source contract")
    if source is not None and source.get("source_files") != source_files:
        fail("native-owner semantic source audit disagrees with capsule snapshot")
    closure = value.get("local_dependency_closure")
    if not isinstance(closure, dict) or set(closure) != {
        "cargo_metadata_sha256",
        "target_triple",
        "root_package_id",
        "packages",
        "external_local_paths_inside_snapshot",
    }:
        fail("native build local dependency closure schema is not exact")
    packages = closure.get("packages")
    if not isinstance(packages, list) or len(packages) != len(LOCAL_PACKAGE_MANIFESTS):
        fail("native build local dependency closure count is not exact")
    observed_manifests: dict[str, str] = {}
    for item in packages:
        if not isinstance(item, dict) or set(item) != {
            "name",
            "version",
            "manifest_path",
            "package_root",
        }:
            fail("native build local dependency package is malformed")
        manifest = _safe_relative(item.get("manifest_path"), "local manifest path")
        if item.get("package_root") != str(PurePosixPath(manifest).parent):
            fail("native build local package root does not match its manifest")
        if not isinstance(item.get("name"), str) or not isinstance(
            item.get("version"), str
        ):
            fail("native build local package name/version is malformed")
        observed_manifests[item["name"]] = manifest
    if (
        observed_manifests != LOCAL_PACKAGE_MANIFESTS
        or closure.get("target_triple") != TARGET
        or closure.get("external_local_paths_inside_snapshot") is not True
        or HEX64.fullmatch(str(closure.get("cargo_metadata_sha256", ""))) is None
        or not str(closure.get("root_package_id", "")).startswith("dcentrald ")
        or capsule.get("cargo_metadata", {}).get("sha256")
        != closure.get("cargo_metadata_sha256")
    ):
        fail("native build local dependency closure is not exact")
    if (
        value.get("schema") != SCHEMA
        or value.get("claim") != CLAIM
        or value.get("classification")
        != "exact-snapshot-capsule-linked-manifest-key-pinned-candidate"
        or value.get("target_triple") != TARGET
        or value.get("cargo_profile") != PROFILE
        or value.get("cargo_command") != CARGO_COMMAND
        or value.get("aarch64_compile_contract") != AARCH64_COMPILE_CONTRACT
        or value.get("compile_contract_sha256")
        != digest(canonical_json(AARCH64_COMPILE_CONTRACT))
        or value.get("network_nonuse_proven") is not False
        or value.get("network_contract") != NETWORK_CONTRACT
        or value.get("manifest_public_key_hex") != manifest_public_key_hex
        or value.get("manifest_public_key_sha256")
        != digest(bytes.fromhex(manifest_public_key_hex))
        or value.get("release_authority_granted") is not False
        or value.get("installation_authority_granted") is not False
        or value.get("live_hardware_contacted") is not False
    ):
        fail("native build receipt metadata or authority boundary is not exact")
    return value


def stage_receipt(
    receipt_path: Path,
    artifact_path: Path,
    capsule_build_receipt_path: Path,
    cargo_metadata_path: Path,
    *,
    repo_root: Path = REPO_ROOT,
) -> dict[str, Any]:
    capsule_data = _read_regular(
        capsule_build_receipt_path, MAX_JSON_BYTES, "capsule build receipt"
    )
    capsule = _json_bytes(capsule_data, "capsule build receipt")
    metadata = _read_regular(cargo_metadata_path, MAX_JSON_BYTES, "Cargo metadata")
    result = make_receipt(
        artifact_path,
        capsule_build_receipt=capsule,
        cargo_metadata_data=metadata,
        repo_root=repo_root,
    )
    if receipt_path.exists() and receipt_path.is_symlink():
        fail("refusing symlink receipt destination")
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=receipt_path.parent,
        prefix=f".{receipt_path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        temporary = Path(handle.name)
        handle.write(canonical_json(result))
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.replace(temporary, receipt_path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    stage = sub.add_parser("stage")
    stage.add_argument("--artifact", type=Path, required=True)
    stage.add_argument("--receipt", type=Path, required=True)
    stage.add_argument("--capsule-build-receipt", type=Path, required=True)
    stage.add_argument("--cargo-metadata", type=Path, required=True)
    stage.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    verify = sub.add_parser("verify")
    verify.add_argument("--artifact", type=Path, required=True)
    verify.add_argument("--receipt", type=Path, required=True)
    verify.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    verify.add_argument("--require-clean", action="store_true")
    args = parser.parse_args(argv)
    try:
        repo_root = args.repo_root.resolve()
        artifact = args.artifact.resolve()
        receipt = args.receipt.absolute()
        if args.command == "stage":
            result = stage_receipt(
                receipt,
                artifact,
                args.capsule_build_receipt.resolve(),
                args.cargo_metadata.resolve(),
                repo_root=repo_root,
            )
        else:
            result = verify_receipt(
                receipt,
                artifact,
                repo_root=repo_root,
                require_clean=args.require_clean,
            )
    except (OSError, NativeBuildError) as error:
        print(f"S19K_NATIVE_BUILD_REFUSED: {error}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
