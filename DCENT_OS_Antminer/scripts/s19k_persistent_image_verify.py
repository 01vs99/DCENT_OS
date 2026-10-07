#!/usr/bin/env python3
"""Verify a reproducible, post-A/B-signed S19k rootfs-window image offline.

The evidence bundle contains two independently-attested *unsigned* package
builds plus one narrowly-derived signed package. This module compares complete
A/B bytes, proves the signed package differs only by the exact Ed25519 manifest
signature, opens the uImage/newc payload without extracting it, and binds exact
native-owner and tested stock-recovery receipts. It never contacts a target and
never grants install or NAND-mutation authority.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import sys
import tarfile
from typing import Any, Mapping, NoReturn, Sequence
import zlib


RESULT_SCHEMA = "dcentos.s19k-persistent-image-verification/v4"
CONTRACT_SCHEMA = "dcentos.s19k-persistent-image-build-contract/v3"
BUILD_SCHEMA = "dcentos.s19k-reproducible-build-attestation/v1"
SIGNING_RECEIPT_SCHEMA = "dcentos.s19k-hermetic-post-ab-signing/v1"
NATIVE_OWNER_SCHEMA = "dcentos.s19k-native-owner-implementation/v7"
NATIVE_BUILD_SCHEMA = "dcentos.s19k-native-release-link-candidate/v4"
NATIVE_BUILD_CLAIM = (
    "exact-snapshot-capsule-linked-manifest-key-pinned-network-enabled-bootstrap-"
    "candidate-not-build-causality-reproducibility-signed-release-live-or-install-"
    "authority-proof"
)
NATIVE_BUILD_COMMAND = (
    "cargo build --release --locked --offline --target "
    "aarch64-unknown-linux-musl"
)
RECOVERY_SCHEMA = "dcentos.s19k-persistent-recovery-verification/v1"
SOURCE_READINESS_SCHEMA = "dcentos.s19k-persistent-image-readiness/v2"
BOARD = "am3-s19k"
PREFIX = f"sysupgrade-{BOARD}"
BUILD_PACKAGE_FILES = ("build-a.unsigned.tar", "build-b.unsigned.tar")
BUILD_RECEIPT_FILES = ("build-a.json", "build-b.json")
SIGNED_PACKAGE_FILE = "dcentos-sysupgrade-am3-s19kpro.tar"
SIGNING_RECEIPT_FILE = "signing-receipt.json"
HOST_PREFLIGHT_FILE = "host-preflight.json"
SIGNER_RUNTIME_FILE = "signer-runtime.json"
SIGNER_INSPECT_BEFORE_FILE = "signer-inspect-before.json"
SIGNER_INSPECT_AFTER_FILE = "signer-inspect-after.json"
SIGNER_LOG_FILE = "signer.log"
TRUSTED_KEY_FILE = "trusted-release-key.pem"
NATIVE_RECEIPT_FILE = "native-owner-verification.json"
RECOVERY_RECEIPT_FILE = "stock-recovery-verification.json"
VERIFICATION_FILE = "verification.json"
PACKAGE_NATIVE_PATH = f"{PREFIX}/{NATIVE_RECEIPT_FILE}"
PACKAGE_RECOVERY_PATH = f"{PREFIX}/{RECOVERY_RECEIPT_FILE}"
PACKAGE_CONTRACT_PATH = f"{PREFIX}/IMAGE_CONTRACT.json"
PACKAGE_KEY_PATH = f"{PREFIX}/release_ed25519.pub"
PACKAGE_MANIFEST_PATH = f"{PREFIX}/MANIFEST.json"
PACKAGE_SIGNATURE_PATH = f"{PREFIX}/MANIFEST.sig"
PACKAGE_ROOT_PATH = f"{PREFIX}/root"
PACKAGE_KERNEL_PATH = f"{PREFIX}/kernel"
PACKAGE_METADATA_PATH = f"{PREFIX}/METADATA"
PACKAGE_SUMS_PATH = f"{PREFIX}/SHA256SUMS"
BUILDER_LEAF = "build_amlogic_native_install.sh"
WRITER_LEAF = "install_amlogic_persistent.sh"
PACKAGE_BUILDER_PATH = f"{PREFIX}/{BUILDER_LEAF}"
PACKAGE_WRITER_PATH = f"{PREFIX}/{WRITER_LEAF}"
ROOTFS_MTD = "/dev/mtd5"
ROOTFS_OFFSET_HEX = "0x05100000"
ROOTFS_WINDOW_HEX = "0x02800000"
ROOTFS_OFFSET_BYTES = 0x05100000
ROOTFS_WINDOW_BYTES = 0x02800000
ROOTFS_ERASE_SIZE = 131072
ROOTFS_ERASE_COUNT = 320
MAX_PACKAGE_BYTES = 128 * 1024 * 1024
MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_ROOTFS_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_ROOTFS_ENTRIES = 32768
MAX_ROOTFS_MEMBER_BYTES = 128 * 1024 * 1024
BUILD_KEYS = (
    "schema", "build_id", "build_root_id", "clean_build",
    "build_cache_reused", "network_used", "source_commit",
    "source_date_epoch", "build_target", "build_arch", "toolchain_id",
    "package_name", "package_sha256", "package_bytes",
)
SIGNING_RECEIPT_KEYS = (
    "schema", "build_a_package_sha256", "build_a_package_bytes",
    "build_b_package_sha256", "build_b_package_bytes",
    "unsigned_package_sha256", "unsigned_package_bytes",
    "signed_package_name", "signed_package_sha256", "signed_package_bytes",
    "manifest_sha256", "manifest_bytes", "manifest_signature_sha256",
    "manifest_signature_bytes", "release_key_sha256", "release_key_bytes",
    "source_commit", "source_date_epoch", "build_target", "build_arch",
    "toolchain_id", "a_b_equality_verified_before_private_key_open",
    "public_inputs_verified_before_private_key_open", "private_key_open_count",
    "derivation", "output_no_replace", "network_used",
    "install_authority_granted", "flash_authority_granted",
    "mutation_authority_granted", "signing_id",
)
NATIVE_PREREQUISITES = {
    "native-secure-firmware-re", "native-hardware-contract", "adopted-endurance",
    "native-build-reproducibility",
}
NATIVE_SOURCE_PATHS = (
    "DCENT_OS_Antminer/dcentrald/dcentrald-common/src/s19k_bm1366_nopic_beta.rs",
    "DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/platform/amlogic/mod.rs",
    "DCENT_OS_Antminer/dcentrald/dcentrald/src/serial_mining.rs",
    "DCENT_OS_Antminer/dcentrald/rust-toolchain.toml",
    "DCENT_OS_Antminer/dcentrald/.cargo/config.toml",
    "DCENT_OS_Antminer/dcentrald/Cargo.lock",
    "DCENT_OS_Antminer/dcentrald/zig-cc-aarch64.sh",
    "DCENT_OS_Antminer/dcentrald/zig-ar-aarch64.sh",
    "DCENT_OS_Antminer/scripts/s19k_aarch64_compile_check.sh",
    "DCENT_OS_Antminer/scripts/s19k_native_build_verify.py",
)
NATIVE_COMPILE_CONTRACT = {
    "status": "exact-snapshot-capsule-bound",
    "target": "aarch64-unknown-linux-musl",
    "rust_toolchain": "1.90.0",
    "zig_version": "0.13.0",
    "zig_archive_sha256": "d45312e61ebcc48032b77bc4cf7fd6915c11fa16e4aad116b66c9468211230ea",
    "cargo_locked": True,
    "cargo_offline": True,
    "immutable_builder_required": True,
    "fresh_result_root_required": True,
    "release_link_required": True,
}
NATIVE_LOCAL_PACKAGE_MANIFESTS = {
    "dcent-schema": "projects/dcent-schema/Cargo.toml",
    "dcentrald": "DCENT_OS_Antminer/dcentrald/dcentrald/Cargo.toml",
    "dcentrald-api": "DCENT_OS_Antminer/dcentrald/dcentrald-api/Cargo.toml",
    "dcentrald-api-grpc": "DCENT_OS_Antminer/dcentrald/dcentrald-api-grpc/Cargo.toml",
    "dcentrald-api-types": "DCENT_OS_Antminer/dcentrald/dcentrald-api-types/Cargo.toml",
    "dcentrald-asic": "DCENT_OS_Antminer/dcentrald/dcentrald-asic/Cargo.toml",
    "dcentrald-autotuner": "DCENT_OS_Antminer/dcentrald/dcentrald-autotuner/Cargo.toml",
    "dcentrald-bridge": "DCENT_OS_Antminer/dcentrald/dcentrald-bridge/Cargo.toml",
    "dcentrald-chip-analysis": "DCENT_OS_Antminer/dcentrald/dcentrald-chip-analysis/Cargo.toml",
    "dcentrald-common": "DCENT_OS_Antminer/dcentrald/dcentrald-common/Cargo.toml",
    "dcentrald-diagnostics": "DCENT_OS_Antminer/dcentrald/dcentrald-diagnostics/Cargo.toml",
    "dcentrald-fabric-lease": "DCENT_OS_Antminer/dcentrald/dcentrald-fabric-lease/Cargo.toml",
    "dcentrald-hal": "DCENT_OS_Antminer/dcentrald/dcentrald-hal/Cargo.toml",
    "dcentrald-silicon-profiles": "DCENT_OS_Antminer/dcentrald/dcentrald-silicon-profiles/Cargo.toml",
    "dcentrald-stratum": "DCENT_OS_Antminer/dcentrald/dcentrald-stratum/Cargo.toml",
    "dcentrald-thermal": "DCENT_OS_Antminer/dcentrald/dcentrald-thermal/Cargo.toml",
}
NATIVE_BUILD_KEYS = (
    "schema", "claim", "classification", "target_triple", "cargo_profile",
    "cargo_command", "artifact", "semantic_source_files",
    "semantic_source_files_sha256", "aarch64_compile_contract",
    "compile_contract_sha256", "capsule_build_receipt",
    "capsule_build_receipt_sha256", "local_dependency_closure",
    "manifest_public_key_hex", "manifest_public_key_sha256",
    "network_nonuse_proven",
    "network_contract",
    "release_authority_granted", "installation_authority_granted",
    "live_hardware_contacted", "verification_id",
)
NATIVE_BUILD_NETWORK_CONTRACT = {
    "scope": "entire-capsule-invocation",
    "builder_materialization_network": "permitted",
    "dependency_prefetch_network": "permitted",
    "compile_container_network_namespace": "enabled",
    "cargo_locked": True,
    "cargo_compile_offline_flag": True,
    "network_observation": "not-measured",
    "network_nonuse_proven": False,
}
CAPSULE_BUILD_KEYS = (
    "binary", "build_inputs", "build_environment", "build_variant", "builder",
    "cargo_metadata", "claim", "compile_environment", "git", "profile",
    "release_capsule", "schema_version", "source_inventory",
    "source_inventory_sha256", "target_triple", "toolchain_context",
)
ADOPTED_ROUTE_ARTIFACT_SHA256S = {
    "fbd730e5c189cc69d5a191fd3bffdba3f2401e171d24e36e3d86b0d38dc0967b",
    "9570a9fcd8e8a2cff6f3d21902f6354666c5b337b7b260641e5b0baf9260b4d6",
}
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
REPO_ROOT = PROJECT_ROOT.parent.parent
SOURCE_PATHS = (
    "DCENT_OS_Antminer/scripts/s19k_persistent_image_verify.py",
    "DCENT_OS_Antminer/scripts/build_amlogic_native_install.sh",
    "DCENT_OS_Antminer/scripts/install_amlogic_persistent.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/configs/dcentos_am3_s19kpro_defconfig",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19kpro/post-image.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/am3-s19kpro/post-build.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S37board_setup",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/rootfs-overlay/etc/init.d/S82dcentrald",
    "DCENT_OS_Antminer/contracts/hardware/amlogic-gpio437.json",
    "DCENT_OS_Antminer/scripts/generate_amlogic_gpio437.py",
    "DCENT_OS_Antminer/br2_external_dcentos/board/amlogic/rootfs-overlay/usr/share/dcentos/amlogic-gpio437.sh",
    "DCENT_OS_Antminer/br2_external_dcentos/board/common/rootfs-overlay/usr/share/dcentos/amlogic-gpio437.sh",
)


class PersistentImageError(ValueError):
    """The offline image evidence failed closed."""


def fail(message: str) -> NoReturn:
    raise PersistentImageError(message)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("ascii")


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _hex64(value: Any, label: str) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or value != value.lower()
            or any(c not in "0123456789abcdef" for c in value)):
        fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _token(value: Any, label: str, *, maximum: int = 256) -> str:
    if (not isinstance(value, str) or not value or len(value) > maximum
            or any(ord(c) < 0x21 or ord(c) > 0x7E for c in value)):
        fail(f"{label} must be a non-empty printable ASCII token")
    return value


def _positive_int(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if (isinstance(value, bool) or not isinstance(value, int)
            or value <= 0 or value > maximum):
        fail(f"{label} must be a positive bounded integer")
    return value


def _nonnegative_int(value: Any, label: str, maximum: int = 2**63 - 1) -> int:
    if (isinstance(value, bool) or not isinstance(value, int)
            or value < 0 or value > maximum):
        fail(f"{label} must be a non-negative bounded integer")
    return value


def _exact_keys(value: Mapping[str, Any], keys: Sequence[str], label: str) -> None:
    if set(value) != set(keys):
        fail(f"{label} keys are not exact")


def _pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _json_bytes(data: bytes, label: str, *, canonical: bool = True) -> dict[str, Any]:
    if not data or len(data) > MAX_JSON_BYTES or data.startswith(b"\xef\xbb\xbf"):
        fail(f"{label} is empty, oversized, or starts with a BOM")
    try:
        value = json.loads(data.decode("ascii"),
                           object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"{label} is not strict ASCII JSON: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    if canonical and data != canonical_json(value):
        fail(f"{label} must use canonical JSON bytes")
    return value


def _read_regular(path: Path, maximum: int, label: str) -> bytes:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        fail(f"{label} is missing: {path}")
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        fail(f"{label} must be a non-symlink regular file: {path}")
    if metadata.st_size <= 0 or metadata.st_size > maximum:
        fail(f"{label} has invalid size {metadata.st_size}")
    data = path.read_bytes()
    if len(data) != metadata.st_size:
        fail(f"{label} changed while being read")
    return data


def audit_source_tree(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Audit offline verifier/build readiness without claiming image evidence."""
    corpus: dict[str, bytes] = {}
    for relative in SOURCE_PATHS:
        corpus[relative] = _read_regular(
            repo_root / Path(*relative.split("/")), MAX_JSON_BYTES, relative)
    try:
        verifier = corpus[SOURCE_PATHS[0]].decode("utf-8")
        builder = corpus[SOURCE_PATHS[1]].decode("utf-8")
        writer = corpus[SOURCE_PATHS[2]].decode("utf-8")
        defconfig = corpus[SOURCE_PATHS[3]].decode("utf-8")
        post_image = corpus[SOURCE_PATHS[4]].decode("utf-8")
        post_build = corpus[SOURCE_PATHS[5]].decode("utf-8")
        setup = corpus[SOURCE_PATHS[6]].decode("utf-8")
        daemon = corpus[SOURCE_PATHS[7]].decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"persistent-image source is not UTF-8: {error}")
    anchors = {
        "verifier": (
            "def verify_workflow_evidence(",
            "two clean S19k unsigned build outputs are not byte-identical",
            "DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256",
            "public_inputs_verified_before_private_key_open",
            '"install_authority_granted": False',
        ),
        "builder": ("s19kpro|s19k)", "DCENT_REQUIRE_INSTALLABLE_PACKAGE=1"),
        "writer": ("CLEAR_FOR_FLASH=false",
                   'if [ "$CLEAR_FOR_FLASH" != true ]; then'),
        "defconfig": ("BR2_REPRODUCIBLE=y",),
        "post_image": (
            "DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256",
            "DCENT_S19K_NATIVE_OWNER_RECEIPT",
            "DCENT_S19K_STOCK_RECOVERY_RECEIPT",
            "DCENT_PACKAGE_INSTALLABLE=true",
            "DCENT_TARGET_SIDE_SYSUPGRADE=false",
            "--sort=name --format=ustar --owner=0 --group=0",
            "build-contract",
        ),
        "post_build": ("gzip -9 -n -c", "DCENT_RELEASE_PUBKEY_FILE",
                       "dcent_provision_release_image"),
        "setup": ('GPIO437_POLICY_HELPER=/usr/share/dcentos/amlogic-gpio437.sh',
                  '. "$GPIO437_POLICY_HELPER" || return 1',
                  'PSU_CLASS=$(dcent_gpio437_policy_state "$BOARD_TARGET")',
                  'LEVELS=$(dcent_gpio437_drive_levels "$BOARD_TARGET") || return 1',
                  'PWR_OFF_VALUE=$2', 'PWR_OFF_DIRECTION=$3',
                  'set_gpio_direction_checked "$PWR_GPIO" "$PWR_OFF_DIRECTION" out || return 1',
                  'set_gpio_value_checked "$PWR_GPIO" "$PWR_OFF_VALUE" || return 1',
                  "write_receipt boot-safe || return 1"),
        "daemon": ("verify_amlogic_boot_safe_state",),
    }
    texts = {"verifier": verifier, "builder": builder, "writer": writer,
             "defconfig": defconfig, "post_image": post_image,
             "post_build": post_build, "setup": setup, "daemon": daemon}
    for label, required in anchors.items():
        for anchor in required:
            if anchor not in texts[label]:
                fail(f"{label} readiness source lacks anchor: {anchor}")
    if "CLEAR_FOR_FLASH=true" in writer:
        fail("persistent NAND writer is enabled in source")
    # Current setup consumes the exact-target policy. Prove both the qualified
    # S19k levels and the generated bytes, rather than accepting variable names
    # as evidence of polarity. Historical sealed-image verification below keeps
    # its original literal-level contract and receipt schema unchanged.
    import generate_amlogic_gpio437 as gpio437
    try:
        policy = json.loads(corpus[SOURCE_PATHS[8]],
                            object_pairs_hook=_pairs_no_duplicates)
        gpio437.validate(policy)
        profile = next((row for row in policy["profiles"]
                        if row["board_target"] == BOARD), None)
        if profile is None:
            fail("GPIO437 readiness policy lacks the exact S19k target")
        status, vendors, levels = gpio437.decision(profile, policy["sources"])
        if status != "qualified" or vendors < 2 or levels != (0, 1):
            fail("GPIO437 readiness requires qualified exact S19k ON=0/OFF=1")
        generated = gpio437.shell_text(policy).encode("utf-8")
        for relative in SOURCE_PATHS[10:12]:
            if corpus[relative] != generated:
                fail(f"GPIO437 readiness generated helper differs: {relative}")
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        fail(f"GPIO437 readiness policy is invalid: {error}")
    return {
        "schema": SOURCE_READINESS_SCHEMA,
        "phase_id": "persistent-image",
        "classification": "ready",
        "host_only_source_audit": True,
        "reproducible_build_verifier_present": True,
        "live_hardware_contacted": False,
        "network_used": False,
        "install_authority_granted": False,
        "mutation_authority_granted": False,
        "nand_writer_clear_for_flash": False,
        "source_files": [
            {"path": relative, "sha256": _hash(corpus[relative]),
             "bytes": len(corpus[relative])}
            for relative in SOURCE_PATHS
        ],
        "external_evidence_required": [
            "two independent clean offline build attestations and byte-identical unsigned tar outputs",
            "one isolated equality-gated post-A/B Ed25519 signing receipt and exact derived package",
            "dependency-bound verified native-owner receipt and exact dcentrald artifact",
            "tested exact stock-recovery receipt from the target device",
        ],
    }


def audit(repo_root: Path = REPO_ROOT) -> dict[str, Any]:
    """Compatibility alias for controller source-readiness discovery."""
    return audit_source_tree(repo_root)


def _verification_id(value: Mapping[str, Any], label: str) -> str:
    observed = _hex64(value.get("verification_id"), f"{label} verification_id")
    unsigned = dict(value)
    del unsigned["verification_id"]
    if observed != _hash(canonical_json(unsigned)):
        fail(f"{label} verification_id does not bind the exact receipt")
    return observed


def _public_key_identity(pem: bytes) -> tuple[Any, str, str]:
    if len(pem) > MAX_KEY_BYTES or not pem.endswith(b"\n"):
        fail("trusted release key must be bounded newline-terminated PEM")
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        fail(f"Python cryptography is required for Ed25519 verification: {error}")
    try:
        key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError) as error:
        fail(f"trusted release key is not valid PEM: {error}")
    if not isinstance(key, Ed25519PublicKey):
        fail("trusted release key is not Ed25519")
    normalized = key.public_bytes(serialization.Encoding.PEM,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    if pem != normalized:
        fail("trusted release key is not canonical Ed25519 SPKI PEM")
    der = key.public_bytes(serialization.Encoding.DER,
                           serialization.PublicFormat.SubjectPublicKeyInfo)
    raw = key.public_bytes(serialization.Encoding.Raw,
                           serialization.PublicFormat.Raw)
    return key, _hash(der), raw.hex()


@dataclass(frozen=True)
class Package:
    raw: bytes
    files: dict[str, bytes]
    members: tuple[tarfile.TarInfo, ...]


def _safe_tar_path(name: str) -> str:
    if not name or "\\" in name or name.startswith("/") or "\x00" in name:
        fail(f"unsafe tar member path: {name!r}")
    path = PurePosixPath(name)
    if any(part in ("", ".", "..") for part in path.parts):
        fail(f"noncanonical tar member path: {name!r}")
    normalized = path.as_posix()
    if normalized != name.rstrip("/"):
        fail(f"noncanonical tar member path: {name!r}")
    return normalized


def _parse_package(raw: bytes, label: str, *, signature_required: bool) -> Package:
    if len(raw) > MAX_PACKAGE_BYTES:
        fail(f"{label} exceeds the package-size bound")
    files: dict[str, bytes] = {}
    members: list[tarfile.TarInfo] = []
    seen: set[str] = set()
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                name = _safe_tar_path(member.name)
                if name in seen:
                    fail(f"{label} has duplicate tar member {name}")
                seen.add(name)
                members.append(member)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    fail(f"{label} contains unsafe tar member type at {name}")
                if member.isdir():
                    continue
                if not member.isfile() or member.size < 0 or member.size > MAX_PACKAGE_BYTES:
                    fail(f"{label} contains unsupported/oversized member {name}")
                stream = archive.extractfile(member)
                if stream is None:
                    fail(f"{label} could not read tar member {name}")
                value = stream.read(member.size + 1)
                if len(value) != member.size:
                    fail(f"{label} member {name} was truncated")
                files[name] = value
    except (tarfile.TarError, OSError) as error:
        fail(f"{label} is not a valid uncompressed tar archive: {error}")
    required = {
        PACKAGE_KERNEL_PATH, PACKAGE_ROOT_PATH, PACKAGE_METADATA_PATH,
        PACKAGE_SUMS_PATH, PACKAGE_MANIFEST_PATH,
        PACKAGE_KEY_PATH, PACKAGE_NATIVE_PATH, PACKAGE_RECOVERY_PATH,
        PACKAGE_CONTRACT_PATH, PACKAGE_BUILDER_PATH, PACKAGE_WRITER_PATH,
    }
    if signature_required:
        required.add(PACKAGE_SIGNATURE_PATH)
    elif PACKAGE_SIGNATURE_PATH in files:
        fail(f"{label} unsigned intermediate already contains MANIFEST.sig")
    if set(files) != required:
        fail(f"{label} payload set is not exact")
    normalized_members = [_safe_tar_path(member.name) for member in members]
    expected_members = [PREFIX, *sorted(required)]
    if normalized_members != expected_members:
        fail(f"{label} tar member order/set is not exact deterministic ustar")
    directories = {
        _safe_tar_path(member.name) for member in members if member.isdir()
    }
    if directories != {PREFIX}:
        fail(f"{label} tar directory set is not exact")
    return Package(raw=raw, files=files, members=tuple(members))


def _parse_sums(data: bytes) -> dict[str, str]:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        fail(f"SHA256SUMS is not ASCII: {error}")
    if not text.endswith("\n"):
        fail("SHA256SUMS must end in one newline")
    result: dict[str, str] = {}
    for line in text.splitlines():
        pieces = line.split("  ")
        if len(pieces) != 2 or "/" in pieces[1] or pieces[1] in result:
            fail(f"SHA256SUMS has malformed/duplicate line: {line!r}")
        result[pieces[1]] = _hex64(pieces[0],
                                   f"SHA256SUMS digest for {pieces[1]}")
    expected = {"kernel", "root", "METADATA", "release_ed25519.pub",
                NATIVE_RECEIPT_FILE, RECOVERY_RECEIPT_FILE,
                "IMAGE_CONTRACT.json", BUILDER_LEAF, WRITER_LEAF}
    if set(result) != expected:
        fail("SHA256SUMS does not cover the exact persistent-image payload set")
    return result


def _bounded_gzip(data: bytes) -> bytes:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        value = decompressor.decompress(data, MAX_ROOTFS_UNPACKED_BYTES + 1)
        value += decompressor.flush(MAX_ROOTFS_UNPACKED_BYTES + 1 - len(value))
    except zlib.error as error:
        fail(f"rootfs uImage gzip payload is invalid: {error}")
    if len(value) > MAX_ROOTFS_UNPACKED_BYTES or decompressor.unconsumed_tail:
        fail("rootfs expands beyond the offline verification bound")
    if not decompressor.eof or decompressor.unused_data:
        fail("rootfs gzip stream is truncated or has trailing bytes")
    return value


def _parse_uimage(data: bytes, source_date_epoch: int) -> bytes:
    if len(data) <= 64 or len(data) > ROOTFS_WINDOW_BYTES:
        fail("rootfs uImage is empty or exceeds the exact AML rootfs window")
    try:
        values = struct.unpack(">7I4B32s", data[:64])
    except struct.error as error:
        fail(f"rootfs uImage header is invalid: {error}")
    magic, header_crc, timestamp, size, load, entry, data_crc = values[:7]
    os_id, arch, image_type, compression, name = values[7:]
    header = bytearray(data[:64])
    header[4:8] = b"\0\0\0\0"
    if magic != 0x27051956 or zlib.crc32(header) & 0xFFFFFFFF != header_crc:
        fail("rootfs uImage magic/header CRC is invalid")
    payload = data[64:]
    if size != len(payload) or zlib.crc32(payload) & 0xFFFFFFFF != data_crc:
        fail("rootfs uImage size/data CRC is invalid")
    if timestamp != source_date_epoch or source_date_epoch > 0xFFFFFFFF:
        fail("rootfs uImage timestamp is not exact SOURCE_DATE_EPOCH")
    if (load, entry, os_id, arch, image_type, compression) != (0, 0, 5, 22, 1, 1):
        fail("rootfs uImage is not Linux/ARM64/ramdisk/gzip")
    if name.rstrip(b"\0") != b"DCENT_OS S19K Pro rootfs":
        fail("rootfs uImage name is not the exact S19k identity")
    return _bounded_gzip(payload)


def _normalize_cpio_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    if name == ".":
        return ""
    if not name or name.startswith("/") or "\\" in name:
        fail(f"unsafe newc path: {name!r}")
    path = PurePosixPath(name)
    if any(part in ("", ".", "..") for part in path.parts):
        fail(f"noncanonical newc path: {name!r}")
    return path.as_posix()


def _parse_newc(data: bytes) -> dict[str, tuple[int, int, bytes]]:
    result: dict[str, tuple[int, int, bytes]] = {}
    offset = 0
    entries = 0
    trailer = False
    while offset < len(data):
        if len(data) - offset < 110:
            fail("newc archive has a truncated header")
        header = data[offset:offset + 110]
        offset += 110
        if header[:6] not in (b"070701", b"070702"):
            fail("rootfs is not a newc/crc cpio archive")
        try:
            fields = [int(header[6 + 8*i:14 + 8*i], 16) for i in range(13)]
        except ValueError:
            fail("newc archive contains a non-hex header field")
        mode, link_count, filesize, namesize = (
            fields[1], fields[4], fields[6], fields[11]
        )
        if namesize <= 1 or namesize > 4096 or filesize > MAX_ROOTFS_MEMBER_BYTES:
            fail("newc archive contains invalid name/file size")
        if offset + namesize > len(data):
            fail("newc archive has a truncated name")
        name_raw = data[offset:offset + namesize]
        offset += namesize
        if name_raw[-1:] != b"\0" or b"\0" in name_raw[:-1]:
            fail("newc archive has a malformed pathname")
        try:
            name_text = name_raw[:-1].decode("utf-8")
        except UnicodeDecodeError as error:
            fail(f"newc pathname is not UTF-8: {error}")
        offset = (offset + 3) & ~3
        if name_text == "TRAILER!!!":
            if filesize != 0:
                fail("newc trailer carries data")
            trailer = True
            break
        name = _normalize_cpio_name(name_text)
        if name in result:
            fail(f"newc archive contains duplicate normalized path {name}")
        if offset + filesize > len(data):
            fail(f"newc archive has truncated content for {name}")
        content = data[offset:offset + filesize]
        offset = (offset + filesize + 3) & ~3
        result[name] = (mode, link_count, content)
        entries += 1
        if entries > MAX_ROOTFS_ENTRIES:
            fail("newc archive exceeds entry-count bound")
    if not trailer:
        fail("newc archive has no TRAILER!!! entry")
    if any(data[offset:]):
        fail("newc archive has non-zero trailing bytes")
    return result


def _root_regular(
    entries: Mapping[str, tuple[int, int, bytes]],
    path: str,
    maximum: int,
    *,
    executable: bool = False,
) -> bytes:
    if path not in entries:
        fail(f"rootfs is missing required path {path}")
    mode, link_count, data = entries[path]
    if stat.S_IFMT(mode) != stat.S_IFREG or len(data) > maximum:
        fail(f"rootfs required path is not bounded regular file: {path}")
    if link_count != 1:
        fail(f"rootfs required path is hard-link ambiguous: {path}")
    if executable and mode & 0o111 == 0:
        fail(f"rootfs required executable has no execute bit: {path}")
    return data


def _verify_aarch64_static_elf_blob(blob: bytes) -> None:
    """Require the packaged daemon itself to be a runnable static AArch64 ELF."""
    if len(blob) < 64 or blob[:4] != b"\x7fELF":
        fail("packaged dcentrald has a truncated or missing ELF64 header")
    if blob[4:7] != bytes((2, 1, 1)):
        fail("packaged dcentrald is not ELF64 little-endian version 1")
    elf_type = struct.unpack_from("<H", blob, 16)[0]
    machine = struct.unpack_from("<H", blob, 18)[0]
    elf_version = struct.unpack_from("<I", blob, 20)[0]
    entry = struct.unpack_from("<Q", blob, 24)[0]
    phoff = struct.unpack_from("<Q", blob, 32)[0]
    ehsize = struct.unpack_from("<H", blob, 52)[0]
    phentsize = struct.unpack_from("<H", blob, 54)[0]
    phnum = struct.unpack_from("<H", blob, 56)[0]
    if elf_type not in (2, 3) or machine != 183 or elf_version != 1 or entry == 0:
        fail("packaged dcentrald is not a runnable AArch64 ELF")
    if ehsize != 64 or phentsize != 56 or phnum in (0, 0xFFFF):
        fail("packaged dcentrald has an inadmissible program-header contract")
    table_size = phentsize * phnum
    if phoff < 64 or phoff > len(blob) or table_size > len(blob) - phoff:
        fail("packaged dcentrald program-header table is outside the file")
    executable_ranges: list[tuple[int, int]] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        program_type = struct.unpack_from("<I", blob, offset)[0]
        if program_type == 3:
            fail("packaged dcentrald contains PT_INTERP and is not static")
        if program_type != 1:
            continue
        flags = struct.unpack_from("<I", blob, offset + 4)[0]
        file_offset = struct.unpack_from("<Q", blob, offset + 8)[0]
        virtual_address = struct.unpack_from("<Q", blob, offset + 16)[0]
        file_size = struct.unpack_from("<Q", blob, offset + 32)[0]
        memory_size = struct.unpack_from("<Q", blob, offset + 40)[0]
        if file_size > memory_size:
            fail("packaged dcentrald PT_LOAD file size exceeds memory size")
        if file_offset > len(blob) or file_size > len(blob) - file_offset:
            fail("packaged dcentrald PT_LOAD range is outside the file")
        if flags & 1 and file_size:
            executable_ranges.append(
                (virtual_address, virtual_address + file_size)
            )
    if not executable_ranges or not any(
        start <= entry < end for start, end in executable_ranges
    ):
        fail("packaged dcentrald entry is outside executable PT_LOAD bytes")


def _safeoff_baseline(
    root: bytes, release_key_bytes: bytes
) -> tuple[dict[str, Any], dict[str, tuple[int, int, bytes]]]:
    entries = _parse_newc(root)
    platform = _root_regular(entries, "etc/dcentos/platform", 128)
    legacy_platform = _root_regular(entries, "etc/dcentos-platform", 128)
    board = _root_regular(entries, "etc/dcentos/board_target", 128)
    rail = _root_regular(entries, "etc/dcentos/rail_gpio", 128)
    policy = _root_regular(entries, "etc/dcentos/mutation_policy", 1024)
    embedded_key = _root_regular(entries, "etc/dcentos/release_ed25519.pub",
                                 MAX_KEY_BYTES)
    release_marker = _root_regular(entries, "etc/dcentos/release-image", 4096)
    config = _root_regular(entries, "etc/dcentrald.toml", 256 * 1024)
    setup = _root_regular(
        entries, "etc/init.d/S37board_setup", 1024 * 1024, executable=True
    )
    daemon = _root_regular(
        entries, "etc/init.d/S82dcentrald", 1024 * 1024, executable=True
    )
    packaged_daemon = _root_regular(
        entries, "usr/local/bin/dcentrald", 64 * 1024 * 1024,
        executable=True,
    )
    _verify_aarch64_static_elf_blob(packaged_daemon)
    if platform != b"am3-aml-s19k\n" or legacy_platform != platform:
        fail("rootfs lacks exact am3-aml-s19k platform identity")
    # Older sealed boot-observation images carry only boot-safeoff. Native
    # beta images also start the daemon, whose own EEPROM/cooling/watchdog
    # admission governs mining after normal configuration. Neither policy
    # grants sysupgrade, recovery or arbitrary persistent writes.
    if board != b"am3-s19k\n" or rail != b"437\n" or policy not in (
        b"boot-safeoff\n", b"boot-safeoff\ndaemon-hardware\n",
    ):
        fail("rootfs board/rail/mutation-policy identity is not exact")
    if embedded_key != release_key_bytes:
        fail("rootfs embedded release key differs from signed package key")
    if b"release_image=1\n" not in release_marker:
        fail("rootfs lacks the release-image hardening marker")
    try:
        config_text = config.decode("utf-8")
        setup_text = setup.decode("utf-8")
        daemon_text = daemon.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"SafeOff baseline source is not UTF-8: {error}")
    mining = config_text.find("[mining]")
    enabled = config_text.find("enabled = false", mining)
    next_section = config_text.find("\n[", mining + 1)
    if mining < 0 or enabled < 0 or (next_section >= 0 and enabled > next_section):
        fail("rootfs does not boot with mining disabled")
    setup_anchors = (
        "PWR_GPIO=437", 'am3-aml-s19k:am3-s19k)',
        'dcent_mutation_policy_has "$MUTATION_POLICY_FILE" boot-safeoff',
        'set_gpio_direction_checked "$PWR_GPIO" high out',
        'set_gpio_value_checked "$PWR_GPIO" 1',
        "hold_hashboards_reset_low || return 1",
        "write_receipt boot-safe || return 1",
    )
    if any(anchor not in setup_text for anchor in setup_anchors):
        fail("S37board_setup lacks exact S19k SafeOff baseline anchors")
    verify_anchor = 'if [ "$PLATFORM" = amlogic ] && ! verify_amlogic_boot_safe_state; then'
    daemon_exec = '"$DAEMON"'
    verify_position = daemon_text.find(verify_anchor)
    if verify_position < 0 or daemon_text.find(daemon_exec, verify_position) < 0:
        fail("S82dcentrald does not require boot-safe receipt before execution")
    baseline = {
        "platform": "am3-aml-s19k", "board_target": BOARD,
        "rail_gpio": 437, "safeoff_value": 1,
        "mining_enabled_at_boot": False,
        "board_setup_path": "etc/init.d/S37board_setup",
        "board_setup_sha256": _hash(setup),
        "daemon_init_path": "etc/init.d/S82dcentrald",
        "daemon_init_sha256": _hash(daemon),
        "mutation_policy_path": "etc/dcentos/mutation_policy",
        "mutation_policy_sha256": _hash(policy),
        "embedded_release_key_sha256": _hash(embedded_key),
        "release_image_marker_sha256": _hash(release_marker),
    }
    return baseline, entries


def _verify_native_receipt(
    data: bytes, *, expected_source_commit: str
) -> tuple[dict[str, Any], str]:
    receipt = _json_bytes(data, "native-owner receipt")
    if receipt.get("schema") != NATIVE_OWNER_SCHEMA:
        fail("native-owner receipt schema is not exact")
    if (receipt.get("phase_id") != "native-cold-start-owner"
            or receipt.get("classification") != "verified"
            or receipt.get("source_readiness_classification") != "ready"
            or receipt.get("production_owner_present") is not True
            or receipt.get("dependency_evidence_bound") is not True
            or receipt.get("authority_minted") is not False):
        fail("native-owner receipt does not prove a production owner")
    prerequisite_ids = receipt.get("prerequisite_verification_ids")
    if (not isinstance(prerequisite_ids, dict)
            or set(prerequisite_ids) != NATIVE_PREREQUISITES):
        fail("native-owner receipt does not bind the exact prerequisite set")
    for phase_id, verification_id in prerequisite_ids.items():
        _hex64(verification_id, f"native-owner prerequisite {phase_id}")
    artifact = receipt.get("native_owner_artifact")
    if not isinstance(artifact, dict):
        fail("native-owner receipt lacks native_owner_artifact")
    _exact_keys(artifact, ("path", "sha256", "bytes"),
                "native-owner artifact")
    if artifact.get("path") != "usr/local/bin/dcentrald":
        fail("native-owner artifact path is not packaged daemon")
    _hex64(artifact.get("sha256"), "native-owner artifact SHA-256")
    _positive_int(artifact.get("bytes"), "native-owner artifact bytes",
                  64 * 1024 * 1024)
    if artifact["sha256"] in ADOPTED_ROUTE_ARTIFACT_SHA256S:
        fail("native-owner receipt reuses an older adopted-route artifact")
    source_files = receipt.get("source_files")
    if not isinstance(source_files, list) or len(source_files) != len(NATIVE_SOURCE_PATHS):
        fail("native-owner receipt lacks exact source-file identities")
    for expected_path, identity in zip(NATIVE_SOURCE_PATHS, source_files):
        if not isinstance(identity, dict):
            fail("native-owner source identity is not an object")
        _exact_keys(identity, ("path", "sha256", "bytes"),
                    "native-owner source identity")
        if identity.get("path") != expected_path:
            fail("native-owner source identity order/path is not exact")
        _hex64(identity.get("sha256"), f"native-owner source {expected_path}")
        _positive_int(identity.get("bytes"),
                      f"native-owner source bytes {expected_path}",
                      MAX_JSON_BYTES)
    if receipt.get("aarch64_compile_contract") != NATIVE_COMPILE_CONTRACT:
        fail("native-owner receipt lacks the exact AArch64 compile contract")
    native_build = receipt.get("native_build_receipt")
    if not isinstance(native_build, dict):
        fail("native-owner receipt lacks the native build receipt")
    _exact_keys(native_build, NATIVE_BUILD_KEYS, "native build receipt")
    native_build_id = _verification_id(native_build, "native build receipt")
    native_build_artifact = native_build.get("artifact")
    capsule = native_build.get("capsule_build_receipt")
    if not isinstance(capsule, dict):
        fail("native build receipt lacks capsule build evidence")
    _exact_keys(capsule, CAPSULE_BUILD_KEYS, "capsule build receipt")
    capsule_binary = capsule.get("binary")
    capsule_git = capsule.get("git")
    capsule_lineage = capsule.get("release_capsule")
    capsule_metadata = capsule.get("cargo_metadata")
    if (
        not isinstance(capsule_git, dict)
        or set(capsule_git) != {"commit", "source_kind"}
        or capsule_git.get("source_kind") != "exact-git-object-snapshot"
    ):
        fail("capsule build receipt lacks exact Git-snapshot provenance")
    source_commit = capsule_git.get("commit")
    if (
        not isinstance(source_commit, str)
        or len(source_commit) not in (40, 64)
        or source_commit != source_commit.lower()
        or any(character not in "0123456789abcdef" for character in source_commit)
    ):
        fail("native build source commit is not a canonical Git identity")
    if not isinstance(capsule_lineage, dict) or set(capsule_lineage) != {
        "schema",
        "release_invocation_descriptor_sha256",
        "release_invocation_id",
        "source_snapshot_descriptor_sha256",
        "source_snapshot_id",
    }:
        fail("capsule build lineage schema is not exact")
    if capsule_lineage.get("schema") != "org.dcentral.dcentos.release-capsule-lineage.v2":
        fail("capsule build lineage version is not exact")
    for key in (
        "release_invocation_descriptor_sha256",
        "release_invocation_id",
        "source_snapshot_descriptor_sha256",
        "source_snapshot_id",
    ):
        _hex64(capsule_lineage.get(key), f"capsule lineage {key}")
    if not isinstance(capsule_metadata, dict) or set(capsule_metadata) != {
        "path", "sha256", "size"
    }:
        fail("capsule Cargo metadata identity is malformed")
    cargo_metadata_sha256 = _hex64(
        capsule_metadata.get("sha256"), "capsule Cargo metadata SHA-256"
    )
    _positive_int(
        capsule_metadata.get("size"), "capsule Cargo metadata bytes", MAX_JSON_BYTES
    )
    if (
        not isinstance(capsule_binary, dict)
        or capsule_binary.get("name") != "dcentrald"
        or capsule_binary.get("sha256") != artifact["sha256"]
        or capsule_binary.get("size") != artifact["bytes"]
        or not str(capsule_binary.get("path", "")).endswith("/dcentrald")
    ):
        fail("capsule build receipt does not bind the packaged daemon")
    closure = native_build.get("local_dependency_closure")
    if not isinstance(closure, dict) or set(closure) != {
        "cargo_metadata_sha256", "target_triple", "root_package_id", "packages",
        "external_local_paths_inside_snapshot",
    }:
        fail("native build local dependency closure is malformed")
    closure_packages = closure.get("packages")
    if not isinstance(closure_packages, list) or len(closure_packages) != len(
        NATIVE_LOCAL_PACKAGE_MANIFESTS
    ):
        fail("native build local dependency closure count is not exact")
    closure_manifests: dict[str, str] = {}
    for package in closure_packages:
        if not isinstance(package, dict) or set(package) != {
            "name", "version", "manifest_path", "package_root"
        }:
            fail("native build local dependency package is malformed")
        name = package.get("name")
        manifest = package.get("manifest_path")
        if not isinstance(name, str) or not isinstance(manifest, str):
            fail("native build local dependency package identity is malformed")
        if package.get("package_root") != str(PurePosixPath(manifest).parent):
            fail("native build local dependency package root is stale")
        closure_manifests[name] = manifest
    if (
        closure_manifests != NATIVE_LOCAL_PACKAGE_MANIFESTS
        or closure.get("cargo_metadata_sha256") != cargo_metadata_sha256
        or closure.get("target_triple") != "aarch64-unknown-linux-musl"
        or closure.get("external_local_paths_inside_snapshot") is not True
        or not str(closure.get("root_package_id", "")).startswith("dcentrald ")
    ):
        fail("native build local dependency closure is not exact")
    manifest_public_key_hex = _hex64(
        native_build.get("manifest_public_key_hex"),
        "native build manifest public key",
    )
    if native_build.get("manifest_public_key_sha256") != _hash(
        bytes.fromhex(manifest_public_key_hex)
    ):
        fail("native build manifest public-key hash is stale")
    build_environment = capsule.get("build_environment")
    compile_environment = capsule.get("compile_environment")
    if (
        build_environment
        != {
            "DCENT_MANIFEST_KEY_ID": "",
            "DCENT_MANIFEST_PUBLIC_KEY_HEX": manifest_public_key_hex,
        }
        or not isinstance(compile_environment, dict)
        or not isinstance(compile_environment.get("entries"), dict)
        or compile_environment["entries"].get("DCENT_MANIFEST_KEY_ID") != ""
        or compile_environment["entries"].get("DCENT_MANIFEST_PUBLIC_KEY_HEX")
        != manifest_public_key_hex
    ):
        fail("native build capsule does not bind one exact manifest public key")
    if (
        native_build.get("schema") != NATIVE_BUILD_SCHEMA
        or native_build.get("claim") != NATIVE_BUILD_CLAIM
        or native_build.get("classification")
        != "exact-snapshot-capsule-linked-manifest-key-pinned-candidate"
        or native_build.get("target_triple") != "aarch64-unknown-linux-musl"
        or native_build.get("cargo_profile") != "release"
        or native_build.get("cargo_command") != NATIVE_BUILD_COMMAND
        or native_build_artifact
        != {"path": "dcentrald", "sha256": artifact["sha256"], "bytes": artifact["bytes"]}
        or native_build.get("semantic_source_files") != source_files
        or native_build.get("semantic_source_files_sha256")
        != _hash(canonical_json(source_files))
        or native_build.get("aarch64_compile_contract") != NATIVE_COMPILE_CONTRACT
        or native_build.get("compile_contract_sha256")
        != _hash(canonical_json(NATIVE_COMPILE_CONTRACT))
        or native_build.get("capsule_build_receipt_sha256")
        != _hash(canonical_json(capsule))
        or source_commit != expected_source_commit
        or capsule.get("schema_version") != 4
        or capsule.get("claim")
        != "declared-release-capsule-and-post-build-snapshot-consistency-not-build-causality-or-reproducibility-proof"
        or capsule.get("target_triple") != "aarch64-unknown-linux-musl"
        or capsule.get("profile") != "release"
        or capsule.get("build_variant") != "amlogic"
        or native_build.get("network_nonuse_proven") is not False
        or native_build.get("network_contract") != NATIVE_BUILD_NETWORK_CONTRACT
        or native_build.get("release_authority_granted") is not False
        or native_build.get("installation_authority_granted") is not False
        or native_build.get("live_hardware_contacted") is not False
    ):
        fail("native build receipt is not the exact snapshot-capsule candidate")
    observed_build_ids = receipt.get("native_owner_build_binding", {}).get(
        "observed_native_build_verification_ids"
    )
    observed_invocation_ids = receipt.get("native_owner_build_binding", {}).get(
        "observed_release_invocation_ids"
    )
    if (
        not isinstance(observed_build_ids, list)
        or len(observed_build_ids) != 2
        or len(set(observed_build_ids)) != 2
        or native_build_id not in observed_build_ids
        or not isinstance(observed_invocation_ids, list)
        or len(observed_invocation_ids) != 2
        or len(set(observed_invocation_ids)) != 2
        or capsule_lineage["release_invocation_id"] not in observed_invocation_ids
    ):
        fail("native-owner receipt lacks two exact build observations")
    for value in observed_build_ids + observed_invocation_ids:
        _hex64(value, "native-owner reproducibility observation")
    expected_build_binding = {
        "target_triple": "aarch64-unknown-linux-musl",
        "cargo_profile": "release",
        "artifact_role": "native-cold-start-owner",
        "source_files_sha256": _hash(canonical_json(source_files)),
        "compile_contract_sha256": _hash(
            canonical_json(NATIVE_COMPILE_CONTRACT)
        ),
        "adopted_artifact_reused": False,
        "native_build_verification_id": native_build_id,
        "capsule_build_receipt_sha256": native_build[
            "capsule_build_receipt_sha256"
        ],
        "source_commit": source_commit,
        "source_snapshot_id": capsule_lineage["source_snapshot_id"],
        "release_invocation_id": capsule_lineage["release_invocation_id"],
        "cargo_metadata_sha256": cargo_metadata_sha256,
        "manifest_public_key_hex": manifest_public_key_hex,
        "manifest_public_key_sha256": native_build[
            "manifest_public_key_sha256"
        ],
        "native_reproducibility_verification_id": prerequisite_ids[
            "native-build-reproducibility"
        ],
        "observed_native_build_verification_ids": observed_build_ids,
        "observed_release_invocation_ids": observed_invocation_ids,
    }
    if receipt.get("native_owner_build_binding") != expected_build_binding:
        fail("native-owner receipt lacks the exact source/artifact build binding")
    return receipt, _verification_id(receipt, "native-owner receipt")


def _verify_recovery_receipt(data: bytes) -> tuple[dict[str, Any], str]:
    receipt = _json_bytes(data, "stock-recovery receipt")
    if (receipt.get("schema") != RECOVERY_SCHEMA
            or receipt.get("claim") !=
            "stock-recovery-rehearsed-before-any-dcentos-write"):
        fail("stock-recovery receipt schema/claim is not exact")
    for field in ("separate_mutation_authority_verified",
                  "stock_restore_rehearsal_verified", "original_bytes_restored",
                  "terminal_safeoff_verified"):
        if receipt.get(field) is not True:
            fail(f"stock-recovery receipt lacks required {field}")
    for field in ("dcentos_write_observed", "dcentos_write_authorized",
                  "mutation_authority_granted"):
        if receipt.get(field) is not False:
            fail(f"stock-recovery receipt improperly claims {field}")
    _token(receipt.get("device_id"), "recovery device_id")
    stock = receipt.get("stock_bmu")
    if not isinstance(stock, dict):
        fail("stock-recovery receipt lacks stock_bmu")
    _hex64(stock.get("sha256"), "stock BMU SHA-256")
    _positive_int(stock.get("bytes"), "stock BMU bytes", 128 * 1024 * 1024)
    return receipt, _verification_id(receipt, "stock-recovery receipt")


def _verify_build_receipt(data: bytes, package_name: str,
                          package: bytes) -> dict[str, Any]:
    receipt = _json_bytes(data, f"{package_name} build attestation")
    _exact_keys(receipt, BUILD_KEYS, f"{package_name} build attestation")
    if receipt["schema"] != BUILD_SCHEMA:
        fail(f"{package_name} build attestation schema is not exact")
    _token(receipt["build_id"], f"{package_name} build_id")
    _token(receipt["build_root_id"], f"{package_name} build_root_id")
    if (receipt["clean_build"] is not True
            or receipt["build_cache_reused"] is not False
            or receipt["network_used"] is not False):
        fail(f"{package_name} was not offline clean build without cache reuse")
    commit = _token(receipt["source_commit"], f"{package_name} source_commit")
    if (len(commit) not in (40, 64)
            or any(c not in "0123456789abcdef" for c in commit)):
        fail(f"{package_name} source_commit is not full lowercase object id")
    _nonnegative_int(receipt["source_date_epoch"],
                     f"{package_name} source_date_epoch", 0xFFFFFFFF)
    if (receipt["build_target"] != "dcentos_am3_s19kpro_defconfig"
            or receipt["build_arch"] != "aarch64"):
        fail(f"{package_name} build target/architecture is not exact")
    _token(receipt["toolchain_id"], f"{package_name} toolchain_id")
    if receipt["package_name"] != package_name:
        fail(f"{package_name} attestation names different package")
    if (receipt["package_sha256"] != _hash(package)
            or receipt["package_bytes"] != len(package)):
        fail(f"{package_name} attestation does not bind exact package bytes")
    return receipt


def _manifest_payload(manifest: Mapping[str, Any], name: str, path: str,
                      data: bytes) -> None:
    payloads = manifest.get("payloads")
    if not isinstance(payloads, dict) or not isinstance(payloads.get(name), dict):
        fail(f"signed manifest lacks payload {name}")
    value = payloads[name]
    if (value.get("path") != path or value.get("size") != len(data)
            or value.get("sha256") != _hash(data)):
        fail(f"signed manifest payload {name} does not bind exact bytes")


def build_image_contract(root_uimage: bytes, native_receipt_bytes: bytes,
                         recovery_receipt_bytes: bytes, release_key_bytes: bytes,
                         builder_bytes: bytes, writer_bytes: bytes,
                         *, source_commit: str, source_date_epoch: int,
                         build_target: str, build_arch: str,
                         toolchain_id: str,
                         expected_release_key_sha256: str) -> dict[str, Any]:
    """Construct the canonical contract embedded in both builds."""
    native, native_id = _verify_native_receipt(
        native_receipt_bytes, expected_source_commit=source_commit
    )
    recovery, recovery_id = _verify_recovery_receipt(recovery_receipt_bytes)
    _, key_id, raw_public_key_hex = _public_key_identity(release_key_bytes)
    expected_key_sha = _hex64(expected_release_key_sha256,
                              "externally expected release-key SHA-256")
    if _hash(release_key_bytes) != expected_key_sha:
        fail("release public key does not match external expected identity")
    native_manifest_key_hex = native["native_build_receipt"][
        "manifest_public_key_hex"
    ]
    if native_manifest_key_hex != raw_public_key_hex:
        fail("packaged release key differs from native daemon manifest key pin")
    unpacked = _parse_uimage(root_uimage, source_date_epoch)
    baseline, entries = _safeoff_baseline(unpacked, release_key_bytes)
    owner_artifact = native["native_owner_artifact"]
    daemon = _root_regular(entries, owner_artifact["path"], 64 * 1024 * 1024)
    if (owner_artifact["sha256"] != _hash(daemon)
            or owner_artifact["bytes"] != len(daemon)):
        fail("native-owner receipt does not bind packaged dcentrald bytes")
    try:
        builder_text = builder_bytes.decode("utf-8")
        writer_text = writer_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"persistent install helper is not UTF-8: {error}")
    for anchor in ("s19kpro|s19k)", "DCENT_REQUIRE_INSTALLABLE_PACKAGE=1",
                   '"$DCENT_AM3_ROOTFS_WINDOW_DEC"'):
        if anchor not in builder_text:
            fail(f"native-install builder lacks S19k anchor: {anchor}")
    for anchor in ('. "$SCRIPT_DIR/lib/am3_geometry.sh"',
                   "CLEAR_FOR_FLASH=false",
                   'if [ "$CLEAR_FOR_FLASH" != true ]; then',
                   "refusing flash_erase/nandwrite/fw_setenv"):
        if anchor not in writer_text:
            fail(f"persistent writer lacks disabled anchor: {anchor}")
    if "CLEAR_FOR_FLASH=true" in writer_text:
        fail("persistent writer contains enabled CLEAR_FOR_FLASH assignment")
    return {
        "schema": CONTRACT_SCHEMA,
        "board": BOARD,
        "provenance": {
            "source_commit": source_commit,
            "source_date_epoch": source_date_epoch,
            "build_target": build_target,
            "build_arch": build_arch,
            "toolchain_id": toolchain_id,
        },
        "rootfs_payload": {"path": PACKAGE_ROOT_PATH,
                           "sha256": _hash(root_uimage),
                           "bytes": len(root_uimage)},
        "aml_rootfs_geometry": {
            "mtd": ROOTFS_MTD, "offset_hex": ROOTFS_OFFSET_HEX,
            "offset_bytes": ROOTFS_OFFSET_BYTES,
            "window_hex": ROOTFS_WINDOW_HEX,
            "window_bytes": ROOTFS_WINDOW_BYTES,
            "erase_size_bytes": ROOTFS_ERASE_SIZE,
            "erase_count": ROOTFS_ERASE_COUNT,
        },
        "safeoff_boot_baseline": baseline,
        "native_owner": {
            "path": PACKAGE_NATIVE_PATH,
            "receipt_sha256": _hash(native_receipt_bytes),
            "verification_id": native_id,
            "source_files_sha256": _hash(canonical_json(native["source_files"])),
            "artifact_path": owner_artifact["path"],
            "artifact_sha256": owner_artifact["sha256"],
            "artifact_bytes": owner_artifact["bytes"],
            "aarch64_compile_contract": native["aarch64_compile_contract"],
            "build_binding": native["native_owner_build_binding"],
            "native_build_verification_id": native["native_build_receipt"][
                "verification_id"
            ],
            "capsule_build_receipt_sha256": native["native_build_receipt"][
                "capsule_build_receipt_sha256"
            ],
            "source_commit": native["native_build_receipt"][
                "capsule_build_receipt"
            ]["git"]["commit"],
            "source_snapshot_id": native["native_build_receipt"][
                "capsule_build_receipt"
            ]["release_capsule"]["source_snapshot_id"],
            "release_invocation_id": native["native_build_receipt"][
                "capsule_build_receipt"
            ]["release_capsule"]["release_invocation_id"],
            "cargo_metadata_sha256": native["native_build_receipt"][
                "capsule_build_receipt"
            ]["cargo_metadata"]["sha256"],
            "manifest_public_key_hex": native_manifest_key_hex,
            "manifest_public_key_sha256": native["native_build_receipt"][
                "manifest_public_key_sha256"
            ],
        },
        "stock_recovery": {
            "path": PACKAGE_RECOVERY_PATH,
            "receipt_sha256": _hash(recovery_receipt_bytes),
            "verification_id": recovery_id,
            "device_id": recovery["device_id"],
            "stock_bmu_sha256": recovery["stock_bmu"]["sha256"],
        },
        "release_key": {"path": PACKAGE_KEY_PATH,
                        "sha256": _hash(release_key_bytes),
                        "key_id": key_id,
                        "raw_public_key_hex": raw_public_key_hex},
        "install_route": {
            "builder_path": PACKAGE_BUILDER_PATH,
            "builder_sha256": _hash(builder_bytes),
            "writer_path": PACKAGE_WRITER_PATH,
            "writer_sha256": _hash(writer_bytes),
            "writer_clear_for_flash": False,
            "separate_install_authority_required": True,
        },
        "authority": {"install_authority_granted": False,
                      "mutation_authority_granted": False,
                      "nand_write_authorized": False},
    }


@dataclass(frozen=True)
class PublicBuildPairValidation:
    """Exact public validation completed before any private-key access."""

    package: Package
    build_receipts: tuple[dict[str, Any], dict[str, Any]]
    manifest: dict[str, Any]
    manifest_bytes: bytes
    provenance: dict[str, Any]
    expected_contract: dict[str, Any]
    trusted_key: bytes
    release_key_id: str
    raw_public_key_hex: str
    native: dict[str, Any]
    native_verification_id: str
    recovery: dict[str, Any]
    recovery_verification_id: str


def _verify_build_pair_receipts(
    packages_raw: Sequence[bytes], receipt_raw: Sequence[bytes]
) -> tuple[dict[str, Any], dict[str, Any]]:
    if len(packages_raw) != 2 or len(receipt_raw) != 2:
        fail("unsigned A/B validation requires exactly two packages and receipts")
    if packages_raw[0] != packages_raw[1]:
        fail("two clean S19k unsigned build outputs are not byte-identical")
    receipts = tuple(
        _verify_build_receipt(raw, package_name, package)
        for raw, package_name, package in zip(
            receipt_raw, BUILD_PACKAGE_FILES, packages_raw
        )
    )
    if (
        receipts[0]["build_id"] == receipts[1]["build_id"]
        or receipts[0]["build_root_id"] == receipts[1]["build_root_id"]
    ):
        fail("attestations must identify two distinct builds and roots")
    shared = (
        "source_commit", "source_date_epoch", "build_target", "build_arch",
        "toolchain_id", "package_sha256", "package_bytes",
    )
    for field in shared:
        if receipts[0][field] != receipts[1][field]:
            fail(f"reproducibility attestations disagree on {field}")
    return receipts


def _validate_package_public_contract(
    package: Package,
    trusted_key: bytes,
    native_external: bytes,
    recovery_external: bytes,
    build_receipt: Mapping[str, Any],
    *,
    expected_release_key_sha256: str,
    signature_required: bool,
) -> PublicBuildPairValidation:
    expected_key_sha = _hex64(
        expected_release_key_sha256, "externally expected release-key SHA-256"
    )
    if _hash(trusted_key) != expected_key_sha:
        fail("trusted release key does not match external expected identity")
    if package.files[PACKAGE_KEY_PATH] != trusted_key:
        fail("packaged release key differs from out-of-band trusted key")
    if package.files[PACKAGE_NATIVE_PATH] != native_external:
        fail("packaged native-owner receipt differs from exact supplied receipt")
    if package.files[PACKAGE_RECOVERY_PATH] != recovery_external:
        fail("packaged stock-recovery receipt differs from exact supplied receipt")

    key, key_id, raw_public_key_hex = _public_key_identity(trusted_key)
    manifest_bytes = package.files[PACKAGE_MANIFEST_PATH]
    if signature_required:
        signature = package.files[PACKAGE_SIGNATURE_PATH]
        if len(signature) != 64:
            fail("MANIFEST.sig is not exact 64-byte Ed25519 signature")
        try:
            key.verify(signature, manifest_bytes)
        except Exception as error:
            fail(f"signed manifest verification failed: {type(error).__name__}")
    elif PACKAGE_SIGNATURE_PATH in package.files:
        fail("unsigned intermediate must not contain MANIFEST.sig")

    manifest = _json_bytes(manifest_bytes, "release manifest", canonical=False)
    if (
        manifest.get("schema") != 1
        or manifest.get("manifest_profile") != "dcentos.sysupgrade-authority/v1"
        or manifest.get("product") != "DCENT_OS"
        or manifest.get("family") != "antminer"
        or manifest.get("package_type") != "sysupgrade"
        or manifest.get("installable") is not True
        or manifest.get("artifact_maturity") != "experimental"
        or manifest.get("board_family") != "am3"
        or manifest.get("board") != BOARD
        or manifest.get("board_target") != BOARD
        or manifest.get("status") != "release"
        or manifest.get("target_side_sysupgrade") is not False
    ):
        fail("release manifest is not exact S19k host-driven release profile")
    toolbox = manifest.get("toolbox")
    if (
        not isinstance(toolbox, dict)
        or toolbox.get("install_mode") != "host_driven_rootfs_window_lab"
        or toolbox.get("target_side_sysupgrade") is not False
    ):
        fail("release manifest lacks exact host-driven rootfs-window profile")
    for command_name in ("install_command", "update_command"):
        command = toolbox.get(command_name)
        if (
            not isinstance(command, str)
            or "--artifact-dir" not in command
            or "--yes" in command
            or "--accept-vnish-aml-rootfs-window" in command
        ):
            fail(f"release manifest {command_name} bypasses operator gate")
    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        fail("release manifest lacks build provenance")
    for field in (
        "source_commit", "source_date_epoch", "build_target", "build_arch",
        "toolchain_id",
    ):
        if provenance.get(field) != build_receipt[field]:
            fail(f"release manifest provenance disagrees on {field}")
    if (
        provenance.get("source_tree_state")
        not in ("clean", "exact_git_object_snapshot")
        or provenance.get("source_commit_epoch")
        != provenance.get("source_date_epoch")
    ):
        fail("release manifest does not prove exact clean source snapshot")

    sums = _parse_sums(package.files[PACKAGE_SUMS_PATH])
    payload_names = {
        "kernel": PACKAGE_KERNEL_PATH,
        "root": PACKAGE_ROOT_PATH,
        "METADATA": PACKAGE_METADATA_PATH,
        "release_ed25519.pub": PACKAGE_KEY_PATH,
        NATIVE_RECEIPT_FILE: PACKAGE_NATIVE_PATH,
        RECOVERY_RECEIPT_FILE: PACKAGE_RECOVERY_PATH,
        "IMAGE_CONTRACT.json": PACKAGE_CONTRACT_PATH,
        BUILDER_LEAF: PACKAGE_BUILDER_PATH,
        WRITER_LEAF: PACKAGE_WRITER_PATH,
    }
    for leaf, path in payload_names.items():
        if sums[leaf] != _hash(package.files[path]):
            fail(f"SHA256SUMS does not bind exact {leaf} bytes")
    _manifest_payload(
        manifest, "kernel", PACKAGE_KERNEL_PATH, package.files[PACKAGE_KERNEL_PATH]
    )
    _manifest_payload(
        manifest, "rootfs", PACKAGE_ROOT_PATH, package.files[PACKAGE_ROOT_PATH]
    )
    _manifest_payload(
        manifest, "metadata", PACKAGE_METADATA_PATH, package.files[PACKAGE_METADATA_PATH]
    )
    _manifest_payload(manifest, "verification_key", PACKAGE_KEY_PATH, trusted_key)
    _manifest_payload(
        manifest, "native_owner_verification", PACKAGE_NATIVE_PATH, native_external
    )
    _manifest_payload(
        manifest,
        "stock_recovery_verification",
        PACKAGE_RECOVERY_PATH,
        recovery_external,
    )
    _manifest_payload(
        manifest,
        "persistent_image_contract",
        PACKAGE_CONTRACT_PATH,
        package.files[PACKAGE_CONTRACT_PATH],
    )
    _manifest_payload(
        manifest,
        "native_install_builder",
        PACKAGE_BUILDER_PATH,
        package.files[PACKAGE_BUILDER_PATH],
    )
    _manifest_payload(
        manifest,
        "persistent_install_writer",
        PACKAGE_WRITER_PATH,
        package.files[PACKAGE_WRITER_PATH],
    )

    expected_contract = build_image_contract(
        package.files[PACKAGE_ROOT_PATH],
        native_external,
        recovery_external,
        trusted_key,
        package.files[PACKAGE_BUILDER_PATH],
        package.files[PACKAGE_WRITER_PATH],
        source_commit=provenance["source_commit"],
        source_date_epoch=provenance["source_date_epoch"],
        build_target=provenance["build_target"],
        build_arch=provenance["build_arch"],
        toolchain_id=provenance["toolchain_id"],
        expected_release_key_sha256=expected_key_sha,
    )
    contract = _json_bytes(
        package.files[PACKAGE_CONTRACT_PATH], "persistent image contract"
    )
    if contract != expected_contract:
        fail("embedded image contract is stale or does not bind exact evidence")
    for member in package.members:
        if (
            member.mtime != provenance["source_date_epoch"]
            or member.uid != 0
            or member.gid != 0
            or member.uname != ""
            or member.gname != ""
            or member.pax_headers
        ):
            fail(f"tar metadata for {member.name} is not deterministic")
        if member.mode & 0o6000:
            fail(f"tar member {member.name} carries set-id bits")

    native, native_id = _verify_native_receipt(
        native_external, expected_source_commit=provenance["source_commit"]
    )
    recovery, recovery_id = _verify_recovery_receipt(recovery_external)
    return PublicBuildPairValidation(
        package=package,
        build_receipts=(dict(build_receipt), dict(build_receipt)),
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        provenance=dict(provenance),
        expected_contract=expected_contract,
        trusted_key=trusted_key,
        release_key_id=key_id,
        raw_public_key_hex=raw_public_key_hex,
        native=native,
        native_verification_id=native_id,
        recovery=recovery,
        recovery_verification_id=recovery_id,
    )


def validate_unsigned_build_pair(
    build_a: bytes,
    build_b: bytes,
    build_a_receipt: bytes,
    build_b_receipt: bytes,
    trusted_key: bytes,
    native_owner_receipt: bytes,
    stock_recovery_receipt: bytes,
    *,
    expected_release_key_sha256: str,
) -> PublicBuildPairValidation:
    """Validate every public input before a post-A/B signer may open a key."""

    receipts = _verify_build_pair_receipts(
        (build_a, build_b), (build_a_receipt, build_b_receipt)
    )
    package = _parse_package(
        build_a, BUILD_PACKAGE_FILES[0], signature_required=False
    )
    validated = _validate_package_public_contract(
        package,
        trusted_key,
        native_owner_receipt,
        stock_recovery_receipt,
        receipts[0],
        expected_release_key_sha256=expected_release_key_sha256,
        signature_required=False,
    )
    return PublicBuildPairValidation(
        **{
            **validated.__dict__,
            "build_receipts": receipts,
        }
    )


def _tar_member_binding(member: tarfile.TarInfo) -> tuple[Any, ...]:
    return (
        _safe_tar_path(member.name),
        member.type,
        member.mode,
        member.uid,
        member.gid,
        member.uname,
        member.gname,
        member.mtime,
        member.size,
        member.linkname,
        tuple(sorted(member.pax_headers.items())),
    )


def _verify_signed_derivation(
    unsigned: Package, signed: Package, *, source_date_epoch: int
) -> None:
    if set(signed.files) != set(unsigned.files) | {PACKAGE_SIGNATURE_PATH}:
        fail("signed package does not add exactly MANIFEST.sig")
    for name, value in unsigned.files.items():
        if signed.files.get(name) != value:
            fail(f"signed package changed unsigned member bytes: {name}")
    unsigned_members = {
        _safe_tar_path(member.name): member for member in unsigned.members
    }
    signed_members = {_safe_tar_path(member.name): member for member in signed.members}
    for name, member in unsigned_members.items():
        if name not in signed_members or _tar_member_binding(member) != _tar_member_binding(
            signed_members[name]
        ):
            fail(f"signed package changed unsigned tar metadata: {name}")
    signature = signed_members.get(PACKAGE_SIGNATURE_PATH)
    if (
        signature is None
        or not signature.isfile()
        or signature.size != 64
        or signature.mode != 0o644
        or signature.uid != 0
        or signature.gid != 0
        or signature.uname != ""
        or signature.gname != ""
        or signature.mtime != source_date_epoch
        or signature.linkname
        or signature.pax_headers
    ):
        fail("signed package MANIFEST.sig metadata is not exact deterministic ustar")


def _verify_signing_receipt(
    data: bytes,
    *,
    unsigned_a: bytes,
    unsigned_b: bytes,
    signed: Package,
    trusted_key: bytes,
    validation: PublicBuildPairValidation,
) -> dict[str, Any]:
    receipt = _json_bytes(data, "post-A/B signing receipt")
    _exact_keys(receipt, SIGNING_RECEIPT_KEYS, "post-A/B signing receipt")
    body = dict(receipt)
    observed_id = _hex64(body.pop("signing_id"), "post-A/B signing_id")
    if observed_id != _hash(canonical_json(body)):
        fail("post-A/B signing_id does not bind the exact receipt")
    signature = signed.files[PACKAGE_SIGNATURE_PATH]
    expected = {
        "schema": SIGNING_RECEIPT_SCHEMA,
        "build_a_package_sha256": _hash(unsigned_a),
        "build_a_package_bytes": len(unsigned_a),
        "build_b_package_sha256": _hash(unsigned_b),
        "build_b_package_bytes": len(unsigned_b),
        "unsigned_package_sha256": _hash(unsigned_a),
        "unsigned_package_bytes": len(unsigned_a),
        "signed_package_name": SIGNED_PACKAGE_FILE,
        "signed_package_sha256": _hash(signed.raw),
        "signed_package_bytes": len(signed.raw),
        "manifest_sha256": _hash(validation.manifest_bytes),
        "manifest_bytes": len(validation.manifest_bytes),
        "manifest_signature_sha256": _hash(signature),
        "manifest_signature_bytes": len(signature),
        "release_key_sha256": _hash(trusted_key),
        "release_key_bytes": len(trusted_key),
        "source_commit": validation.provenance["source_commit"],
        "source_date_epoch": validation.provenance["source_date_epoch"],
        "build_target": validation.provenance["build_target"],
        "build_arch": validation.provenance["build_arch"],
        "toolchain_id": validation.provenance["toolchain_id"],
        "a_b_equality_verified_before_private_key_open": True,
        "public_inputs_verified_before_private_key_open": True,
        "private_key_open_count": 1,
        "derivation": "add-exact-ed25519-manifest-signature-only",
        "output_no_replace": True,
        "network_used": False,
        "install_authority_granted": False,
        "flash_authority_granted": False,
        "mutation_authority_granted": False,
    }
    if body != expected:
        fail("post-A/B signing receipt does not exact-bind inputs and output")
    receipt["signing_id"] = observed_id
    return receipt


def _verify_host_preflight(raw: bytes) -> dict[str, Any]:
    report = _json_bytes(raw, "host preflight")
    _exact_keys(
        report,
        (
            "schema",
            "claim",
            "capacity_model",
            "docker",
            "docker_trust_nonclaim",
            "roots",
            "production_ready",
            "release_authority_granted",
            "install_authority_granted",
            "flash_authority_granted",
            "component_sha256",
            "preflight_id",
        ),
        "host preflight",
    )
    body = dict(report)
    component_sha256 = body.pop("component_sha256")
    preflight_id = body.pop("preflight_id")
    docker = report["docker"]
    roots = report["roots"]
    capacity = report["capacity_model"]
    if (
        report["schema"] != "dcentos.s19k-hermetic-host-preflight/v1"
        or report["claim"] != "host-custody-and-worst-case-capacity-preflight-only"
        or not isinstance(component_sha256, str)
        or len(component_sha256) != 64
        or any(character not in "0123456789abcdef" for character in component_sha256)
        or preflight_id != _hash(canonical_json(body))
        or not isinstance(docker, dict)
        or report["docker_trust_nonclaim"]
        != (
            "client-bytes-and-client-server-version-only; daemon-endpoint-context-"
            "daemon-id-rootless-kernel-and-security-posture-not-bound"
        )
        or not isinstance(docker.get("binary"), dict)
        or set(docker["binary"]) != {"path", "sha256", "bytes"}
        or not isinstance(docker["binary"]["path"], str)
        or not docker["binary"]["path"].startswith("/")
        or not isinstance(docker["binary"]["sha256"], str)
        or len(docker["binary"]["sha256"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in docker["binary"]["sha256"]
        )
        or isinstance(docker["binary"]["bytes"], bool)
        or not isinstance(docker["binary"]["bytes"], int)
        or docker["binary"]["bytes"] <= 0
        or not isinstance(roots, list)
        or not roots
        or not isinstance(capacity, dict)
        or report["production_ready"] is not False
        or report["release_authority_granted"] is not False
        or report["install_authority_granted"] is not False
        or report["flash_authority_granted"] is not False
    ):
        fail("host preflight is invalid, stale, or authority-bearing")
    for root in roots:
        if (
            not isinstance(root, dict)
            or root.get("filesystem") != "ext4"
            or root.get("mode") != "0700"
            or "rw" not in root.get("mount_options", [])
            or isinstance(root.get("uid"), bool)
            or not isinstance(root.get("uid"), int)
            or root["uid"] < 1000
            or isinstance(root.get("gid"), bool)
            or not isinstance(root.get("gid"), int)
            or root["gid"] < 1000
        ):
            fail("host preflight contains an unadmitted production root")
    return report


def _verify_signer_runtime(
    raw: bytes,
    *,
    inspect_before_raw: bytes,
    inspect_after_raw: bytes,
    log_raw: bytes,
    signed_raw: bytes,
    signing_receipt_raw: bytes,
    host_preflight: Mapping[str, Any],
) -> dict[str, Any]:
    value = _json_bytes(raw, "isolated signer runtime")
    _exact_keys(
        value,
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
        "isolated signer runtime",
    )
    for field in (
        "private_key_custody_id",
        "verifier_sha256",
        "signer_sha256",
        "inspect_before_sha256",
        "inspect_after_sha256",
        "log_sha256",
        "signed_package_sha256",
        "signing_receipt_sha256",
    ):
        _hex64(value.get(field), f"isolated signer {field}")
    if (
        value["schema"] != "dcentos.s19k-hermetic-isolated-signer-runtime/v1"
        or value["network_mode"] != "none"
        or value["network_boundary_inspected_before_after"] is not True
        or value["read_only_rootfs"] is not True
        or value["privileged"] is not False
        or value["host_preflight_id"] != host_preflight["preflight_id"]
        or value["inspect_before_sha256"] != _hash(inspect_before_raw)
        or value["inspect_after_sha256"] != _hash(inspect_after_raw)
        or value["log_sha256"] != _hash(log_raw)
        or value["log_bytes"] != len(log_raw)
        or value["signed_package_sha256"] != _hash(signed_raw)
        or value["signed_package_bytes"] != len(signed_raw)
        or value["signing_receipt_sha256"] != _hash(signing_receipt_raw)
        or value["signing_receipt_bytes"] != len(signing_receipt_raw)
        or value["container_removed_after_stop_proof"] is not True
        or value["install_authority_granted"] is not False
        or value["flash_authority_granted"] is not False
        or value["mutation_authority_granted"] is not False
    ):
        fail("isolated signer runtime receipt does not bind exact no-network evidence")
    before = _json_bytes(inspect_before_raw, "signer inspect-before")
    after = _json_bytes(inspect_after_raw, "signer inspect-after")
    for label, inspected in (("before", before), ("after", after)):
        config = inspected.get("Config")
        host = inspected.get("HostConfig")
        networks = (inspected.get("NetworkSettings") or {}).get("Networks")
        mounts = inspected.get("Mounts")
        if (
            inspected.get("Id") != value["runtime_id"]
            or not isinstance(config, dict)
            or config.get("Hostname") != "dcent-s19k-signer"
            or config.get("Domainname") != "signer.invalid"
            or config.get("User") in (None, "", "0", "0:0")
            or not isinstance(host, dict)
            or host.get("NetworkMode") != "none"
            or host.get("ReadonlyRootfs") is not True
            or host.get("Privileged") is not False
            or "ALL" not in (host.get("CapDrop") or [])
            or not isinstance(networks, dict)
            or set(networks) != {"none"}
            or not isinstance(mounts, list)
            or {item.get("Destination") for item in mounts if isinstance(item, dict)}
            != {
                "/dcent/source-snapshot",
                "/dcent/public",
                "/dcent/private/release.pem",
                "/dcent/output",
                "/run",
            }
        ):
            fail(f"signer inspect-{label} does not replay the isolated boundary")
    return value


def verify_evidence(evidence_dir: Path, *,
                    expected_release_key_sha256: str | None = None) -> dict[str, Any]:
    if not evidence_dir.is_dir() or evidence_dir.is_symlink():
        fail(f"evidence directory is absent or symlink: {evidence_dir}")
    required_evidence = {
        *BUILD_PACKAGE_FILES,
        *BUILD_RECEIPT_FILES,
        SIGNED_PACKAGE_FILE,
        SIGNING_RECEIPT_FILE,
        HOST_PREFLIGHT_FILE,
        SIGNER_RUNTIME_FILE,
        SIGNER_INSPECT_BEFORE_FILE,
        SIGNER_INSPECT_AFTER_FILE,
        SIGNER_LOG_FILE,
        TRUSTED_KEY_FILE,
        NATIVE_RECEIPT_FILE,
        RECOVERY_RECEIPT_FILE,
    }
    observed_evidence = {entry.name for entry in evidence_dir.iterdir()}
    if observed_evidence not in (required_evidence, required_evidence | {VERIFICATION_FILE}):
        fail("persistent-image evidence file set is not exact v4")
    packages_raw = [_read_regular(evidence_dir / name, MAX_PACKAGE_BYTES, name)
                    for name in BUILD_PACKAGE_FILES]
    build_receipt_raw = [
        _read_regular(evidence_dir / name, MAX_JSON_BYTES, name)
        for name in BUILD_RECEIPT_FILES
    ]
    trusted_key = _read_regular(evidence_dir / TRUSTED_KEY_FILE,
                                MAX_KEY_BYTES, TRUSTED_KEY_FILE)
    expected_key_sha = (expected_release_key_sha256
                        or os.environ.get("DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256"))
    if not expected_key_sha:
        fail("external trusted key identity is required via "
             "DCENT_S19K_EXPECTED_RELEASE_KEY_SHA256")
    expected_key_sha = _hex64(expected_key_sha,
                              "externally expected release-key SHA-256")
    native_external = _read_regular(evidence_dir / NATIVE_RECEIPT_FILE,
                                    MAX_JSON_BYTES, NATIVE_RECEIPT_FILE)
    recovery_external = _read_regular(evidence_dir / RECOVERY_RECEIPT_FILE,
                                      MAX_JSON_BYTES, RECOVERY_RECEIPT_FILE)
    unsigned_validation = validate_unsigned_build_pair(
        packages_raw[0],
        packages_raw[1],
        build_receipt_raw[0],
        build_receipt_raw[1],
        trusted_key,
        native_external,
        recovery_external,
        expected_release_key_sha256=expected_key_sha,
    )
    build_receipts = list(unsigned_validation.build_receipts)
    signed_raw = _read_regular(
        evidence_dir / SIGNED_PACKAGE_FILE, MAX_PACKAGE_BYTES, SIGNED_PACKAGE_FILE
    )
    package = _parse_package(
        signed_raw, SIGNED_PACKAGE_FILE, signature_required=True
    )
    _verify_signed_derivation(
        unsigned_validation.package,
        package,
        source_date_epoch=unsigned_validation.provenance["source_date_epoch"],
    )
    if package.files[PACKAGE_KEY_PATH] != trusted_key:
        fail("packaged release key differs from out-of-band trusted key")
    if package.files[PACKAGE_NATIVE_PATH] != native_external:
        fail("packaged native-owner receipt differs from exact supplied receipt")
    if package.files[PACKAGE_RECOVERY_PATH] != recovery_external:
        fail("packaged stock-recovery receipt differs from exact supplied receipt")

    key, key_id, raw_public_key_hex = _public_key_identity(trusted_key)
    signature = package.files[PACKAGE_SIGNATURE_PATH]
    if len(signature) != 64:
        fail("MANIFEST.sig is not exact 64-byte Ed25519 signature")
    manifest_bytes = package.files[PACKAGE_MANIFEST_PATH]
    try:
        key.verify(signature, manifest_bytes)
    except Exception as error:
        fail(f"signed manifest verification failed: {type(error).__name__}")
    manifest = _json_bytes(manifest_bytes, "signed manifest", canonical=False)
    if (manifest.get("schema") != 1
            or manifest.get("manifest_profile") !=
            "dcentos.sysupgrade-authority/v1"
            or manifest.get("product") != "DCENT_OS"
            or manifest.get("family") != "antminer"
            or manifest.get("package_type") != "sysupgrade"
            or manifest.get("installable") is not True
            or manifest.get("artifact_maturity") != "experimental"
            or manifest.get("board_family") != "am3"
            or manifest.get("board") != BOARD
            or manifest.get("board_target") != BOARD
            or manifest.get("status") != "release"
            or manifest.get("target_side_sysupgrade") is not False):
        fail("signed manifest is not exact S19k host-driven release profile")
    toolbox = manifest.get("toolbox")
    if (not isinstance(toolbox, dict)
            or toolbox.get("install_mode") != "host_driven_rootfs_window_lab"
            or toolbox.get("target_side_sysupgrade") is not False):
        fail("signed manifest lacks exact host-driven rootfs-window profile")
    for command_name in ("install_command", "update_command"):
        command = toolbox.get(command_name)
        if (not isinstance(command, str) or "--artifact-dir" not in command
                or "--yes" in command
                or "--accept-vnish-aml-rootfs-window" in command):
            fail(f"signed manifest {command_name} bypasses operator gate")
    provenance = manifest.get("provenance")
    if not isinstance(provenance, dict):
        fail("signed manifest lacks build provenance")
    for field in ("source_commit", "source_date_epoch", "build_target",
                  "build_arch", "toolchain_id"):
        if provenance.get(field) != build_receipts[0][field]:
            fail(f"signed manifest provenance disagrees on {field}")
    if (provenance.get("source_tree_state") not in
            ("clean", "exact_git_object_snapshot")
            or provenance.get("source_commit_epoch") !=
            provenance.get("source_date_epoch")):
        fail("signed manifest does not prove exact clean source snapshot")

    sums = _parse_sums(package.files[PACKAGE_SUMS_PATH])
    payload_names = {
        "kernel": PACKAGE_KERNEL_PATH, "root": PACKAGE_ROOT_PATH,
        "METADATA": PACKAGE_METADATA_PATH,
        "release_ed25519.pub": PACKAGE_KEY_PATH,
        NATIVE_RECEIPT_FILE: PACKAGE_NATIVE_PATH,
        RECOVERY_RECEIPT_FILE: PACKAGE_RECOVERY_PATH,
        "IMAGE_CONTRACT.json": PACKAGE_CONTRACT_PATH,
        BUILDER_LEAF: PACKAGE_BUILDER_PATH,
        WRITER_LEAF: PACKAGE_WRITER_PATH,
    }
    for leaf, path in payload_names.items():
        if sums[leaf] != _hash(package.files[path]):
            fail(f"SHA256SUMS does not bind exact {leaf} bytes")
    _manifest_payload(manifest, "kernel", PACKAGE_KERNEL_PATH,
                      package.files[PACKAGE_KERNEL_PATH])
    _manifest_payload(manifest, "rootfs", PACKAGE_ROOT_PATH,
                      package.files[PACKAGE_ROOT_PATH])
    _manifest_payload(manifest, "metadata", PACKAGE_METADATA_PATH,
                      package.files[PACKAGE_METADATA_PATH])
    _manifest_payload(manifest, "verification_key", PACKAGE_KEY_PATH, trusted_key)
    _manifest_payload(manifest, "native_owner_verification",
                      PACKAGE_NATIVE_PATH, native_external)
    _manifest_payload(manifest, "stock_recovery_verification",
                      PACKAGE_RECOVERY_PATH, recovery_external)
    _manifest_payload(manifest, "persistent_image_contract",
                      PACKAGE_CONTRACT_PATH, package.files[PACKAGE_CONTRACT_PATH])
    _manifest_payload(manifest, "native_install_builder", PACKAGE_BUILDER_PATH,
                      package.files[PACKAGE_BUILDER_PATH])
    _manifest_payload(manifest, "persistent_install_writer", PACKAGE_WRITER_PATH,
                      package.files[PACKAGE_WRITER_PATH])

    expected_contract = build_image_contract(
        package.files[PACKAGE_ROOT_PATH], native_external, recovery_external,
        trusted_key, package.files[PACKAGE_BUILDER_PATH],
        package.files[PACKAGE_WRITER_PATH],
        source_commit=provenance["source_commit"],
        source_date_epoch=provenance["source_date_epoch"],
        build_target=provenance["build_target"],
        build_arch=provenance["build_arch"],
        toolchain_id=provenance["toolchain_id"],
        expected_release_key_sha256=expected_key_sha)
    contract = _json_bytes(package.files[PACKAGE_CONTRACT_PATH],
                           "persistent image contract")
    if contract != expected_contract:
        fail("embedded image contract is stale or does not bind exact evidence")
    for member in package.members:
        if (member.mtime != provenance["source_date_epoch"]
                or member.uid != 0 or member.gid != 0):
            fail(f"tar metadata for {member.name} is not deterministic")
        if member.mode & 0o6000:
            fail(f"tar member {member.name} carries set-id bits")

    native, native_id = _verify_native_receipt(
        native_external, expected_source_commit=provenance["source_commit"]
    )
    recovery, recovery_id = _verify_recovery_receipt(recovery_external)
    signing_receipt_raw = _read_regular(
        evidence_dir / SIGNING_RECEIPT_FILE,
        MAX_JSON_BYTES,
        SIGNING_RECEIPT_FILE,
    )
    signing_receipt = _verify_signing_receipt(
        signing_receipt_raw,
        unsigned_a=packages_raw[0],
        unsigned_b=packages_raw[1],
        signed=package,
        trusted_key=trusted_key,
        validation=unsigned_validation,
    )
    host_preflight_raw = _read_regular(
        evidence_dir / HOST_PREFLIGHT_FILE,
        MAX_JSON_BYTES,
        HOST_PREFLIGHT_FILE,
    )
    host_preflight = _verify_host_preflight(host_preflight_raw)
    signer_runtime_raw = _read_regular(
        evidence_dir / SIGNER_RUNTIME_FILE,
        MAX_JSON_BYTES,
        SIGNER_RUNTIME_FILE,
    )
    signer_runtime = _verify_signer_runtime(
        signer_runtime_raw,
        inspect_before_raw=_read_regular(
            evidence_dir / SIGNER_INSPECT_BEFORE_FILE,
            MAX_JSON_BYTES,
            SIGNER_INSPECT_BEFORE_FILE,
        ),
        inspect_after_raw=_read_regular(
            evidence_dir / SIGNER_INSPECT_AFTER_FILE,
            MAX_JSON_BYTES,
            SIGNER_INSPECT_AFTER_FILE,
        ),
        log_raw=_read_regular(
            evidence_dir / SIGNER_LOG_FILE,
            MAX_JSON_BYTES,
            SIGNER_LOG_FILE,
        ),
        signed_raw=signed_raw,
        signing_receipt_raw=signing_receipt_raw,
        host_preflight=host_preflight,
    )
    root_data = package.files[PACKAGE_ROOT_PATH]
    result: dict[str, Any] = {
        "schema": RESULT_SCHEMA, "phase_id": "persistent-image",
        "classification": "verified", "installable": True, "board": BOARD,
        "image_sha256": _hash(root_data), "image_bytes": len(root_data),
        "package_sha256": _hash(signed_raw),
        "package_bytes": len(signed_raw),
        "unsigned_package_sha256": _hash(packages_raw[0]),
        "unsigned_package_bytes": len(packages_raw[0]),
        "a_b_unsigned_equality_verified": True,
        "private_key_excluded_from_builds": True,
        # The v4 receipt replays the retained runtime metadata, signed-package
        # derivation, and private-custody identifier.  It does not yet receive
        # an independently authenticated source-authority projection binding
        # the exact signer/verifier bytes, OCI image/config digests, command,
        # mounts, and daemon security posture.  A self-authored evidence tree
        # must therefore never promote itself to an isolation proof.
        "isolated_post_ab_signing_verified": False,
        "post_ab_derivation_and_runtime_metadata_verified": True,
        "isolated_post_ab_signing_nonclaim": (
            "retained-runtime-metadata-is-not-joined-to-independent-source-"
            "authority-and-exact-oci-boundary"
        ),
        "post_ab_signing_id": signing_receipt["signing_id"],
        "post_ab_signing_receipt_sha256": _hash(signing_receipt_raw),
        "host_preflight_id": host_preflight["preflight_id"],
        "host_preflight_receipt_sha256": _hash(host_preflight_raw),
        "host_preflight_component_sha256": host_preflight["component_sha256"],
        "isolated_signer_runtime_id": signer_runtime["runtime_id"],
        "isolated_signer_runtime_receipt_sha256": _hash(signer_runtime_raw),
        "isolated_signer_private_key_custody_id": signer_runtime[
            "private_key_custody_id"
        ],
        "source_commit": provenance["source_commit"],
        "source_date_epoch": provenance["source_date_epoch"],
        "release_key_sha256": _hash(trusted_key), "release_key_id": key_id,
        "release_manifest_public_key_hex": raw_public_key_hex,
        "signed_manifest_sha256": _hash(manifest_bytes),
        "persistent_image_contract_sha256":
            _hash(package.files[PACKAGE_CONTRACT_PATH]),
        "native_owner_verification_id": native_id,
        "native_owner_receipt_sha256": _hash(native_external),
        "native_owner_artifact_sha256":
            native["native_owner_artifact"]["sha256"],
        "native_owner_source_files_sha256":
            _hash(canonical_json(native["source_files"])),
        "native_owner_aarch64_compile_contract_bound": True,
        "native_owner_source_artifact_build_binding_verified": True,
        "native_owner_clean_source_commit_bound": True,
        "stock_recovery_verification_id": recovery_id,
        "stock_recovery_receipt_sha256": _hash(recovery_external),
        "stock_recovery_device_id": recovery["device_id"],
        "aml_rootfs_geometry": expected_contract["aml_rootfs_geometry"],
        "safeoff_boot_baseline": expected_contract["safeoff_boot_baseline"],
        "reproducible_builds_verified": True,
        "signed_manifest_verified": True,
        "native_owner_artifact_bound": True,
        "stock_recovery_receipt_bound": True,
        "install_authority_granted": False,
        "mutation_authority_granted": False,
        "nand_write_authorized": False,
        "live_hardware_contacted": False, "network_used": False,
    }
    result["verification_id"] = _hash(canonical_json(result))
    receipt_path = evidence_dir / VERIFICATION_FILE
    if (receipt_path.exists()
            and _read_regular(receipt_path, MAX_JSON_BYTES, VERIFICATION_FILE)
            != canonical_json(result)):
        fail("verification.json is stale or noncanonical")
    return result


def verify_workflow_evidence(evidence_dir: Path) -> dict[str, Any]:
    """Entry point consumed by ``s19k_gauntlet_workflow.py``."""
    return verify_evidence(evidence_dir)


def _write_verification_receipt(evidence_dir: Path,
                                result: Mapping[str, Any]) -> Path:
    """Materialize the canonical phase receipt without replacing evidence.

    The campaign controller consumes ``verification.json`` from the phase
    directory.  Keeping this write inside the verifier avoids a shell
    redirection race and guarantees that the retained bytes are exactly the
    freshly recomputed, self-bound result.  An already-present identical
    receipt is accepted for idempotent verification; any drift fails closed.
    """
    destination = evidence_dir / VERIFICATION_FILE
    expected = canonical_json(result)
    if destination.exists() or destination.is_symlink():
        observed = _read_regular(destination, MAX_JSON_BYTES, VERIFICATION_FILE)
        if observed != expected:
            fail("verification.json is stale or noncanonical")
        return destination

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(destination, flags, 0o600)
        created = True
        view = memoryview(expected)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                fail("short write while retaining verification.json")
            view = view[written:]
        os.fsync(descriptor)
    except FileExistsError:
        fail("refusing to replace concurrently-created verification.json")
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        if created:
            try:
                destination.unlink()
            except OSError:
                pass
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return destination


def _write_contract(args: argparse.Namespace) -> dict[str, Any]:
    contract = build_image_contract(
        _read_regular(args.root, ROOTFS_WINDOW_BYTES, "rootfs uImage"),
        _read_regular(args.native_owner_receipt, MAX_JSON_BYTES,
                      "native-owner receipt"),
        _read_regular(args.stock_recovery_receipt, MAX_JSON_BYTES,
                      "stock-recovery receipt"),
        _read_regular(args.release_key, MAX_KEY_BYTES, "release public key"),
        _read_regular(args.native_install_builder, MAX_JSON_BYTES,
                      "native-install builder"),
        _read_regular(args.persistent_install_writer, MAX_JSON_BYTES,
                      "persistent-install writer"),
        source_commit=args.source_commit,
        source_date_epoch=args.source_date_epoch,
        build_target=args.build_target, build_arch=args.build_arch,
        toolchain_id=args.toolchain_id,
        expected_release_key_sha256=args.expected_release_key_sha256)
    output: Path = args.output
    if output.exists() or output.is_symlink():
        fail(f"refusing to replace existing image contract: {output}")
    output.write_bytes(canonical_json(contract))
    return contract


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)
    sub.add_parser("audit-source")
    verify = sub.add_parser("verify")
    verify.add_argument("--evidence-dir", type=Path, required=True)
    verify.add_argument("--expected-release-key-sha256")
    verify.add_argument(
        "--write-receipt", action="store_true",
        help=("exclusively retain the freshly recomputed result as "
              "EVIDENCE_DIR/verification.json"),
    )
    contract = sub.add_parser("build-contract")
    contract.add_argument("--root", type=Path, required=True)
    contract.add_argument("--native-owner-receipt", type=Path, required=True)
    contract.add_argument("--stock-recovery-receipt", type=Path, required=True)
    contract.add_argument("--release-key", type=Path, required=True)
    contract.add_argument("--native-install-builder", type=Path, required=True)
    contract.add_argument("--persistent-install-writer", type=Path, required=True)
    contract.add_argument("--source-commit", required=True)
    contract.add_argument("--source-date-epoch", type=int, required=True)
    contract.add_argument("--build-target", required=True)
    contract.add_argument("--build-arch", required=True)
    contract.add_argument("--toolchain-id", required=True)
    contract.add_argument("--expected-release-key-sha256", required=True)
    contract.add_argument("--output", type=Path, required=True)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "audit-source":
            value = audit_source_tree()
        elif args.command == "verify":
            value = verify_evidence(
                args.evidence_dir,
                expected_release_key_sha256=args.expected_release_key_sha256)
            if args.write_receipt:
                _write_verification_receipt(args.evidence_dir, value)
        else:
            value = _write_contract(args)
    except (OSError, PersistentImageError) as error:
        print(f"S19K_PERSISTENT_IMAGE_REFUSED: {error}", file=sys.stderr)
        return 1
    print(canonical_json(value).decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
