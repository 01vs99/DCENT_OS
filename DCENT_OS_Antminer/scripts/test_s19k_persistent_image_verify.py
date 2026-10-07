#!/usr/bin/env python3
"""Adversarial host-only tests for the S19k persistent-image verifier."""

from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import stat
import struct
import sys
import tarfile
import tempfile
import unittest
import zlib


SCRIPT = Path(__file__).with_name("s19k_persistent_image_verify.py")
SPEC = importlib.util.spec_from_file_location("s19k_persistent_image_verify", SCRIPT)
assert SPEC and SPEC.loader
image = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = image
SPEC.loader.exec_module(image)


EPOCH = 1_700_000_000
COMMIT = "1" * 40
TOOLCHAIN = "buildroot-aarch64-test-v1"


def synthetic_aarch64_daemon() -> bytes:
    blob = bytearray(64 + 56 + 4)
    blob[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<H", blob, 16, 2)
    struct.pack_into("<H", blob, 18, 183)
    struct.pack_into("<I", blob, 20, 1)
    struct.pack_into("<Q", blob, 24, 0x400000)
    struct.pack_into("<Q", blob, 32, 64)
    struct.pack_into("<H", blob, 52, 64)
    struct.pack_into("<H", blob, 54, 56)
    struct.pack_into("<H", blob, 56, 1)
    struct.pack_into("<I", blob, 64, 1)
    struct.pack_into("<I", blob, 68, 5)
    struct.pack_into("<Q", blob, 72, 120)
    struct.pack_into("<Q", blob, 80, 0x400000)
    struct.pack_into("<Q", blob, 96, 4)
    struct.pack_into("<Q", blob, 104, 4)
    blob[120:124] = b"\x1f\x20\x03\xd5"
    return bytes(blob)


DAEMON = synthetic_aarch64_daemon()
BUILDER = b"""#!/bin/sh
case "$VARIANT" in
  s19kpro|s19k) : ;;
esac
DCENT_REQUIRE_INSTALLABLE_PACKAGE=1
[ "$ROOT_SIZE" -le "$DCENT_AM3_ROOTFS_WINDOW_DEC" ]
"""
WRITER = b"""#!/bin/sh
. "$SCRIPT_DIR/lib/am3_geometry.sh"
CLEAR_FOR_FLASH=false
if [ "$CLEAR_FOR_FLASH" != true ]; then
    echo "refusing flash_erase/nandwrite/fw_setenv"
    exit 1
fi
"""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def with_verification_id(value: dict) -> dict:
    result = dict(value)
    result["verification_id"] = digest(image.canonical_json(result))
    return result


def newc_entry(
    name: str, data: bytes, mode: int, ino: int, *, link_count: int = 1
) -> bytes:
    name_bytes = name.encode("utf-8") + b"\0"
    fields = (ino, mode, 0, 0, link_count, EPOCH, len(data), 0, 0, 0, 0,
              len(name_bytes), 0)
    header = b"070701" + b"".join(f"{field:08x}".encode("ascii")
                                  for field in fields)
    result = header + name_bytes
    result += b"\0" * ((-len(result)) % 4)
    result += data
    result += b"\0" * ((-len(result)) % 4)
    return result


def make_cpio(
    public_key: bytes,
    *,
    safeoff_value: int = 1,
    daemon_bytes: bytes = DAEMON,
    daemon_mode: int = 0o755,
    daemon_link_count: int = 1,
    mutation_policy: bytes = b"boot-safeoff\n",
) -> bytes:
    setup = f"""#!/bin/sh
PWR_GPIO=437
case "$PLATFORM:$BOARD_TARGET" in
  am3-aml-s19k:am3-s19k)
    dcent_mutation_policy_has "$MUTATION_POLICY_FILE" boot-safeoff
    ;;
esac
set_gpio_direction_checked "$PWR_GPIO" high out
set_gpio_value_checked "$PWR_GPIO" {safeoff_value}
hold_hashboards_reset_low || return 1
write_receipt boot-safe || return 1
""".encode()
    daemon_init = b"""#!/bin/sh
if [ "$PLATFORM" = amlogic ] && ! verify_amlogic_boot_safe_state; then
    exit 1
fi
"$DAEMON"
"""
    files = {
        "etc/dcentos/platform": b"am3-aml-s19k\n",
        "etc/dcentos-platform": b"am3-aml-s19k\n",
        "etc/dcentos/board_target": b"am3-s19k\n",
        "etc/dcentos/rail_gpio": b"437\n",
        "etc/dcentos/mutation_policy": mutation_policy,
        "etc/dcentos/release_ed25519.pub": public_key,
        "etc/dcentos/release-image": b"# test release marker\nrelease_image=1\n",
        "etc/dcentrald.toml": b"[mining]\nenabled = false\n\n[pool]\nurl = \"\"\n",
        "etc/init.d/S37board_setup": setup,
        "etc/init.d/S82dcentrald": daemon_init,
        "usr/local/bin/dcentrald": daemon_bytes,
    }
    result = b""
    for ino, (name, data) in enumerate(files.items(), 1):
        mode = stat.S_IFREG | (
            daemon_mode
            if name == "usr/local/bin/dcentrald"
            else (0o755 if "/init.d/" in name else 0o644)
        )
        result += newc_entry(
            name,
            data,
            mode,
            ino,
            link_count=(
                daemon_link_count
                if name == "usr/local/bin/dcentrald"
                else 1
            ),
        )
    result += newc_entry("TRAILER!!!", b"", 0, len(files) + 1)
    return result + b"\0" * ((-len(result)) % 512)


def make_uimage(public_key: bytes, *, safeoff_value: int = 1) -> bytes:
    payload = gzip.compress(make_cpio(public_key, safeoff_value=safeoff_value),
                            compresslevel=9, mtime=EPOCH)
    name = b"DCENT_OS S19K Pro rootfs".ljust(32, b"\0")
    header = struct.pack(">7I4B32s", 0x27051956, 0, EPOCH, len(payload),
                         0, 0, zlib.crc32(payload) & 0xFFFFFFFF,
                         5, 22, 1, 1, name)
    header_crc = zlib.crc32(header) & 0xFFFFFFFF
    header = struct.pack(">7I4B32s", 0x27051956, header_crc, EPOCH,
                         len(payload), 0, 0,
                         zlib.crc32(payload) & 0xFFFFFFFF,
                         5, 22, 1, 1, name)
    return header + payload


class Fixture:
    def __init__(self, root: Path) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.root = root
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.raw_public_key_hex = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        ).hex()
        self.expected_key_sha = digest(self.public_key)
        self.root_uimage = make_uimage(self.public_key)
        source_files = [
            {"path": path, "sha256": f"{index:x}" * 64, "bytes": 4096}
            for index, path in enumerate(image.NATIVE_SOURCE_PATHS, 1)
        ]
        cargo_metadata_sha256 = "7" * 64
        capsule_build_receipt = {
            "binary": {
                "name": "dcentrald",
                "path": "target/aarch64-unknown-linux-musl/release/dcentrald",
                "sha256": digest(DAEMON),
                "size": len(DAEMON),
            },
            "build_inputs": {},
            "build_environment": {
                "DCENT_MANIFEST_KEY_ID": "",
                "DCENT_MANIFEST_PUBLIC_KEY_HEX": self.raw_public_key_hex,
            },
            "build_variant": "amlogic",
            "builder": {
                "kind": "docker-cross",
                "base_reference": "rust@sha256:" + "3" * 64,
                "image_id": "sha256:" + "4" * 64,
                "package_resolution": "official-zig-0.13.0-sha256-d45312e6",
            },
            "cargo_metadata": {
                "path": "inventory/aarch64.metadata.json",
                "sha256": cargo_metadata_sha256,
                "size": 4096,
            },
            "claim": (
                "declared-release-capsule-and-post-build-snapshot-consistency-"
                "not-build-causality-or-reproducibility-proof"
            ),
            "compile_environment": {
                "entries": {
                    "DCENT_MANIFEST_KEY_ID": "",
                    "DCENT_MANIFEST_PUBLIC_KEY_HEX": self.raw_public_key_hex,
                }
            },
            "git": {
                "commit": COMMIT,
                "source_kind": "exact-git-object-snapshot",
            },
            "profile": "release",
            "release_capsule": {
                "schema": "org.dcentral.dcentos.release-capsule-lineage.v2",
                "release_invocation_descriptor_sha256": "8" * 64,
                "release_invocation_id": "9" * 64,
                "source_snapshot_descriptor_sha256": "a" * 64,
                "source_snapshot_id": "b" * 64,
            },
            "schema_version": 4,
            "source_inventory": [],
            "source_inventory_sha256": "c" * 64,
            "target_triple": "aarch64-unknown-linux-musl",
            "toolchain_context": {},
        }
        closure_packages = [
            {
                "name": name,
                "version": "0.9.0",
                "manifest_path": manifest,
                "package_root": Path(manifest).parent.as_posix(),
            }
            for name, manifest in image.NATIVE_LOCAL_PACKAGE_MANIFESTS.items()
        ]
        native_build = with_verification_id(
            {
                "schema": image.NATIVE_BUILD_SCHEMA,
                "claim": image.NATIVE_BUILD_CLAIM,
                "classification": (
                    "exact-snapshot-capsule-linked-manifest-key-pinned-candidate"
                ),
                "target_triple": "aarch64-unknown-linux-musl",
                "cargo_profile": "release",
                "cargo_command": image.NATIVE_BUILD_COMMAND,
                "artifact": {
                    "path": "dcentrald",
                    "sha256": digest(DAEMON),
                    "bytes": len(DAEMON),
                },
                "semantic_source_files": source_files,
                "semantic_source_files_sha256": digest(
                    image.canonical_json(source_files)
                ),
                "aarch64_compile_contract": image.NATIVE_COMPILE_CONTRACT,
                "compile_contract_sha256": digest(
                    image.canonical_json(image.NATIVE_COMPILE_CONTRACT)
                ),
                "capsule_build_receipt": capsule_build_receipt,
                "capsule_build_receipt_sha256": digest(
                    image.canonical_json(capsule_build_receipt)
                ),
                "local_dependency_closure": {
                    "cargo_metadata_sha256": cargo_metadata_sha256,
                    "target_triple": "aarch64-unknown-linux-musl",
                    "root_package_id": "dcentrald 0.9.0 (path+file:///snapshot)",
                    "packages": closure_packages,
                    "external_local_paths_inside_snapshot": True,
                },
                "manifest_public_key_hex": self.raw_public_key_hex,
                "manifest_public_key_sha256": digest(
                    bytes.fromhex(self.raw_public_key_hex)
                ),
                "network_nonuse_proven": False,
                "network_contract": image.NATIVE_BUILD_NETWORK_CONTRACT,
                "release_authority_granted": False,
                "installation_authority_granted": False,
                "live_hardware_contacted": False,
            }
        )
        self.native = with_verification_id({
            "schema": image.NATIVE_OWNER_SCHEMA,
            "phase_id": "native-cold-start-owner",
            "classification": "verified",
            "source_readiness_classification": "ready",
            "production_owner_present": True,
            "dependency_evidence_bound": True,
            "prerequisite_verification_ids": {
                "native-secure-firmware-re": "a" * 64,
                "native-hardware-contract": "b" * 64,
                "adopted-endurance": "c" * 64,
                "native-build-reproducibility": "d" * 64,
            },
            "native_owner_artifact": {
                "path": "usr/local/bin/dcentrald",
                "sha256": digest(DAEMON),
                "bytes": len(DAEMON),
            },
            "source_files": source_files,
            "aarch64_compile_contract": image.NATIVE_COMPILE_CONTRACT,
            "native_build_receipt": native_build,
            "native_owner_build_binding": {
                "target_triple": "aarch64-unknown-linux-musl",
                "cargo_profile": "release",
                "artifact_role": "native-cold-start-owner",
                "source_files_sha256": digest(image.canonical_json(source_files)),
                "compile_contract_sha256": digest(
                    image.canonical_json(image.NATIVE_COMPILE_CONTRACT)
                ),
                "adopted_artifact_reused": False,
                "native_build_verification_id": native_build["verification_id"],
                "capsule_build_receipt_sha256": native_build[
                    "capsule_build_receipt_sha256"
                ],
                "source_commit": COMMIT,
                "source_snapshot_id": capsule_build_receipt[
                    "release_capsule"
                ]["source_snapshot_id"],
                "release_invocation_id": capsule_build_receipt[
                    "release_capsule"
                ]["release_invocation_id"],
                "cargo_metadata_sha256": cargo_metadata_sha256,
                "manifest_public_key_hex": self.raw_public_key_hex,
                "manifest_public_key_sha256": native_build[
                    "manifest_public_key_sha256"
                ],
                "native_reproducibility_verification_id": "d" * 64,
                "observed_native_build_verification_ids": sorted(
                    [native_build["verification_id"], "e" * 64]
                ),
                "observed_release_invocation_ids": sorted(
                    [
                        capsule_build_receipt["release_capsule"][
                            "release_invocation_id"
                        ],
                        "f" * 64,
                    ]
                ),
            },
            "authority_minted": False,
        })
        self.recovery = with_verification_id({
            "schema": image.RECOVERY_SCHEMA,
            "claim": "stock-recovery-rehearsed-before-any-dcentos-write",
            "device_id": "s19kpro-78",
            "stock_bmu": {"sha256": "d" * 64, "bytes": 4096},
            "separate_mutation_authority_verified": True,
            "stock_restore_rehearsal_verified": True,
            "original_bytes_restored": True,
            "terminal_safeoff_verified": True,
            "dcentos_write_observed": False,
            "dcentos_write_authorized": False,
            "mutation_authority_granted": False,
        })
        self.native_bytes = image.canonical_json(self.native)
        self.recovery_bytes = image.canonical_json(self.recovery)
        self.files = self._base_files()
        self.write_package()

    def _base_files(self) -> dict[str, bytes]:
        contract = image.build_image_contract(
            self.root_uimage, self.native_bytes, self.recovery_bytes,
            self.public_key, BUILDER, WRITER,
            source_commit=COMMIT, source_date_epoch=EPOCH,
            build_target="dcentos_am3_s19kpro_defconfig",
            build_arch="aarch64", toolchain_id=TOOLCHAIN,
            expected_release_key_sha256=self.expected_key_sha)
        return {
            image.PACKAGE_KERNEL_PATH: b"exact-s19k-kernel",
            image.PACKAGE_ROOT_PATH: self.root_uimage,
            image.PACKAGE_METADATA_PATH: b"DCENT_OS\nS19k persistent test\n",
            image.PACKAGE_KEY_PATH: self.public_key,
            image.PACKAGE_NATIVE_PATH: self.native_bytes,
            image.PACKAGE_RECOVERY_PATH: self.recovery_bytes,
            image.PACKAGE_CONTRACT_PATH: image.canonical_json(contract),
            image.PACKAGE_BUILDER_PATH: BUILDER,
            image.PACKAGE_WRITER_PATH: WRITER,
        }

    def _refresh_unsigned_metadata(self) -> None:
        leaf_paths = {
            "kernel": image.PACKAGE_KERNEL_PATH,
            "root": image.PACKAGE_ROOT_PATH,
            "METADATA": image.PACKAGE_METADATA_PATH,
            "release_ed25519.pub": image.PACKAGE_KEY_PATH,
            image.NATIVE_RECEIPT_FILE: image.PACKAGE_NATIVE_PATH,
            image.RECOVERY_RECEIPT_FILE: image.PACKAGE_RECOVERY_PATH,
            "IMAGE_CONTRACT.json": image.PACKAGE_CONTRACT_PATH,
            image.BUILDER_LEAF: image.PACKAGE_BUILDER_PATH,
            image.WRITER_LEAF: image.PACKAGE_WRITER_PATH,
        }
        self.files[image.PACKAGE_SUMS_PATH] = b"".join(
            f"{digest(self.files[path])}  {leaf}\n".encode("ascii")
            for leaf, path in leaf_paths.items())
        payload_names = {
            "kernel": image.PACKAGE_KERNEL_PATH,
            "rootfs": image.PACKAGE_ROOT_PATH,
            "metadata": image.PACKAGE_METADATA_PATH,
            "verification_key": image.PACKAGE_KEY_PATH,
            "native_owner_verification": image.PACKAGE_NATIVE_PATH,
            "stock_recovery_verification": image.PACKAGE_RECOVERY_PATH,
            "persistent_image_contract": image.PACKAGE_CONTRACT_PATH,
            "native_install_builder": image.PACKAGE_BUILDER_PATH,
            "persistent_install_writer": image.PACKAGE_WRITER_PATH,
        }
        payloads = {
            name: {"path": path, "size": len(self.files[path]),
                   "sha256": digest(self.files[path])}
            for name, path in payload_names.items()
        }
        self.manifest = {
            "schema": 1,
            "manifest_profile": "dcentos.sysupgrade-authority/v1",
            "product": "DCENT_OS", "family": "antminer",
            "package_type": "sysupgrade", "installable": True,
            "artifact_maturity": "experimental", "board_family": "am3",
            "board": image.BOARD, "board_target": image.BOARD,
            "version": "test-1", "created_at_utc": "2023-11-14T22:13:20Z",
            "status": "release",
            "provenance": {
                "source_commit": COMMIT, "source_tree_state": "clean",
                "source_date_epoch": EPOCH, "source_commit_epoch": EPOCH,
                "build_target": "dcentos_am3_s19kpro_defconfig",
                "build_arch": "aarch64", "toolchain_id": TOOLCHAIN,
            },
            "target_side_sysupgrade": False,
            "payloads": payloads,
            "toolbox": {
                "install_command": "dcent install <ip> -f image.tar --artifact-dir <restore-verified-artifact-dir>",
                "update_command": "dcent install <ip> -f image.tar --artifact-dir <restore-verified-artifact-dir>",
                "upload_endpoint": None, "board_target_header": None,
                "requires_inactive_slot": False,
                "install_mode": "host_driven_rootfs_window_lab",
                "target_side_sysupgrade": False,
            },
        }
        manifest_bytes = json.dumps(self.manifest, indent=2,
                                    ensure_ascii=True).encode("ascii") + b"\n"
        self.files[image.PACKAGE_MANIFEST_PATH] = manifest_bytes
        self.files.pop(image.PACKAGE_SIGNATURE_PATH, None)

    def _refresh_signed_metadata(self) -> None:
        self._refresh_unsigned_metadata()
        manifest_bytes = self.files[image.PACKAGE_MANIFEST_PATH]
        self.files[image.PACKAGE_SIGNATURE_PATH] = self.private_key.sign(manifest_bytes)

    def _tar(self, *, mtime: int = EPOCH, signed: bool = True) -> bytes:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            directory = tarfile.TarInfo(image.PREFIX)
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            directory.uid = directory.gid = 0
            directory.uname = directory.gname = ""
            directory.mtime = mtime
            archive.addfile(directory)
            selected = {
                name: value
                for name, value in self.files.items()
                if signed or name != image.PACKAGE_SIGNATURE_PATH
            }
            for name in sorted(selected):
                value = selected[name]
                member = tarfile.TarInfo(name)
                member.size = len(value)
                member.mode = 0o644
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                member.mtime = mtime
                archive.addfile(member, io.BytesIO(value))
        return output.getvalue()

    def write_package(self, *, mtime: int = EPOCH) -> None:
        self._refresh_signed_metadata()
        unsigned = self._tar(mtime=mtime, signed=False)
        signed = self._tar(mtime=mtime, signed=True)
        for name in image.BUILD_PACKAGE_FILES:
            (self.root / name).write_bytes(unsigned)
        for index, (receipt_name, package_name) in enumerate(
                zip(image.BUILD_RECEIPT_FILES, image.BUILD_PACKAGE_FILES)):
            receipt = {
                "schema": image.BUILD_SCHEMA,
                "build_id": f"build-{index}",
                "build_root_id": f"clean-root-{index}",
                "clean_build": True, "build_cache_reused": False,
                "network_used": False, "source_commit": COMMIT,
                "source_date_epoch": EPOCH,
                "build_target": "dcentos_am3_s19kpro_defconfig",
                "build_arch": "aarch64", "toolchain_id": TOOLCHAIN,
                "package_name": package_name,
                "package_sha256": digest(unsigned), "package_bytes": len(unsigned),
            }
            (self.root / receipt_name).write_bytes(image.canonical_json(receipt))
        (self.root / image.SIGNED_PACKAGE_FILE).write_bytes(signed)
        signature = self.files[image.PACKAGE_SIGNATURE_PATH]
        signing_body = {
            "schema": image.SIGNING_RECEIPT_SCHEMA,
            "build_a_package_sha256": digest(unsigned),
            "build_a_package_bytes": len(unsigned),
            "build_b_package_sha256": digest(unsigned),
            "build_b_package_bytes": len(unsigned),
            "unsigned_package_sha256": digest(unsigned),
            "unsigned_package_bytes": len(unsigned),
            "signed_package_name": image.SIGNED_PACKAGE_FILE,
            "signed_package_sha256": digest(signed),
            "signed_package_bytes": len(signed),
            "manifest_sha256": digest(self.files[image.PACKAGE_MANIFEST_PATH]),
            "manifest_bytes": len(self.files[image.PACKAGE_MANIFEST_PATH]),
            "manifest_signature_sha256": digest(signature),
            "manifest_signature_bytes": len(signature),
            "release_key_sha256": digest(self.public_key),
            "release_key_bytes": len(self.public_key),
            "source_commit": COMMIT,
            "source_date_epoch": EPOCH,
            "build_target": "dcentos_am3_s19kpro_defconfig",
            "build_arch": "aarch64",
            "toolchain_id": TOOLCHAIN,
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
        signing_receipt = dict(signing_body)
        signing_receipt["signing_id"] = digest(image.canonical_json(signing_body))
        (self.root / image.SIGNING_RECEIPT_FILE).write_bytes(
            image.canonical_json(signing_receipt)
        )
        (self.root / image.TRUSTED_KEY_FILE).write_bytes(self.public_key)
        (self.root / image.NATIVE_RECEIPT_FILE).write_bytes(
            self.files[image.PACKAGE_NATIVE_PATH])
        (self.root / image.RECOVERY_RECEIPT_FILE).write_bytes(
            self.files[image.PACKAGE_RECOVERY_PATH])
        preflight_body = {
            "schema": "dcentos.s19k-hermetic-host-preflight/v1",
            "claim": "host-custody-and-worst-case-capacity-preflight-only",
            "capacity_model": {
                "required_free_bytes_per_filesystem": 392 * 1024**3,
                "required_free_inodes_per_filesystem": 8_000_000,
            },
            "docker": {
                "binary": {
                    "path": "/usr/bin/docker",
                    "sha256": "8" * 64,
                    "bytes": 4096,
                },
                "client_version": "fixture",
                "server_version": "fixture",
                "server_os": "linux",
            },
            "docker_trust_nonclaim": (
                "client-bytes-and-client-server-version-only; daemon-endpoint-"
                "context-daemon-id-rootless-kernel-and-security-posture-not-bound"
            ),
            "roots": [
                {
                    "label": "build-parent",
                    "path": "/srv/dcent/build",
                    "device": 7,
                    "filesystem": "ext4",
                    "mountpoint": "/srv/dcent",
                    "mount_options": ["rw"],
                    "mode": "0700",
                    "uid": 1000,
                    "gid": 1000,
                    "free_bytes": 392 * 1024**3,
                    "free_inodes": 8_000_000,
                }
            ],
            "production_ready": False,
            "release_authority_granted": False,
            "install_authority_granted": False,
            "flash_authority_granted": False,
        }
        preflight = dict(preflight_body)
        preflight["component_sha256"] = "9" * 64
        preflight["preflight_id"] = digest(image.canonical_json(preflight_body))
        (self.root / image.HOST_PREFLIGHT_FILE).write_bytes(
            image.canonical_json(preflight)
        )
        runtime_id = "a" * 64
        inspect = {
            "Id": runtime_id,
            "Config": {
                "Hostname": "dcent-s19k-signer",
                "Domainname": "signer.invalid",
                "User": "1000:1000",
            },
            "HostConfig": {
                "NetworkMode": "none",
                "ReadonlyRootfs": True,
                "Privileged": False,
                "CapDrop": ["ALL"],
            },
            "NetworkSettings": {"Networks": {"none": {}}},
            "Mounts": [
                {"Destination": "/dcent/source-snapshot"},
                {"Destination": "/dcent/public"},
                {"Destination": "/dcent/private/release.pem"},
                {"Destination": "/dcent/output"},
                {"Destination": "/run"},
            ],
        }
        inspect_before = image.canonical_json(inspect)
        inspect_after = image.canonical_json(inspect)
        signer_log = b"fixture isolated signer log\n"
        signing_receipt_raw = (self.root / image.SIGNING_RECEIPT_FILE).read_bytes()
        runtime_receipt = {
            "schema": "dcentos.s19k-hermetic-isolated-signer-runtime/v1",
            "runtime_id": runtime_id,
            "signing_id": "fixture-signing",
            "builder_image": "fixture.invalid/dcentos@sha256:" + "b" * 64,
            "network_mode": "none",
            "network_boundary_inspected_before_after": True,
            "read_only_rootfs": True,
            "privileged": False,
            "private_key_custody_id": "c" * 64,
            "host_preflight_id": preflight["preflight_id"],
            "verifier_sha256": "d" * 64,
            "signer_sha256": "e" * 64,
            "inspect_before_sha256": digest(inspect_before),
            "inspect_after_sha256": digest(inspect_after),
            "log_sha256": digest(signer_log),
            "log_bytes": len(signer_log),
            "signed_package_sha256": digest(signed),
            "signed_package_bytes": len(signed),
            "signing_receipt_sha256": digest(signing_receipt_raw),
            "signing_receipt_bytes": len(signing_receipt_raw),
            "container_removed_after_stop_proof": True,
            "install_authority_granted": False,
            "flash_authority_granted": False,
            "mutation_authority_granted": False,
        }
        (self.root / image.SIGNER_INSPECT_BEFORE_FILE).write_bytes(inspect_before)
        (self.root / image.SIGNER_INSPECT_AFTER_FILE).write_bytes(inspect_after)
        (self.root / image.SIGNER_LOG_FILE).write_bytes(signer_log)
        (self.root / image.SIGNER_RUNTIME_FILE).write_bytes(
            image.canonical_json(runtime_receipt)
        )


class PersistentImageTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory, Fixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, Fixture(Path(temporary.name))

    def test_native_runtime_policy_keeps_disabled_boot_and_rejects_write_capabilities(self) -> None:
        key = b"public-key-fixture"
        for policy in (b"boot-safeoff\n", b"boot-safeoff\ndaemon-hardware\n"):
            baseline, _ = image._safeoff_baseline(make_cpio(key, mutation_policy=policy), key)
            self.assertFalse(baseline["mining_enabled_at_boot"])
            self.assertEqual(baseline["mutation_policy_sha256"], digest(policy))
        for policy in (
            b"hardware-enabled\n", b"daemon-hardware\n",
            b"boot-safeoff\ndaemon-hardware\npersistent-write\n",
            b"boot-safeoff\ndaemon-hardware\nsysupgrade\n",
        ):
            with self.subTest(policy=policy):
                with self.assertRaisesRegex(image.PersistentImageError, "mutation-policy"):
                    image._safeoff_baseline(make_cpio(key, mutation_policy=policy), key)

    def test_signed_rootfs_rechecks_executable_static_aarch64_daemon(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        cases = (
            (
                {"daemon_mode": 0o644},
                "execute bit",
            ),
            (
                {"daemon_bytes": b"\x7fELF-not-a-runnable-aarch64-image"},
                "ELF64 header",
            ),
            (
                {"daemon_link_count": 2},
                "hard-link ambiguous",
            ),
        )
        for options, message in cases:
            with self.subTest(options=options):
                root = make_cpio(fixture.public_key, **options)
                with self.assertRaisesRegex(image.PersistentImageError, message):
                    image._safeoff_baseline(root, fixture.public_key)

    def test_source_readiness_is_ready_but_not_verified(self) -> None:
        result = image.audit_source_tree()
        self.assertEqual(result["classification"], "ready")
        self.assertFalse(result["install_authority_granted"])
        self.assertFalse(result["nand_writer_clear_for_flash"])

    def test_current_readiness_binds_qualified_policy_and_both_generated_helpers(self) -> None:
        for mutation in ("inverted-policy", "missing-target", "amlogic-helper", "common-helper"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                for relative in image.SOURCE_PATHS:
                    destination = root / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes((image.REPO_ROOT / relative).read_bytes())
                policy_path = root / image.SOURCE_PATHS[8]
                policy = json.loads(policy_path.read_bytes())
                if mutation == "inverted-policy":
                    for row in policy["profiles"]:
                        if row["board_target"] == image.BOARD:
                            for evidence in row["evidence"]:
                                if evidence["on_raw"] is not None:
                                    evidence["on_raw"] = 1 - evidence["on_raw"]
                                if evidence["off_raw"] is not None:
                                    evidence["off_raw"] = 1 - evidence["off_raw"]
                    policy_path.write_text(json.dumps(policy), encoding="utf-8")
                elif mutation == "missing-target":
                    policy["profiles"] = [row for row in policy["profiles"]
                                          if row["board_target"] != image.BOARD]
                    policy_path.write_text(json.dumps(policy), encoding="utf-8")
                else:
                    helper = root / image.SOURCE_PATHS[10 if mutation == "amlogic-helper" else 11]
                    original = helper.read_bytes()
                    changed = original.replace(b"'0 1 high'", b"'1 0 low'", 1)
                    self.assertNotEqual(original, changed)
                    helper.write_bytes(changed)
                with self.assertRaisesRegex(image.PersistentImageError, "GPIO437 readiness"):
                    image.audit_source_tree(root)

    def test_complete_signed_reproducible_bundle_verifies_without_authority(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            result = image.verify_evidence(
                fixture.root,
                expected_release_key_sha256=fixture.expected_key_sha)
        self.assertTrue(result["reproducible_builds_verified"])
        self.assertTrue(result["signed_manifest_verified"])
        self.assertTrue(result["post_ab_derivation_and_runtime_metadata_verified"])
        self.assertFalse(result["isolated_post_ab_signing_verified"])
        self.assertIn("not-joined", result["isolated_post_ab_signing_nonclaim"])
        self.assertEqual(result["image_sha256"], digest(fixture.root_uimage))
        self.assertFalse(result["install_authority_granted"])
        self.assertFalse(result["mutation_authority_granted"])
        self.assertFalse(result["nand_write_authorized"])

    def test_cli_exclusively_materializes_canonical_verification_receipt(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            arguments = [
                "verify",
                "--evidence-dir", str(fixture.root),
                "--expected-release-key-sha256", fixture.expected_key_sha,
                "--write-receipt",
            ]
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(image.main(arguments), 0)
            receipt = fixture.root / image.VERIFICATION_FILE
            retained = receipt.read_bytes()
            result = image.verify_evidence(
                fixture.root,
                expected_release_key_sha256=fixture.expected_key_sha,
            )
            self.assertEqual(retained, image.canonical_json(result))

            # Re-verification is idempotent, but drift is never replaced.
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(image.main(arguments), 0)
            self.assertEqual(receipt.read_bytes(), retained)
            receipt.write_bytes(b"{}\n")
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(image.main(arguments), 1)
            self.assertEqual(receipt.read_bytes(), b"{}\n")

    def test_external_key_identity_is_mandatory(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            with self.assertRaisesRegex(image.PersistentImageError, "external trusted key identity"):
                image.verify_evidence(fixture.root)
            with self.assertRaisesRegex(image.PersistentImageError, "external expected identity"):
                image.verify_evidence(fixture.root,
                                      expected_release_key_sha256="0" * 64)

    def test_release_key_must_match_native_manifest_pin(self) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        temporary, fixture = self.fixture()
        with temporary:
            other_public_key = Ed25519PrivateKey.generate().public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            with self.assertRaisesRegex(
                image.PersistentImageError,
                "differs from native daemon manifest key pin",
            ):
                image.build_image_contract(
                    make_uimage(other_public_key),
                    fixture.native_bytes,
                    fixture.recovery_bytes,
                    other_public_key,
                    BUILDER,
                    WRITER,
                    source_commit=COMMIT,
                    source_date_epoch=EPOCH,
                    build_target="dcentos_am3_s19kpro_defconfig",
                    build_arch="aarch64",
                    toolchain_id=TOOLCHAIN,
                    expected_release_key_sha256=digest(other_public_key),
                )

    def test_two_builds_must_be_byte_identical(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            path = fixture.root / image.BUILD_PACKAGE_FILES[1]
            path.write_bytes(path.read_bytes() + b"x")
            with self.assertRaisesRegex(image.PersistentImageError, "byte-identical"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_builds_require_distinct_clean_roots(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            first = json.loads((fixture.root / "build-a.json").read_text())
            second_path = fixture.root / "build-b.json"
            second = json.loads(second_path.read_text())
            second["build_root_id"] = first["build_root_id"]
            second_path.write_bytes(image.canonical_json(second))
            with self.assertRaisesRegex(image.PersistentImageError, "distinct builds and roots"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_invalid_real_signature_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture._refresh_signed_metadata()
            signature = bytearray(fixture.files[image.PACKAGE_SIGNATURE_PATH])
            signature[0] ^= 1
            fixture.files[image.PACKAGE_SIGNATURE_PATH] = bytes(signature)
            (fixture.root / image.SIGNED_PACKAGE_FILE).write_bytes(fixture._tar())
            with self.assertRaisesRegex(image.PersistentImageError, "manifest verification"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_native_source_readiness_cannot_substitute_for_verified_phase(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            receipt = dict(fixture.native)
            receipt["classification"] = "ready"
            receipt.pop("verification_id")
            receipt = with_verification_id(receipt)
            fixture.files[image.PACKAGE_NATIVE_PATH] = image.canonical_json(receipt)
            fixture.write_package()
            with self.assertRaisesRegex(image.PersistentImageError, "production owner"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_native_owner_must_bind_exact_prerequisites(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            receipt = dict(fixture.native)
            receipt.pop("verification_id")
            receipt["prerequisite_verification_ids"] = {
                "native-secure-firmware-re": "a" * 64,
            }
            fixture.files[image.PACKAGE_NATIVE_PATH] = image.canonical_json(
                with_verification_id(receipt))
            fixture.write_package()
            with self.assertRaisesRegex(image.PersistentImageError, "prerequisite set"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_native_owner_must_bind_exact_aarch64_compile_contract(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            receipt = dict(fixture.native)
            receipt.pop("verification_id")
            receipt["aarch64_compile_contract"] = {
                **image.NATIVE_COMPILE_CONTRACT,
                "cargo_offline": False,
            }
            fixture.files[image.PACKAGE_NATIVE_PATH] = image.canonical_json(
                with_verification_id(receipt)
            )
            fixture.write_package()
            with self.assertRaisesRegex(
                image.PersistentImageError, "exact AArch64 compile contract"
            ):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha,
                )

    def test_persistent_image_rejects_mismatched_native_source_snapshot(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            receipt = dict(fixture.native)
            receipt.pop("verification_id")
            native_build = dict(receipt["native_build_receipt"])
            native_build.pop("verification_id")
            capsule = dict(native_build["capsule_build_receipt"])
            capsule["git"] = {
                "commit": "f" * 40,
                "source_kind": "exact-git-object-snapshot",
            }
            native_build["capsule_build_receipt"] = capsule
            native_build["capsule_build_receipt_sha256"] = digest(
                image.canonical_json(capsule)
            )
            native_build = with_verification_id(native_build)
            binding = dict(receipt["native_owner_build_binding"])
            binding["native_build_verification_id"] = native_build["verification_id"]
            binding["capsule_build_receipt_sha256"] = native_build[
                "capsule_build_receipt_sha256"
            ]
            binding["source_commit"] = "f" * 40
            receipt["native_build_receipt"] = native_build
            receipt["native_owner_build_binding"] = binding
            fixture.files[image.PACKAGE_NATIVE_PATH] = image.canonical_json(
                with_verification_id(receipt)
            )
            fixture.write_package()
            with self.assertRaisesRegex(
                image.PersistentImageError, "exact snapshot-capsule candidate"
            ):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha,
                )

    def test_recovery_mutation_claim_is_not_accepted(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            receipt = dict(fixture.recovery)
            receipt.pop("verification_id")
            receipt["mutation_authority_granted"] = True
            fixture.files[image.PACKAGE_RECOVERY_PATH] = image.canonical_json(
                with_verification_id(receipt))
            fixture.write_package()
            with self.assertRaisesRegex(image.PersistentImageError, "improperly claims"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_safeoff_value_drift_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.files[image.PACKAGE_ROOT_PATH] = make_uimage(
                fixture.public_key, safeoff_value=0)
            fixture.write_package()
            with self.assertRaisesRegex(image.PersistentImageError, "SafeOff baseline"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_enabled_writer_source_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.files[image.PACKAGE_WRITER_PATH] = WRITER.replace(
                b"CLEAR_FOR_FLASH=false", b"CLEAR_FOR_FLASH=true")
            fixture.write_package()
            with self.assertRaisesRegex(image.PersistentImageError, "disabled anchor|enabled CLEAR_FOR_FLASH"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_nondeterministic_tar_mtime_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.write_package(mtime=EPOCH + 1)
            with self.assertRaisesRegex(image.PersistentImageError, "tar metadata"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_target_side_sysupgrade_is_rejected_even_when_signed(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture._refresh_signed_metadata()
            fixture.manifest["target_side_sysupgrade"] = True
            value = json.dumps(fixture.manifest, indent=2).encode() + b"\n"
            fixture.files[image.PACKAGE_MANIFEST_PATH] = value
            fixture.files[image.PACKAGE_SIGNATURE_PATH] = fixture.private_key.sign(value)
            unsigned = fixture._tar(signed=False)
            signed = fixture._tar()
            for name in image.BUILD_PACKAGE_FILES:
                (fixture.root / name).write_bytes(unsigned)
            for receipt_name in image.BUILD_RECEIPT_FILES:
                receipt = json.loads((fixture.root / receipt_name).read_text())
                receipt["package_sha256"] = digest(unsigned)
                receipt["package_bytes"] = len(unsigned)
                (fixture.root / receipt_name).write_bytes(image.canonical_json(receipt))
            (fixture.root / image.SIGNED_PACKAGE_FILE).write_bytes(signed)
            with self.assertRaisesRegex(image.PersistentImageError, "host-driven release profile"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)

    def test_stale_terminal_receipt_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            (fixture.root / image.VERIFICATION_FILE).write_bytes(b"{}\n")
            with self.assertRaisesRegex(image.PersistentImageError, "stale or noncanonical"):
                image.verify_evidence(
                    fixture.root,
                    expected_release_key_sha256=fixture.expected_key_sha)


if __name__ == "__main__":
    unittest.main()
