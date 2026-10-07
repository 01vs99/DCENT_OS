#!/usr/bin/env python3
"""Adversarial tests for the S19k exact-snapshot capsule build receipt."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

import binary_build_receipt as capsule
import release_capsule_lineage
import s19k_native_build_verify as build


MANIFEST_PUBLIC_KEY_HEX = "a" * 64


def aarch64_elf(marker: bytes = b"native-build-test") -> bytes:
    result = bytearray(256)
    result[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", result, 16, 2, 183)
    result[32 : 32 + len(marker)] = marker
    return bytes(result)


def context(path: str, lines: list[str], entries: dict[str, str] | None = None) -> dict[str, object]:
    data = ("\n".join(lines) + "\n").encode("utf-8")
    result: dict[str, object] = {
        "path": path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "lines": lines,
    }
    if entries is not None:
        result["entries"] = dict(sorted(entries.items()))
    return result


def reseal(value: dict[str, object]) -> dict[str, object]:
    result = copy.deepcopy(value)
    result.pop("verification_id", None)
    result["verification_id"] = build.digest(build.canonical_json(result))
    return result


class CapsuleFixture:
    def __init__(
        self,
        root: Path,
        *,
        semantic_source_bytes: dict[str, bytes] | None = None,
    ) -> None:
        self.root = root
        self.semantic_source_bytes = semantic_source_bytes or {}
        self.repo = root / "repo"
        self.repo.mkdir(parents=True)
        self._write_sources()
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "user.name", "S19k Capsule Fixture")
        self.git("add", ".")
        self.git("commit", "-qm", "exact snapshot fixture")
        self.commit = self.git("rev-parse", "HEAD").stdout.strip()
        self.artifact = root / "dcentrald"
        self.artifact.write_bytes(aarch64_elf())
        self.metadata = self._metadata()
        self.metadata_data = build.canonical_json(self.metadata)
        self.capsule_receipt = self._capsule_receipt()
        self.receipt = build.make_receipt(
            self.artifact,
            capsule_build_receipt=self.capsule_receipt,
            cargo_metadata_data=self.metadata_data,
            repo_root=self.repo,
        )
        self.receipt_path = root / "native-build.json"
        self.receipt_path.write_bytes(build.canonical_json(self.receipt))

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ("git", "-C", str(self.repo), *arguments),
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def _write_sources(self) -> None:
        paths = set(build.SEMANTIC_SOURCE_PATHS)
        paths.update(build.LOCAL_PACKAGE_MANIFESTS.values())
        paths.add("DCENT_OS_Antminer/scripts/build_inputs.manifest")
        for index, relative in enumerate(sorted(paths), 1):
            path = self.repo.joinpath(*relative.split("/"))
            path.parent.mkdir(parents=True, exist_ok=True)
            if relative in self.semantic_source_bytes:
                path.write_bytes(self.semantic_source_bytes[relative])
            elif relative == "DCENT_OS_Antminer/scripts/build_inputs.manifest":
                path.write_text(
                    f"{'0' * 64}  fixture-unused-input.bin\n",
                    encoding="utf-8",
                )
            else:
                path.write_text(f"fixture {index}: {relative}\n", encoding="utf-8")

    def _metadata(self) -> dict[str, object]:
        prefix = "/snapshot/tree"
        packages = []
        ids: dict[str, str] = {}
        for name, manifest in build.LOCAL_PACKAGE_MANIFESTS.items():
            version = "0.1.0" if name == "dcent-schema" else "0.9.0"
            package_id = f"path+file://{prefix}/{Path(manifest).parent.as_posix()}#{name}@{version}"
            ids[name] = package_id
            packages.append(
                {
                    "id": package_id,
                    "name": name,
                    "version": version,
                    "source": None,
                    "manifest_path": f"{prefix}/{manifest}",
                }
            )
        root_id = ids["dcentrald"]
        nodes = []
        for name, package_id in ids.items():
            deps = []
            if name == "dcentrald":
                deps = [
                    {
                        "name": dependency,
                        "pkg": dependency_id,
                        "dep_kinds": [{"kind": None, "target": None}],
                    }
                    for dependency, dependency_id in sorted(ids.items())
                    if dependency != "dcentrald"
                ]
            nodes.append({"id": package_id, "deps": deps})
        return {
            "version": 1,
            "workspace_root": f"{prefix}/DCENT_OS_Antminer/dcentrald",
            "packages": packages,
            "resolve": {"root": root_id, "nodes": nodes},
        }

    def _inventory(self) -> list[dict[str, object]]:
        names = self.git("ls-files").stdout.splitlines()
        result = []
        for name in sorted(names):
            data = self.repo.joinpath(*name.split("/")).read_bytes()
            result.append(
                {
                    "path": name,
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        return result

    def _capsule_receipt(self) -> dict[str, object]:
        artifact = self.artifact.read_bytes()
        inventory = self._inventory()
        inventory_digest = hashlib.sha256()
        for item in inventory:
            inventory_digest.update(
                f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode("utf-8")
            )
        builder = {
            "kind": "docker-cross",
            "base_reference": "rust@sha256:" + "1" * 64,
            "image_id": "sha256:" + "2" * 64,
            "package_resolution": build.BUILDER_PACKAGE_RESOLUTION,
        }
        compile_entries = {
            **build.COMPILE_ENVIRONMENT,
            "DCENT_BUILDER_BASE_REFERENCE": builder["base_reference"],
            "DCENT_BUILDER_IMAGE_ID": builder["image_id"],
            "DCENT_MANIFEST_KEY_ID": "",
            "DCENT_MANIFEST_PUBLIC_KEY_HEX": MANIFEST_PUBLIC_KEY_HEX,
        }
        compile_lines = [f"{key}={value}" for key, value in sorted(compile_entries.items())]
        toolchain_lines = [
            "rustc 1.90.0 (fixture)",
            "binary: rustc",
            "commit-hash: fixture",
            "commit-date: 2026-01-01",
            "host: x86_64-unknown-linux-gnu",
            "release: 1.90.0",
            "LLVM version: fixture",
            "cargo 1.90.0 (fixture)",
            f"builder_base_reference={builder['base_reference']}",
            f"builder_image_id={builder['image_id']}",
            f"builder_package_resolution={build.BUILDER_PACKAGE_RESOLUTION}",
            f"zig_version={build.ZIG_VERSION}",
            f"zig_archive_sha256={build.ZIG_ARCHIVE_SHA256}",
        ]
        manifest_data = (
            self.repo / "DCENT_OS_Antminer/scripts/build_inputs.manifest"
        ).read_bytes()
        return {
            "schema_version": capsule.SCHEMA_VERSION,
            "claim": capsule.RECEIPT_CLAIM_V4,
            "release_capsule": {
                "schema": release_capsule_lineage.SCHEMA,
                "release_invocation_descriptor_sha256": "3" * 64,
                "release_invocation_id": "4" * 64,
                "source_snapshot_descriptor_sha256": "5" * 64,
                "source_snapshot_id": "6" * 64,
            },
            "build_inputs": {
                "claim": capsule.BUILD_INPUT_CLAIM,
                "selection_authority": capsule.BUILD_INPUT_SELECTION_AUTHORITY,
                "evidence": {
                    "manifest": {
                        "path": capsule.CARGO_BUILD_INPUT_MANIFEST,
                        "sha256": hashlib.sha256(manifest_data).hexdigest(),
                        "size": len(manifest_data),
                    },
                    "selection_policy": capsule.BUILD_INPUT_SELECTION_POLICY,
                    "files": [],
                    "snapshot": {
                        "snapshot_id": "7" * 64,
                        "target": "cargo-workspace",
                        "claim": capsule.build_input_snapshot.SNAPSHOT_CLAIM,
                    },
                },
            },
            "target_triple": build.TARGET,
            "profile": build.PROFILE,
            "build_variant": build.BUILD_VARIANT,
            "git": {
                "commit": self.commit,
                "source_kind": "exact-git-object-snapshot",
            },
            "build_environment": {
                "DCENT_MANIFEST_KEY_ID": "",
                "DCENT_MANIFEST_PUBLIC_KEY_HEX": MANIFEST_PUBLIC_KEY_HEX,
            },
            "builder": builder,
            "toolchain_context": context(
                "inventory/toolchain.txt", toolchain_lines
            ),
            "compile_environment": context(
                "inventory/compile-env.txt", compile_lines, compile_entries
            ),
            "source_inventory_sha256": inventory_digest.hexdigest(),
            "source_inventory": inventory,
            "cargo_metadata": {
                "path": "inventory/aarch64.metadata.json",
                "sha256": hashlib.sha256(self.metadata_data).hexdigest(),
                "size": len(self.metadata_data),
            },
            "binary": {
                "name": "dcentrald",
                "path": "target/aarch64-unknown-linux-musl/release/dcentrald",
                "sha256": hashlib.sha256(artifact).hexdigest(),
                "size": len(artifact),
            },
        }


class NativeBuildReceiptTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], CapsuleFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, CapsuleFixture(Path(temporary.name))

    def test_exact_snapshot_capsule_receipt_verifies(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            result = build.verify_receipt(
                fixture.receipt_path,
                fixture.artifact,
                repo_root=fixture.repo,
                require_clean=True,
            )
            self.assertEqual(result, fixture.receipt)
            self.assertEqual(len(result["local_dependency_closure"]["packages"]), 16)
            self.assertEqual(
                result["classification"],
                "exact-snapshot-capsule-linked-manifest-key-pinned-candidate",
            )
            self.assertEqual(
                result["manifest_public_key_hex"], MANIFEST_PUBLIC_KEY_HEX
            )
            self.assertEqual(
                result["manifest_public_key_sha256"],
                hashlib.sha256(bytes.fromhex(MANIFEST_PUBLIC_KEY_HEX)).hexdigest(),
            )
            self.assertEqual(
                fixture.capsule_receipt["compile_environment"]["entries"]["CARGO_BUILD_JOBS"], "2"
            )
            self.assertEqual(
                fixture.capsule_receipt["compile_environment"]["entries"]["CARGO_INCREMENTAL"], "0"
            )
            self.assertFalse(result["network_nonuse_proven"])
            self.assertEqual(result["network_contract"], build.NETWORK_CONTRACT)
            self.assertFalse(result["release_authority_granted"])

    def test_stage_round_trip_requires_exact_capsule_and_metadata_bytes(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            capsule_path = fixture.root / "dcentrald.build-receipt.json"
            metadata_path = fixture.root / "metadata.json"
            output = fixture.root / "staged.json"
            capsule_path.write_bytes(build.canonical_json(fixture.capsule_receipt))
            metadata_path.write_bytes(fixture.metadata_data)
            staged = build.stage_receipt(
                output,
                fixture.artifact,
                capsule_path,
                metadata_path,
                repo_root=fixture.repo,
            )
            self.assertEqual(
                build.verify_receipt(
                    output, fixture.artifact, repo_root=fixture.repo
                ),
                staged,
            )

    def test_dirty_checkout_cannot_change_the_authenticated_snapshot(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            changed = fixture.repo.joinpath(
                *build.SEMANTIC_SOURCE_PATHS[0].split("/")
            )
            changed.write_text("dirty mutable checkout bytes\n", encoding="utf-8")
            result = build.verify_receipt(
                fixture.receipt_path, fixture.artifact, repo_root=fixture.repo
            )
            self.assertEqual(
                result["capsule_build_receipt"]["git"]["commit"], fixture.commit
            )

    def test_artifact_drift_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            fixture.artifact.write_bytes(aarch64_elf(b"different-candidate"))
            with self.assertRaisesRegex(build.NativeBuildError, "exact artifact"):
                build.verify_receipt(
                    fixture.receipt_path, fixture.artifact, repo_root=fixture.repo
                )

    def test_resealed_capsule_inventory_forgery_is_rejected_against_git(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            receipt = copy.deepcopy(fixture.receipt)
            nested = receipt["capsule_build_receipt"]
            nested["source_inventory"][0]["sha256"] = "f" * 64
            accumulator = hashlib.sha256()
            for item in nested["source_inventory"]:
                accumulator.update(
                    f"{item['path']}\0{item['size']}\0{item['sha256']}\n".encode("utf-8")
                )
            nested["source_inventory_sha256"] = accumulator.hexdigest()
            receipt["capsule_build_receipt_sha256"] = build.digest(
                build.canonical_json(nested)
            )
            fixture.receipt_path.write_bytes(build.canonical_json(reseal(receipt)))
            with self.assertRaisesRegex(build.NativeBuildError, "disagrees with Git"):
                build.verify_receipt(
                    fixture.receipt_path, fixture.artifact, repo_root=fixture.repo
                )

    def test_missing_or_unbounded_cargo_resources_are_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            for key, value in (
                ("CARGO_BUILD_JOBS", None),
                ("CARGO_BUILD_JOBS", "1"),
                ("CARGO_BUILD_JOBS", "3"),
                ("CARGO_BUILD_JOBS", "02"),
                ("CARGO_INCREMENTAL", None),
                ("CARGO_INCREMENTAL", "1"),
                ("CARGO_INCREMENTAL", "false"),
                ("CARGO_INCREMENTAL", "00"),
            ):
                with self.subTest(key=key, value=value):
                    nested = copy.deepcopy(fixture.capsule_receipt)
                    entries = dict(nested["compile_environment"]["entries"])
                    if value is None:
                        del entries[key]
                    else:
                        entries[key] = value
                    nested["compile_environment"] = context(
                        "inventory/compile-env.txt",
                        [f"{name}={item}" for name, item in sorted(entries.items())],
                        entries,
                    )
                    with self.assertRaisesRegex(build.NativeBuildError, "sanitized"):
                        build.make_receipt(
                            fixture.artifact,
                            capsule_build_receipt=nested,
                            cargo_metadata_data=fixture.metadata_data,
                            repo_root=fixture.repo,
                        )

    def test_hostile_compile_environment_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            nested = copy.deepcopy(fixture.capsule_receipt)
            environment = nested["compile_environment"]
            entries = dict(environment["entries"])
            entries["RUSTC_WRAPPER"] = "/tmp/hostile-wrapper"
            lines = [f"{key}={value}" for key, value in sorted(entries.items())]
            nested["compile_environment"] = context(
                "inventory/compile-env.txt", lines, entries
            )
            with self.assertRaisesRegex(build.NativeBuildError, "sanitized"):
                build.make_receipt(
                    fixture.artifact,
                    capsule_build_receipt=nested,
                    cargo_metadata_data=fixture.metadata_data,
                    repo_root=fixture.repo,
                )

    def test_empty_manifest_public_key_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            nested = copy.deepcopy(fixture.capsule_receipt)
            nested["build_environment"]["DCENT_MANIFEST_PUBLIC_KEY_HEX"] = ""
            environment = nested["compile_environment"]
            entries = dict(environment["entries"])
            entries["DCENT_MANIFEST_PUBLIC_KEY_HEX"] = ""
            nested["compile_environment"] = context(
                "inventory/compile-env.txt",
                [f"{key}={value}" for key, value in sorted(entries.items())],
                entries,
            )
            with self.assertRaisesRegex(build.NativeBuildError, "canonical lowercase"):
                build.make_receipt(
                    fixture.artifact,
                    capsule_build_receipt=nested,
                    cargo_metadata_data=fixture.metadata_data,
                    repo_root=fixture.repo,
                )

    def test_build_and_compile_manifest_key_mismatch_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            nested = copy.deepcopy(fixture.capsule_receipt)
            environment = nested["compile_environment"]
            entries = dict(environment["entries"])
            entries["DCENT_MANIFEST_PUBLIC_KEY_HEX"] = "b" * 64
            nested["compile_environment"] = context(
                "inventory/compile-env.txt",
                [f"{key}={value}" for key, value in sorted(entries.items())],
                entries,
            )
            with self.assertRaisesRegex(build.NativeBuildError, "sanitized"):
                build.make_receipt(
                    fixture.artifact,
                    capsule_build_receipt=nested,
                    cargo_metadata_data=fixture.metadata_data,
                    repo_root=fixture.repo,
                )

    def test_uppercase_manifest_public_key_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            nested = copy.deepcopy(fixture.capsule_receipt)
            uppercase = "A" * 64
            nested["build_environment"]["DCENT_MANIFEST_PUBLIC_KEY_HEX"] = uppercase
            environment = nested["compile_environment"]
            entries = dict(environment["entries"])
            entries["DCENT_MANIFEST_PUBLIC_KEY_HEX"] = uppercase
            nested["compile_environment"] = context(
                "inventory/compile-env.txt",
                [f"{key}={value}" for key, value in sorted(entries.items())],
                entries,
            )
            with self.assertRaisesRegex(build.NativeBuildError, "canonical lowercase"):
                build.make_receipt(
                    fixture.artifact,
                    capsule_build_receipt=nested,
                    cargo_metadata_data=fixture.metadata_data,
                    repo_root=fixture.repo,
                )

    def test_capsule_container_mount_layout_is_admitted(self) -> None:
        import json as _json

        packages = []
        ids: dict[str, str] = {}
        for name, manifest in build.LOCAL_PACKAGE_MANIFESTS.items():
            version = "0.1.0" if name == "dcent-schema" else "0.9.0"
            if manifest.startswith("DCENT_OS_Antminer/dcentrald/"):
                container = "/src/" + manifest[len("DCENT_OS_Antminer/dcentrald/") :]
            else:
                container = "/dcent-schema/" + manifest[len("projects/dcent-schema/") :]
            package_id = f"path+file://{container}#{name}@{version}"
            ids[name] = package_id
            packages.append(
                {
                    "id": package_id,
                    "name": name,
                    "version": version,
                    "source": None,
                    "manifest_path": container,
                }
            )
        nodes = []
        for name, package_id in ids.items():
            deps = []
            if name == "dcentrald":
                deps = [
                    {
                        "name": dependency,
                        "pkg": dependency_id,
                        "dep_kinds": [{"kind": None, "target": None}],
                    }
                    for dependency, dependency_id in sorted(ids.items())
                    if dependency != "dcentrald"
                ]
            nodes.append({"id": package_id, "deps": deps})
        metadata = {
            "version": 1,
            "workspace_root": "/src",
            "packages": packages,
            "resolve": {"root": ids["dcentrald"], "nodes": nodes},
        }
        closure = build._dependency_closure(
            build.canonical_json(metadata)
        )
        local = closure["packages"]
        for entry in local:
            self.assertTrue(entry["manifest_path"].startswith("projects/"))
            self.assertFalse(entry["manifest_path"].startswith("/"))
        names = {entry["name"] for entry in local}
        self.assertIn("dcentrald", names)
        self.assertIn("dcent-schema", names)

    def test_foreign_capsule_mount_layout_is_refused(self) -> None:
        import copy as _copy

        packages = []
        ids: dict[str, str] = {}
        for name, manifest in build.LOCAL_PACKAGE_MANIFESTS.items():
            version = "0.1.0" if name == "dcent-schema" else "0.9.0"
            container = "/elsewhere/" + Path(manifest).name
            package_id = f"path+file://{container}#{name}@{version}"
            ids[name] = package_id
            packages.append(
                {
                    "id": package_id,
                    "name": name,
                    "version": version,
                    "source": None,
                    "manifest_path": container,
                }
            )
        nodes = [
            {
                "id": ids["dcentrald"],
                "deps": [
                    {
                        "name": dependency,
                        "pkg": dependency_id,
                        "dep_kinds": [{"kind": None, "target": None}],
                    }
                    for dependency, dependency_id in sorted(ids.items())
                    if dependency != "dcentrald"
                ],
            }
        ]
        for name, package_id in ids.items():
            if name != "dcentrald":
                nodes.append({"id": package_id, "deps": []})
        metadata = {
            "version": 1,
            "workspace_root": "/src",
            "packages": packages,
            "resolve": {"root": ids["dcentrald"], "nodes": nodes},
        }
        with self.assertRaisesRegex(
            build.NativeBuildError,
            "escapes the admitted",
        ):
            build._dependency_closure(
                build.canonical_json(metadata)
            )

    def test_incomplete_local_dependency_closure_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            metadata = copy.deepcopy(fixture.metadata)
            missing = "dcentrald-thermal"
            package = next(item for item in metadata["packages"] if item["name"] == missing)
            metadata["packages"].remove(package)
            metadata["resolve"]["nodes"] = [
                node for node in metadata["resolve"]["nodes"] if node["id"] != package["id"]
            ]
            root = next(
                node
                for node in metadata["resolve"]["nodes"]
                if "#dcentrald@" in node["id"]
            )
            root["deps"] = [dep for dep in root["deps"] if dep["pkg"] != package["id"]]
            data = build.canonical_json(metadata)
            nested = copy.deepcopy(fixture.capsule_receipt)
            nested["cargo_metadata"] = {
                **nested["cargo_metadata"],
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            with self.assertRaisesRegex(build.NativeBuildError, "16-package"):
                build.make_receipt(
                    fixture.artifact,
                    capsule_build_receipt=nested,
                    cargo_metadata_data=data,
                    repo_root=fixture.repo,
                )

    def test_nonimmutable_builder_and_historical_v1_are_rejected(self) -> None:
        temporary, fixture = self.fixture()
        with temporary:
            nested = copy.deepcopy(fixture.capsule_receipt)
            nested["builder"]["base_reference"] = "rust:latest"
            with self.assertRaisesRegex(build.NativeBuildError, "schema-v4 admission"):
                build.make_receipt(
                    fixture.artifact,
                    capsule_build_receipt=nested,
                    cargo_metadata_data=fixture.metadata_data,
                    repo_root=fixture.repo,
                )
            historical = {"schema": "dcentos.s19k-native-release-link-candidate/v1"}
            fixture.receipt_path.write_bytes(build.canonical_json(historical))
            with self.assertRaisesRegex(build.NativeBuildError, "key set"):
                build.verify_receipt(
                    fixture.receipt_path, fixture.artifact, repo_root=fixture.repo
                )


if __name__ == "__main__":
    unittest.main()
